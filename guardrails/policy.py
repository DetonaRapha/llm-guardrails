"""Motor de política e carregador do arquivo declarativo.

Duas responsabilidades:

1. **Carregar** a política de um arquivo YAML versionado (`policies/health.yaml`).
   O que está ligado, os thresholds e a ação por severidade moram lá — mudar
   comportamento é mudar o arquivo, revisável em code review, não mexer no código.

2. **Decidir**. Dado o conjunto de vereditos de uma etapa, o `PolicyEngine`
   devolve a `Action` final e a regra que a justificou, seguindo:

   - A ação mais severa entre os vereditos vence
     (ALLOW < REDACT < REQUIRE_APPROVAL < ESCALATE < BLOCK).
   - O mapeamento de severidade da política pode *elevar* a ação
     (ex: qualquer veredito CRITICAL vira BLOCK).
   - **Fail-closed:** se algum detector lançou erro ou não rodou, aplica a ação
     de fallback (BLOCK/ESCALATE em domínio regulado), jamais ALLOW.

O motor também expõe uma fábrica que monta a lista de guardrails ligados a partir
da política, injetando o `Classifier` (stub por default) nos que precisam.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from guardrails.classifiers import Classifier
from guardrails.detectors import (
    DomainPolicyGuard,
    GroundednessGuard,
    InjectionGuard,
    OutputSchemaGuard,
    PIIGuard,
    SafetyGuard,
    TopicalityGuard,
)
from guardrails.types import Action, Guardrail, Severity, Verdict


class PolicyError(Exception):
    """Erro ao carregar ou interpretar a política."""


# ---------------------------------------------------------------------------
# Modelo da política
# ---------------------------------------------------------------------------


@dataclass
class GuardConfig:
    """Configuração de um guardrail individual, vinda do YAML."""

    enabled: bool = False
    action: Action = Action.BLOCK
    options: dict = field(default_factory=dict)  # thresholds, allowed_topics, etc.


@dataclass
class Policy:
    """A política inteira, carregada do arquivo."""

    version: int
    fail_closed: bool
    input: dict[str, GuardConfig] = field(default_factory=dict)
    output: dict[str, GuardConfig] = field(default_factory=dict)
    severity_actions: dict[Severity, Action] = field(default_factory=dict)
    #: ação aplicada quando um detector falha (fail-closed). Derivada, não hardcoded.
    fallback_action: Action = Action.BLOCK

    def guard_config(self, stage: str, name: str) -> GuardConfig | None:
        table = self.input if stage == "input" else self.output
        return table.get(name)


def _parse_guard(raw: object) -> GuardConfig:
    if not isinstance(raw, dict):
        raise PolicyError(f"configuração de guardrail inválida: {raw!r}")
    enabled = bool(raw.get("enabled", False))
    action_raw = raw.get("action", "block")
    try:
        action = Action.from_str(str(action_raw))
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc
    # Tudo que não é enabled/action é opção específica do guardrail.
    options = {k: v for k, v in raw.items() if k not in ("enabled", "action")}
    return GuardConfig(enabled=enabled, action=action, options=options)


def load_policy(path: str | Path) -> Policy:
    """Carrega e valida a política a partir de um arquivo YAML."""
    p = Path(path)
    if not p.exists():
        raise PolicyError(f"arquivo de política não encontrado: {p}")

    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"YAML inválido em {p}: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyError("a raiz da política deve ser um mapeamento")

    if "version" not in data:
        raise PolicyError("a política precisa de um campo 'version'")

    fail_closed = bool(data.get("fail_closed", True))

    input_cfg = {name: _parse_guard(raw) for name, raw in (data.get("input") or {}).items()}
    output_cfg = {name: _parse_guard(raw) for name, raw in (data.get("output") or {}).items()}

    sev_actions: dict[Severity, Action] = {}
    for sev_name, act_name in (data.get("severity_actions") or {}).items():
        sev_actions[Severity.from_str(str(sev_name))] = Action.from_str(str(act_name))

    # Fallback: em domínio regulado (fail_closed), o pior caso é BLOCK. Permite
    # override explícito via 'on_error'. Sem fail_closed, o fallback é ALLOW.
    if "on_error" in data:
        fallback = Action.from_str(str(data["on_error"]))
    else:
        fallback = Action.BLOCK if fail_closed else Action.ALLOW

    return Policy(
        version=int(data["version"]),
        fail_closed=fail_closed,
        input=input_cfg,
        output=output_cfg,
        severity_actions=sev_actions,
        fallback_action=fallback,
    )


# ---------------------------------------------------------------------------
# O motor de decisão
# ---------------------------------------------------------------------------


@dataclass
class Decision:
    """Ação final decidida pelo motor, com a regra que a justificou."""

    action: Action
    reason: str


# Nome usado nos vereditos sintéticos criados quando um detector lança erro.
ERROR_GUARDRAIL_SUFFIX = ":error"


def make_error_verdict(guardrail_name: str, exc: Exception, *, stage: str) -> Verdict:
    """Cria o veredito sintético de um detector que falhou (fail-closed)."""
    return Verdict(
        guardrail=f"{guardrail_name}{ERROR_GUARDRAIL_SUFFIX}",
        passed=False,
        severity=Severity.CRITICAL,
        action_hint=Action.BLOCK,
        detail=f"detector lançou erro: {type(exc).__name__}: {exc}",
        stage=stage,  # type: ignore[arg-type]
    )


def is_error_verdict(v: Verdict) -> bool:
    return v.guardrail.endswith(ERROR_GUARDRAIL_SUFFIX)


class PolicyEngine:
    """Agrega vereditos e decide a ação, com postura fail-closed."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def decide(self, verdicts: list[Verdict]) -> Decision:
        """Decide a ação final para um conjunto de vereditos."""
        action = Action.ALLOW
        reason = "nenhum guardrail disparou"

        for v in verdicts:
            if v.passed and not is_error_verdict(v):
                continue

            # Fail-closed: um detector que falhou aplica o fallback e nunca
            # permite que a decisão fique abaixo dele.
            if is_error_verdict(v):
                if self.policy.fail_closed:
                    candidate = _max_action(self.policy.fallback_action, Action.ESCALATE)
                else:
                    candidate = self.policy.fallback_action
                if candidate > action:
                    action, reason = candidate, (
                        f"fail-closed: {v.guardrail} falhou -> {candidate.name}"
                    )
                continue

            # Veredito normal que não passou: parte do hint do próprio guardrail...
            candidate = v.action_hint
            src = f"{v.guardrail} ({v.severity.name}) sugere {v.action_hint.name}"

            # ...e pode ser elevado pelo mapeamento de severidade da política.
            mapped = self.policy.severity_actions.get(v.severity)
            if mapped is not None and mapped > candidate:
                candidate = mapped
                src = (
                    f"{v.guardrail}: severidade {v.severity.name} "
                    f"mapeada para {mapped.name}"
                )

            if candidate > action:
                action, reason = candidate, src

        return Decision(action=action, reason=reason)


def _max_action(a: Action, b: Action) -> Action:
    return a if a >= b else b


# ---------------------------------------------------------------------------
# Fábrica: monta os guardrails ligados a partir da política
# ---------------------------------------------------------------------------


def build_guardrails(
    policy: Policy,
    *,
    classifier: Classifier | None = None,
) -> tuple[list[Guardrail], list[Guardrail]]:
    """Constrói (input_guards, output_guards) a partir da política.

    Só inclui guardrails com ``enabled: true``. Injeta o `classifier` (stub por
    default, resolvido dentro de cada detector) nos que dependem de modelo.
    """
    input_guards: list[Guardrail] = []
    output_guards: list[Guardrail] = []

    # ---- Entrada ----
    if (cfg := policy.guard_config("input", "pii_redaction")) and cfg.enabled:
        input_guards.append(PIIGuard(stage="input", action=cfg.action))

    if (cfg := policy.guard_config("input", "prompt_injection")) and cfg.enabled:
        min_sev = Severity.from_str(str(cfg.options.get("min_severity", "medium")))
        input_guards.append(
            InjectionGuard(action=cfg.action, min_severity=min_sev, classifier=classifier)
        )

    if (cfg := policy.guard_config("input", "topicality")) and cfg.enabled:
        input_guards.append(
            TopicalityGuard(
                allowed_topics=list(cfg.options.get("allowed_topics", [])),
                action=cfg.action,
            )
        )

    # ---- Saída ----
    if (cfg := policy.guard_config("output", "schema")) and cfg.enabled:
        output_guards.append(
            OutputSchemaGuard(
                required_keys=cfg.options.get("required_keys"),
                action=cfg.action,
            )
        )

    if (cfg := policy.guard_config("output", "pii_leak")) and cfg.enabled:
        output_guards.append(PIIGuard(stage="output", action=cfg.action))

    if (cfg := policy.guard_config("output", "groundedness")) and cfg.enabled:
        output_guards.append(
            GroundednessGuard(
                threshold=float(cfg.options.get("threshold", 0.7)),
                action=cfg.action,
                classifier=classifier,
            )
        )

    if (cfg := policy.guard_config("output", "safety")) and cfg.enabled:
        output_guards.append(
            SafetyGuard(
                threshold=float(cfg.options.get("threshold", 0.5)),
                action=cfg.action,
                classifier=classifier,
            )
        )

    if (cfg := policy.guard_config("output", "domain_policy")) and cfg.enabled:
        output_guards.append(DomainPolicyGuard(action=cfg.action))

    return input_guards, output_guards
