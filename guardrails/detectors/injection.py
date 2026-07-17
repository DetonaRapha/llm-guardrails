"""Injeção de prompt e jailbreak (determinístico + modelo, opcional).

Duas camadas empilhadas:

1. **Determinística (sempre ligada):** padrões conhecidos de ataque — "ignore as
   instruções anteriores", tentativa de vazar o system prompt, troca de papel
   para burlar a política. Roda sem rede, no CI.
2. **Baseada em modelo (opcional):** um `Classifier` pega os casos sutis que
   fogem dos padrões literais. Default é o `StubClassifier` determinístico, então
   o repo roda sem API key. Se o classificador acusar erro, a severidade sobe
   (fail-closed) em vez de ser ignorada.

O guardrail agrega os dois sinais e devolve o de maior severidade.
"""

from __future__ import annotations

import re

from guardrails.classifiers import Classifier, StubClassifier
from guardrails.types import Action, GuardContext, Severity, Verdict

# Padrões literais de alta confiança. Cada um vem com a severidade que atribui.
_PATTERNS: list[tuple[re.Pattern[str], Severity, str]] = [
    (
        re.compile(
            r"ignor[ae]r?\b.{0,40}?(?:instru[çc][õo]es|instructions|previous|prior|"
            r"anterior|regras|rules|acima|above)",
            re.I,
        ),
        Severity.HIGH,
        "tentativa de ignorar instruções anteriores",
    ),
    (
        re.compile(
            r"disregard\b.{0,40}?(?:previous|prior|above|instructions)", re.I
        ),
        Severity.HIGH,
        "tentativa de descartar instruções anteriores",
    ),
    (
        re.compile(r"esque[çc]a (?:tudo|as instru)", re.I),
        Severity.HIGH,
        "tentativa de descartar instruções anteriores",
    ),
    (
        re.compile(r"(?:reveal|show|print|mostre|revele|exiba).{0,30}(?:system prompt|prompt do sistema|instru[çc][õo]es do sistema)", re.I),
        Severity.CRITICAL,
        "tentativa de vazar o system prompt",
    ),
    (
        re.compile(r"(?:you are now|voc[êe] agora [ée]|a partir de agora voc[êe])", re.I),
        Severity.MEDIUM,
        "tentativa de redefinir o papel do modelo",
    ),
    (
        re.compile(r"\bDAN\b|do anything now|modo dan", re.I),
        Severity.HIGH,
        "invocação de persona de jailbreak (DAN)",
    ),
    (
        re.compile(r"(?:developer mode|modo desenvolvedor|jailbreak)", re.I),
        Severity.HIGH,
        "invocação de modo de burla",
    ),
    (
        re.compile(r"(?:sem (?:restri[çc][õo]es|filtro|regras)|no restrictions|unfiltered)", re.I),
        Severity.MEDIUM,
        "pedido para operar sem restrições",
    ),
    (
        re.compile(r"(?:pretend|finja|imagine) (?:you are|that you|que voc[êe]|ser)", re.I),
        Severity.MEDIUM,
        "role-play para burlar política",
    ),
]


class InjectionGuard:
    """Guardrail de injeção de prompt / jailbreak (entrada)."""

    name = "prompt_injection"
    stage = "input"

    def __init__(
        self,
        *,
        action: Action = Action.BLOCK,
        min_severity: Severity = Severity.MEDIUM,
        classifier: Classifier | None = None,
        jailbreak_threshold: float = 0.5,
    ) -> None:
        self._action = action
        self._min_severity = min_severity
        # Default é o stub determinístico: sem rede, roda no CI.
        self._classifier = classifier or StubClassifier()
        self._threshold = jailbreak_threshold

    def check(self, ctx: GuardContext) -> Verdict:
        text = ctx.user_input
        hits: list[str] = []
        severity = Severity.INFO

        # Camada 1 — padrões determinísticos.
        for pattern, sev, label in _PATTERNS:
            if pattern.search(text):
                hits.append(label)
                severity = max(severity, sev)

        # Camada 2 — classificador (stub por default).
        scores = self._classifier.classify(text, ctx.contexts)
        if scores.get("error"):
            # Fail-closed: não conseguimos avaliar => tratamos como suspeito.
            hits.append("classificador indisponível (fail-closed)")
            severity = max(severity, Severity.HIGH)
        elif scores.get("jailbreak", 0.0) >= self._threshold:
            hits.append(f"classificador sinalizou jailbreak (score={scores['jailbreak']:.2f})")
            severity = max(severity, Severity.HIGH)

        if not hits or severity < self._min_severity:
            detalhe = "nenhum padrão de injeção acima do limiar" if not hits else \
                f"achados abaixo do limiar ({severity.name} < {self._min_severity.name})"
            return Verdict.ok(self.name, detalhe, stage=self.stage)

        return Verdict(
            guardrail=self.name,
            passed=False,
            severity=severity,
            action_hint=self._action,
            detail="injeção de prompt detectada: " + "; ".join(hits),
            stage=self.stage,
        )
