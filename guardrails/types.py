"""Contratos centrais dos guardrails.

Aqui moram os tipos que todas as camadas compartilham: a escala de severidade,
o conjunto de ações possíveis, o veredito que cada guardrail devolve, o contexto
que atravessa o pipeline e o resultado final entregue ao chamador.

Estes tipos são deliberadamente simples e sem dependência de rede. São o
vocabulário comum que deixa cada guardrail ser um `check` independente e
combinável (composability), e que deixa o motor de política agregar vereditos
sem conhecer o detalhe de cada detector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Literal, Protocol, runtime_checkable


class Severity(IntEnum):
    """Severidade de um veredito, do mais brando ao mais grave.

    É `IntEnum` de propósito: comparar severidade (``>=``) e ordenar é o que o
    motor de política faz o tempo todo. A ordem numérica É a semântica.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Converte um nome vindo da política (ex: ``"medium"``) em `Severity`."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - erro de configuração
            raise ValueError(f"Severidade desconhecida: {value!r}") from exc


class Action(IntEnum):
    """Ação que o pipeline pode tomar sobre uma interação.

    A ordem numérica codifica a "força" da ação, do menos restritivo ao mais
    restritivo. O motor de política usa essa ordem para escolher a ação mais
    severa entre vários vereditos (ver `policy.py`):

        ALLOW < REDACT < REQUIRE_APPROVAL < ESCALATE < BLOCK
    """

    ALLOW = 0             # deixa passar
    REDACT = 1            # modifica (ex: mascara PII) e passa
    REQUIRE_APPROVAL = 2  # segura até aprovação humana (HITL)
    ESCALATE = 3          # manda pra caminho alternativo (humano, outro modelo)
    BLOCK = 4             # barra, entrega resposta segura padrão

    @classmethod
    def from_str(cls, value: str) -> "Action":
        """Converte um nome vindo da política (ex: ``"block"``) em `Action`."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - erro de configuração
            raise ValueError(f"Ação desconhecida: {value!r}") from exc


Stage = Literal["input", "output"]


@dataclass
class Verdict:
    """O que um guardrail devolve depois de checar uma interação.

    Attributes:
        guardrail: nome do guardrail que emitiu o veredito.
        passed: ``True`` se nada foi detectado (passou limpo).
        severity: gravidade do que foi detectado (INFO se nada).
        action_hint: ação sugerida por este guardrail. É só uma *sugestão*: a
            palavra final é do motor de política, que agrega todos os vereditos.
        detail: descrição legível do que aconteceu, para auditoria.
        modified_payload: preenchido quando o guardrail redige ou reescreve o
            texto (ex: PII mascarada). ``None`` quando não houve modificação.
        stage: em qual etapa rodou ("input" ou "output"); útil na auditoria.
    """

    guardrail: str
    passed: bool
    severity: Severity
    action_hint: Action
    detail: str
    modified_payload: str | None = None
    stage: Stage | None = None

    @classmethod
    def ok(cls, guardrail: str, detail: str = "sem achados", *, stage: Stage | None = None) -> "Verdict":
        """Atalho para um veredito limpo (passou, INFO, ALLOW)."""
        return cls(
            guardrail=guardrail,
            passed=True,
            severity=Severity.INFO,
            action_hint=Action.ALLOW,
            detail=detail,
            stage=stage,
        )


@dataclass
class GuardContext:
    """O contexto que atravessa o pipeline inteiro.

    É mutável de propósito: quando um guardrail de entrada redige PII, o
    orquestrador atualiza `user_input` aqui para que a versão limpa siga para o
    modelo. O mesmo vale para `model_output` na saída.

    Attributes:
        user_input: o texto que o usuário mandou (pode ser redigido no caminho).
        contexts: trechos de contexto recuperado (RAG), usados por groundedness.
        model_output: ``None`` na entrada; preenchido após a chamada do modelo.
        metadata: domínio, id de sessão, flags e afins.
    """

    user_input: str
    contexts: list[str] = field(default_factory=list)
    model_output: str | None = None
    metadata: dict = field(default_factory=dict)


@runtime_checkable
class Guardrail(Protocol):
    """Interface comum de todo guardrail.

    Um guardrail é qualquer objeto com `name`, `stage` e um método `check`. É a
    peça que torna o sistema composável: liga, desliga e combina sem tocar no
    resto. `runtime_checkable` permite validar com ``isinstance`` nos testes.
    """

    name: str
    stage: Stage

    def check(self, ctx: GuardContext) -> Verdict: ...


# Assinatura da função que efetivamente chama o modelo. O orquestrador não
# conhece o provedor; recebe uma função. Isso deixa o repo rodar sem API key,
# com um `call_model` falso/determinístico.
CallModel = Callable[[GuardContext], str]


@dataclass
class GuardedResult:
    """O resultado final do pipeline, pronto para entregar ao chamador.

    Attributes:
        final_output: o que volta pro usuário (pode ser a resposta segura padrão).
        action: a ação final decidida pelo motor de política.
        verdicts: tudo que rodou, na ordem, para auditoria e depuração.
        escalated: ``True`` se a interação foi encaminhada a um caminho alternativo.
        approved: ``None`` se não exigiu aprovação; senão o resultado do HITL.
        blocked_stage: em que etapa a interação foi barrada, se foi ("input"/"output").
        policy_reason: qual regra da política decidiu a ação final (auditabilidade).
    """

    final_output: str
    action: Action
    verdicts: list[Verdict] = field(default_factory=list)
    escalated: bool = False
    approved: bool | None = None
    blocked_stage: Stage | None = None
    policy_reason: str = ""
