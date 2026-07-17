"""Human-in-the-loop: portão de aprovação e roteamento de escalonamento.

Duas primitivas da Camada 3 (controle de fluxo):

- **Portão de aprovação (HITL).** Ação consequente — agendar, enviar, gravar —
  fica retida até um humano aprovar. É o HITL como primitiva regulatória: o
  sistema não age por conta própria em algo que importa.
- **Roteamento de escalonamento.** Quando a política decide ESCALATE, a
  interação vai para um caminho alternativo: humano, modelo mais forte, ou a
  resposta segura padrão. O roteador diz para onde.

Tudo plugável por protocolo. Os defaults são determinísticos e servem para CI:

- `AutoDenyGate`: nega toda aprovação (fail-closed — na ausência de humano, não
  age). É o default seguro.
- `AutoApproveGate`: aprova tudo (só para testes de caminho feliz).
- `CallbackApprovalGate`: delega a uma função (uma CLI, uma fila, um webhook).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable


@dataclass
class ApprovalRequest:
    """Pedido de aprovação de uma ação consequente."""

    session_id: str
    action_description: str          # "enviar e-mail para o paciente", etc.
    payload_preview: str             # prévia (já redigida) do que será feito
    metadata: dict = field(default_factory=dict)


@dataclass
class ApprovalDecision:
    """Resposta do humano (ou do gate) ao pedido de aprovação."""

    approved: bool
    approver: str = ""               # quem decidiu (ou "auto")
    reason: str = ""


@runtime_checkable
class ApprovalGate(Protocol):
    """Portão de aprovação humana."""

    def request(self, request: ApprovalRequest) -> ApprovalDecision: ...


class AutoDenyGate:
    """Nega toda aprovação. Default fail-closed: sem humano, não age."""

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            approved=False,
            approver="auto",
            reason="nenhum aprovador humano disponível (fail-closed)",
        )


class AutoApproveGate:
    """Aprova tudo. Só para testes de caminho feliz — nunca em produção."""

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(approved=True, approver="auto", reason="auto-aprovado (teste)")


class CallbackApprovalGate:
    """Delega a decisão a uma função injetada (CLI, fila, webhook)."""

    def __init__(self, callback: Callable[[ApprovalRequest], ApprovalDecision]) -> None:
        self._callback = callback

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        try:
            return self._callback(request)
        except Exception as exc:  # noqa: BLE001 - falha do gate é fail-closed
            return ApprovalDecision(
                approved=False,
                approver="auto",
                reason=f"gate de aprovação falhou (fail-closed): {exc}",
            )


class QueueApprovalGate:
    """Gate em memória por fila: enfileira pedidos e resolve por decisões pré-carregadas.

    Útil para simular uma fila real em teste: você empilha decisões e cada
    `request` consome a próxima. Sem decisão disponível, nega (fail-closed).
    """

    def __init__(self, decisions: list[ApprovalDecision] | None = None) -> None:
        self.pending: list[ApprovalRequest] = []
        self._decisions: list[ApprovalDecision] = list(decisions or [])

    def enqueue_decision(self, decision: ApprovalDecision) -> None:
        self._decisions.append(decision)

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        self.pending.append(request)
        if self._decisions:
            return self._decisions.pop(0)
        return ApprovalDecision(
            approved=False, approver="auto", reason="fila vazia (fail-closed)"
        )


# ---------------------------------------------------------------------------
# Roteamento de escalonamento
# ---------------------------------------------------------------------------

# Destinos possíveis de um escalonamento.
ROUTE_HUMAN = "human_review"
ROUTE_STRONGER_MODEL = "stronger_model"
ROUTE_SAFE_RESPONSE = "safe_response"


@dataclass
class EscalationRoute:
    """Para onde uma interação escalada deve ir, e por quê."""

    target: str          # um dos ROUTE_*
    reason: str


class EscalationRouter:
    """Decide o destino de uma interação escalada.

    Regra simples e determinística: vereditos CRÍTICOS/HIGH de segurança vão para
    revisão humana; baixa confiança de groundedness pode ir para um modelo mais
    forte; o resto cai na resposta segura. É plugável — um roteador real olharia
    métricas e disponibilidade.
    """

    def __init__(self, default_target: str = ROUTE_SAFE_RESPONSE) -> None:
        self._default = default_target

    def route(self, *, reason: str, verdicts: list) -> EscalationRoute:
        low = reason.lower()
        if "groundedness" in low:
            return EscalationRoute(
                target=ROUTE_STRONGER_MODEL,
                reason="baixa sustentação factual: reavaliar com modelo mais forte",
            )
        if any(k in low for k in ("safety", "injection", "fail-closed", "domain")):
            return EscalationRoute(
                target=ROUTE_HUMAN,
                reason="risco de segurança/conformidade: revisão humana",
            )
        return EscalationRoute(target=self._default, reason="escalonamento padrão")
