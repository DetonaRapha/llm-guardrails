"""O orquestrador: o pipeline que amarra tudo.

Fluxo (ver spec, seção "O motor de política"):

    1. roda os guardrails de entrada        -> vereditos de entrada
    2. policy.decide                         -> se BLOCK/ESCALATE/REQUIRE_APPROVAL,
                                                curto-circuita ANTES do modelo
    3. chama o modelo                        (só se a entrada liberou)
    4. roda os guardrails de saída           -> vereditos de saída
    5. policy.decide (entrada + saída)       -> ação final
    6. audita tudo                           (PII redigida pela própria auditoria)
    7. devolve GuardedResult

Dois pontos que carregam a postura de segurança:

- **Curto-circuito no passo 2:** entrada maliciosa nem chega a gastar chamada de
  modelo. Barreira antes do custo e antes do risco.
- **Fail-closed em toda parte:** se um guardrail lança exceção, viramos aquilo
  num veredito de erro CRÍTICO; o motor de política transforma erro em
  BLOCK/ESCALATE, jamais em ALLOW. O modelo também é chamado dentro de try/except.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from guardrails.audit import AuditTrail
from guardrails.hitl import (
    ApprovalGate,
    ApprovalRequest,
    AutoDenyGate,
    EscalationRouter,
)
from guardrails.policy import (
    Decision,
    Policy,
    PolicyEngine,
    make_error_verdict,
)
from guardrails.types import (
    Action,
    CallModel,
    GuardContext,
    GuardedResult,
    Guardrail,
    Verdict,
)

#: Resposta segura padrão. Nunca vaza o erro cru nem o texto barrado ao usuário.
DEFAULT_SAFE_RESPONSE = (
    "Não é possível atender a esta solicitação com segurança no momento. "
    "Se precisar de ajuda, procure um profissional de saúde qualificado."
)


def _default_clock() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_guards(
    guards: list[Guardrail], ctx: GuardContext, stage: str
) -> list[Verdict]:
    """Roda cada guardrail com isolamento de falha (fail-closed por veredito).

    Se um guardrail lança, não deixamos a exceção derrubar o pipeline nem, pior,
    "passar batido". Viramos a falha num veredito de erro CRÍTICO, que o motor de
    política resolve como fallback.
    """
    verdicts: list[Verdict] = []
    for g in guards:
        try:
            verdicts.append(g.check(ctx))
        except Exception as exc:  # noqa: BLE001 - qualquer falha vira fail-closed
            verdicts.append(make_error_verdict(getattr(g, "name", "desconhecido"), exc, stage=stage))
    return verdicts


def _apply_redactions(verdicts: list[Verdict], original: str) -> str:
    """Aplica o `modified_payload` dos vereditos que redigiram, se houver."""
    text = original
    for v in verdicts:
        if v.modified_payload is not None:
            text = v.modified_payload
    return text


def _as_engine(policy: Policy | PolicyEngine) -> PolicyEngine:
    return policy if isinstance(policy, PolicyEngine) else PolicyEngine(policy)


def guard(
    user_input: str,
    contexts: list[str] | None,
    call_model: CallModel,
    *,
    input_guards: list[Guardrail],
    output_guards: list[Guardrail],
    policy: Policy | PolicyEngine,
    approval_gate: ApprovalGate | None = None,
    audit: AuditTrail | None = None,
    router: EscalationRouter | None = None,
    safe_response: str = DEFAULT_SAFE_RESPONSE,
    metadata: dict | None = None,
    clock: Callable[[], str] | None = None,
) -> GuardedResult:
    """Executa o pipeline de guardrails ponta a ponta e devolve o resultado."""
    engine = _as_engine(policy)
    gate = approval_gate or AutoDenyGate()
    trail = audit or AuditTrail()
    router = router or EscalationRouter()
    now = clock or _default_clock
    meta = dict(metadata or {})
    session_id = str(meta.get("session_id", "sem-sessao"))

    ctx = GuardContext(
        user_input=user_input,
        contexts=list(contexts or []),
        model_output=None,
        metadata=meta,
    )

    # ---- 1. Guardrails de entrada ----
    input_verdicts = _run_guards(input_guards, ctx, "input")
    # Aplica redações à entrada ANTES de chamar o modelo (o modelo nunca vê PII).
    ctx.user_input = _apply_redactions(input_verdicts, ctx.user_input)

    input_decision = engine.decide(input_verdicts)
    trail.record_stage(
        session_id=session_id,
        stage="input",
        verdicts=input_verdicts,
        action=input_decision.action.name,
        policy_reason=input_decision.reason,
        timestamp=now(),
    )

    # ---- 2. Curto-circuito antes do modelo ----
    if input_decision.action in (Action.BLOCK, Action.ESCALATE, Action.REQUIRE_APPROVAL):
        result = _short_circuit_input(
            decision=input_decision,
            verdicts=input_verdicts,
            ctx=ctx,
            gate=gate,
            router=router,
            safe_response=safe_response,
            session_id=session_id,
        )
        # REQUIRE_APPROVAL aprovado na entrada segue para o modelo; senão, encerra.
        if result is not None:
            trail.record_decision(session_id=session_id, result=result, timestamp=now())
            return result

    # ---- 3. Chama o modelo (com isolamento de falha) ----
    try:
        model_output = call_model(ctx)
    except Exception as exc:  # noqa: BLE001 - falha do modelo é fail-closed
        err = make_error_verdict("call_model", exc, stage="output")
        all_verdicts = input_verdicts + [err]
        decision = engine.decide(all_verdicts)
        result = GuardedResult(
            final_output=safe_response,
            action=decision.action,
            verdicts=all_verdicts,
            escalated=decision.action == Action.ESCALATE,
            blocked_stage="output",
            policy_reason=decision.reason,
        )
        trail.record_decision(session_id=session_id, result=result, timestamp=now())
        return result

    ctx.model_output = model_output

    # ---- 4. Guardrails de saída ----
    output_verdicts = _run_guards(output_guards, ctx, "output")
    redacted_output = _apply_redactions(output_verdicts, ctx.model_output or "")

    # ---- 5. Decisão final (entrada + saída) ----
    all_verdicts = input_verdicts + output_verdicts
    final_decision = engine.decide(all_verdicts)

    result = _resolve_final(
        decision=final_decision,
        verdicts=all_verdicts,
        redacted_output=redacted_output,
        ctx=ctx,
        gate=gate,
        router=router,
        safe_response=safe_response,
        session_id=session_id,
    )

    # ---- 6. Auditoria ----
    trail.record_decision(session_id=session_id, result=result, timestamp=now())
    return result


def _short_circuit_input(
    *,
    decision: Decision,
    verdicts: list[Verdict],
    ctx: GuardContext,
    gate: ApprovalGate,
    router: EscalationRouter,
    safe_response: str,
    session_id: str,
) -> GuardedResult | None:
    """Trata a decisão de entrada que interrompe o fluxo antes do modelo.

    Devolve um `GuardedResult` para encerrar, ou ``None`` se a interação foi
    aprovada e deve seguir para o modelo (caso REQUIRE_APPROVAL aprovado).
    """
    if decision.action == Action.BLOCK:
        return GuardedResult(
            final_output=safe_response,
            action=Action.BLOCK,
            verdicts=verdicts,
            blocked_stage="input",
            policy_reason=decision.reason,
        )

    if decision.action == Action.ESCALATE:
        route = router.route(reason=decision.reason, verdicts=verdicts)
        return GuardedResult(
            final_output=safe_response,
            action=Action.ESCALATE,
            verdicts=verdicts,
            escalated=True,
            blocked_stage="input",
            policy_reason=f"{decision.reason} | rota: {route.target} ({route.reason})",
        )

    if decision.action == Action.REQUIRE_APPROVAL:
        approval = gate.request(
            ApprovalRequest(
                session_id=session_id,
                action_description="processar solicitação de entrada",
                payload_preview=ctx.user_input,
                metadata=ctx.metadata,
            )
        )
        if approval.approved:
            return None  # segue para o modelo
        return GuardedResult(
            final_output=safe_response,
            action=Action.BLOCK,
            verdicts=verdicts,
            approved=False,
            blocked_stage="input",
            policy_reason=f"{decision.reason} | aprovação negada: {approval.reason}",
        )

    return None  # não deveria chegar aqui


def _resolve_final(
    *,
    decision: Decision,
    verdicts: list[Verdict],
    redacted_output: str,
    ctx: GuardContext,
    gate: ApprovalGate,
    router: EscalationRouter,
    safe_response: str,
    session_id: str,
) -> GuardedResult:
    """Resolve a ação final sobre a saída do modelo."""
    action = decision.action
    reason = decision.reason

    # Ação consequente (agendar/enviar/gravar) exige aprovação humana mesmo que
    # os guardrails tenham liberado. É o HITL como primitiva regulatória.
    consequential = bool(ctx.metadata.get("consequential_action"))
    if consequential and action in (Action.ALLOW, Action.REDACT):
        action = Action.REQUIRE_APPROVAL
        reason = f"{reason} | ação consequente exige aprovação humana"

    if action == Action.BLOCK:
        return GuardedResult(
            final_output=safe_response,
            action=Action.BLOCK,
            verdicts=verdicts,
            blocked_stage="output",
            policy_reason=reason,
        )

    if action == Action.ESCALATE:
        route = router.route(reason=reason, verdicts=verdicts)
        return GuardedResult(
            final_output=safe_response,
            action=Action.ESCALATE,
            verdicts=verdicts,
            escalated=True,
            blocked_stage="output",
            policy_reason=f"{reason} | rota: {route.target} ({route.reason})",
        )

    if action == Action.REQUIRE_APPROVAL:
        approval = gate.request(
            ApprovalRequest(
                session_id=session_id,
                action_description=str(ctx.metadata.get("action_description", "entregar resposta")),
                payload_preview=redacted_output,
                metadata=ctx.metadata,
            )
        )
        if approval.approved:
            return GuardedResult(
                final_output=redacted_output,
                action=Action.REQUIRE_APPROVAL,
                verdicts=verdicts,
                approved=True,
                policy_reason=f"{reason} | aprovado por {approval.approver}",
            )
        return GuardedResult(
            final_output=safe_response,
            action=Action.BLOCK,
            verdicts=verdicts,
            approved=False,
            blocked_stage="output",
            policy_reason=f"{reason} | aprovação negada: {approval.reason}",
        )

    # ALLOW ou REDACT: entrega a saída (redigida quando houve redação).
    return GuardedResult(
        final_output=redacted_output,
        action=action,
        verdicts=verdicts,
        policy_reason=reason,
    )
