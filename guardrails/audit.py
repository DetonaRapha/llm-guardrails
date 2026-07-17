"""Trilha de auditoria com redação de PII.

Todo veredito e toda decisão viram evento estruturado, com timestamp. Requisito,
não enfeite: rastreabilidade é o que transforma "confie em mim" em evidência.

Regra inegociável (ver "O que NÃO fazer" na spec): **nunca logar PII em claro**.
Todo texto livre que entra num evento passa por `redact_pii` antes de ser
persistido — mesmo que o guardrail de PII não tenha rodado. A auditoria é a
última linha; ela não confia que alguém já limpou.

O sink é plugável:

- `InMemoryAuditSink`: guarda os eventos numa lista (default, ótimo pra teste).
- `JsonlAuditSink`: anexa uma linha JSON por evento a um arquivo (`.jsonl`).

Ambos implementam o protocolo `AuditSink`.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Protocol, runtime_checkable

from guardrails.detectors.pii import redact_pii
from guardrails.types import GuardedResult, Verdict


def _redact(text: str | None) -> str | None:
    """Mascara PII de qualquer texto livre antes de auditar."""
    if text is None:
        return None
    return redact_pii(text).text


@dataclass
class AuditEvent:
    """Um evento estruturado da trilha de auditoria.

    `timestamp` é injetado de fora (o orquestrador passa o horário). Mantemos o
    módulo livre de `datetime.now()` para ser determinístico e testável — quem
    chama decide a fonte de tempo.
    """

    session_id: str
    stage: str                      # "input" | "output" | "decision"
    action: str                     # ação final ou parcial
    policy_reason: str
    verdicts: list[dict] = field(default_factory=list)
    escalated: bool = False
    approved: bool | None = None
    timestamp: str = ""
    detail: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


@runtime_checkable
class AuditSink(Protocol):
    """Destino de eventos de auditoria."""

    def emit(self, event: AuditEvent) -> None: ...


def _verdict_to_audit_dict(v: Verdict) -> dict:
    """Serializa um veredito para auditoria, redigindo campos de texto livre.

    `detail` e `modified_payload` podem conter PII (ex: o detalhe cita o que foi
    mascarado, ou o payload reescrito). Redigimos ambos por precaução.
    """
    return {
        "guardrail": v.guardrail,
        "passed": v.passed,
        "severity": v.severity.name,
        "action_hint": v.action_hint.name,
        "detail": _redact(v.detail),
        "modified_payload": _redact(v.modified_payload),
        "stage": v.stage,
    }


class AuditTrail:
    """Fachada de auditoria: recebe vereditos/resultados e emite eventos limpos."""

    def __init__(self, sink: "AuditSink | None" = None) -> None:
        self._sink: AuditSink = sink or InMemoryAuditSink()

    @property
    def sink(self) -> "AuditSink":
        return self._sink

    def record_stage(
        self,
        *,
        session_id: str,
        stage: str,
        verdicts: list[Verdict],
        action: str,
        policy_reason: str,
        timestamp: str,
        detail: str = "",
    ) -> None:
        event = AuditEvent(
            session_id=session_id,
            stage=stage,
            action=action,
            policy_reason=policy_reason,
            verdicts=[_verdict_to_audit_dict(v) for v in verdicts],
            timestamp=timestamp,
            detail=_redact(detail) or "",
        )
        self._sink.emit(event)

    def record_decision(
        self,
        *,
        session_id: str,
        result: GuardedResult,
        timestamp: str,
    ) -> None:
        event = AuditEvent(
            session_id=session_id,
            stage="decision",
            action=result.action.name,
            policy_reason=result.policy_reason,
            verdicts=[_verdict_to_audit_dict(v) for v in result.verdicts],
            escalated=result.escalated,
            approved=result.approved,
            timestamp=timestamp,
            # final_output pode ser a resposta segura ou texto do modelo — redige.
            detail=_redact(f"final_output={result.final_output}") or "",
        )
        self._sink.emit(event)


class InMemoryAuditSink:
    """Sink em memória. Default, ideal para testes e inspeção."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)

    def as_dicts(self) -> list[dict]:
        return [asdict(e) for e in self.events]


class JsonlAuditSink:
    """Sink que anexa uma linha JSON por evento a um arquivo `.jsonl`."""

    def __init__(self, path: str, encoding: str = "utf-8") -> None:
        self._path = path
        self._encoding = encoding

    def emit(self, event: AuditEvent) -> None:
        with open(self._path, "a", encoding=self._encoding) as fh:
            fh.write(event.to_json() + "\n")
