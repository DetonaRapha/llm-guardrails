"""llm-guardrails — camada de guardrails em volta de uma chamada de LLM.

API pública. O caminho mais curto para usar:

    from guardrails import Guard

    g = Guard.from_policy_file("policies/health.yaml")
    resultado = g.run("meu CPF é 123.456.789-00, estou com febre", call_model=meu_modelo)
    print(resultado.final_output, resultado.action)

Ou, para controle total, use a função `guard(...)` diretamente com listas de
guardrails montadas à mão.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from guardrails.audit import (
    AuditEvent,
    AuditTrail,
    InMemoryAuditSink,
    JsonlAuditSink,
)
from guardrails.classifiers import (
    Classifier,
    ModelClassifier,
    StubClassifier,
)
from guardrails.hitl import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    AutoApproveGate,
    AutoDenyGate,
    CallbackApprovalGate,
    EscalationRouter,
    QueueApprovalGate,
)
from guardrails.orchestrator import DEFAULT_SAFE_RESPONSE, guard
from guardrails.policy import (
    Policy,
    PolicyEngine,
    PolicyError,
    build_guardrails,
    load_policy,
)
from guardrails.types import (
    Action,
    CallModel,
    GuardContext,
    GuardedResult,
    Guardrail,
    Severity,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # tipos
    "Action",
    "Severity",
    "Verdict",
    "GuardContext",
    "GuardedResult",
    "Guardrail",
    "CallModel",
    # política
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "load_policy",
    "build_guardrails",
    # classificadores
    "Classifier",
    "StubClassifier",
    "ModelClassifier",
    # auditoria
    "AuditTrail",
    "AuditEvent",
    "InMemoryAuditSink",
    "JsonlAuditSink",
    # hitl
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalDecision",
    "AutoDenyGate",
    "AutoApproveGate",
    "CallbackApprovalGate",
    "QueueApprovalGate",
    "EscalationRouter",
    # orquestração
    "guard",
    "DEFAULT_SAFE_RESPONSE",
    "Guard",
]


class Guard:
    """Fachada de alto nível: carrega a política e roda o pipeline.

    Monta os guardrails a partir de um arquivo de política e guarda os
    colaboradores (gate de aprovação, auditoria, roteador, classificador). Cada
    chamada de `run` executa o pipeline `guard(...)` completo.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        classifier: Classifier | None = None,
        approval_gate: ApprovalGate | None = None,
        audit: AuditTrail | None = None,
        router: EscalationRouter | None = None,
        safe_response: str = DEFAULT_SAFE_RESPONSE,
    ) -> None:
        self.policy = policy
        self.engine = PolicyEngine(policy)
        self.classifier = classifier or StubClassifier()
        self.input_guards, self.output_guards = build_guardrails(
            policy, classifier=self.classifier
        )
        self.approval_gate = approval_gate or AutoDenyGate()
        self.audit = audit or AuditTrail()
        self.router = router or EscalationRouter()
        self.safe_response = safe_response

    @classmethod
    def from_policy_file(
        cls,
        path: str | Path,
        **kwargs,
    ) -> "Guard":
        """Constrói um `Guard` a partir de um arquivo de política YAML."""
        return cls(load_policy(path), **kwargs)

    def run(
        self,
        user_input: str,
        *,
        call_model: CallModel,
        contexts: list[str] | None = None,
        metadata: dict | None = None,
        clock: Callable[[], str] | None = None,
    ) -> GuardedResult:
        """Roda o pipeline completo para uma interação."""
        return guard(
            user_input,
            contexts,
            call_model,
            input_guards=self.input_guards,
            output_guards=self.output_guards,
            policy=self.engine,
            approval_gate=self.approval_gate,
            audit=self.audit,
            router=self.router,
            safe_response=self.safe_response,
            metadata=metadata,
            clock=clock,
        )
