"""Pacote de detectores (guardrails concretos).

Cada detector implementa o protocolo `Guardrail` de `guardrails.types`: tem
`name`, `stage` e um método `check(ctx) -> Verdict`. São peças independentes e
combináveis — o motor de política (ver `guardrails.policy`) monta a lista de
detectores ligados a partir do arquivo declarativo.

Reexportamos o protocolo aqui por conveniência, para que quem escreve um novo
detector importe tudo de um lugar só.
"""

from __future__ import annotations

from guardrails.types import GuardContext, Guardrail, Severity, Verdict, Action, Stage

from .pii import PIIGuard, redact_pii, RedactionResult
from .injection import InjectionGuard
from .topicality import TopicalityGuard
from .output_schema import OutputSchemaGuard
from .groundedness import GroundednessGuard
from .safety import SafetyGuard, DomainPolicyGuard

__all__ = [
    "GuardContext",
    "Guardrail",
    "Severity",
    "Verdict",
    "Action",
    "Stage",
    "PIIGuard",
    "redact_pii",
    "RedactionResult",
    "InjectionGuard",
    "TopicalityGuard",
    "OutputSchemaGuard",
    "GroundednessGuard",
    "SafetyGuard",
    "DomainPolicyGuard",
]
