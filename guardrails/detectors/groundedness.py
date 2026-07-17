"""Groundedness e alucinação (baseado em modelo, com proxy determinístico).

A resposta do modelo é sustentada pelo contexto fornecido? Se o modelo inventou
fato fora do contexto (RAG), este guardrail sinaliza. Usa um `Classifier`:

- Default: `StubClassifier`, que mede sobreposição léxica entre a saída e os
  contextos. Determinístico, roda no CI, sem rede.
- Real: `ModelClassifier` com um LLM/endpoint que faz verificação de suporte
  factual de verdade — plugável na mesma interface.

Score abaixo do `threshold` dispara a ação configurada (tipicamente ESCALATE:
resposta pouco sustentada vira revisão humana, não bloqueio cego). Erro do
classificador é fail-closed: sobe a severidade em vez de assumir que está tudo bem.
"""

from __future__ import annotations

from guardrails.classifiers import Classifier, StubClassifier
from guardrails.types import Action, GuardContext, Severity, Verdict


class GroundednessGuard:
    """Guardrail de groundedness (saída)."""

    name = "groundedness"
    stage = "output"

    def __init__(
        self,
        *,
        threshold: float = 0.7,
        action: Action = Action.ESCALATE,
        classifier: Classifier | None = None,
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        self._threshold = threshold
        self._action = action
        self._classifier = classifier or StubClassifier()
        self._severity = severity

    def check(self, ctx: GuardContext) -> Verdict:
        output = ctx.model_output or ""
        if not output.strip():
            # Saída vazia não afirma nada; deixamos outros guardrails tratarem.
            return Verdict.ok(self.name, "saída vazia, nada a sustentar", stage=self.stage)

        scores = self._classifier.classify(output, ctx.contexts)

        if scores.get("error"):
            return Verdict(
                guardrail=self.name,
                passed=False,
                severity=max(self._severity, Severity.HIGH),
                action_hint=self._action,
                detail="classificador de groundedness indisponível (fail-closed)",
                stage=self.stage,
            )

        score = float(scores.get("groundedness", 0.0))
        if score < self._threshold:
            return Verdict(
                guardrail=self.name,
                passed=False,
                severity=self._severity,
                action_hint=self._action,
                detail=f"groundedness {score:.2f} abaixo do limiar {self._threshold:.2f}",
                stage=self.stage,
            )

        return Verdict.ok(
            self.name,
            f"groundedness {score:.2f} >= limiar {self._threshold:.2f}",
            stage=self.stage,
        )
