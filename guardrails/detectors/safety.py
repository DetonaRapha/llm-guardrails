"""Toxicidade / conteúdo inseguro (modelo) e conformidade de política de domínio.

Dois guardrails de saída moram aqui, ambos sobre "o que é seguro entregar":

- `SafetyGuard`: passa a saída por um `Classifier` de segurança (na prática, algo
  como Llama Guard ou um endpoint de moderação). Default é o `StubClassifier`
  determinístico, para o CI rodar sem rede. Toxicidade acima do limiar => barra.
  Erro do classificador é fail-closed.

- `DomainPolicyGuard`: regras específicas do domínio, determinísticas. No sabor
  de saúde: o sistema não pode dar diagnóstico definitivo nem prescrição/dosagem.
  Viola a regra => barra. É a "Conformidade de política de domínio" da Camada 2.
  (Fica junto do SafetyGuard por ser, também, uma checagem de segurança de saída.)
"""

from __future__ import annotations

import re

from guardrails.classifiers import Classifier, StubClassifier
from guardrails.types import Action, GuardContext, Severity, Verdict


class SafetyGuard:
    """Guardrail de toxicidade / conteúdo inseguro (saída)."""

    name = "safety"
    stage = "output"

    def __init__(
        self,
        *,
        threshold: float = 0.5,
        action: Action = Action.BLOCK,
        classifier: Classifier | None = None,
        severity: Severity = Severity.HIGH,
    ) -> None:
        self._threshold = threshold
        self._action = action
        self._classifier = classifier or StubClassifier()
        self._severity = severity

    def check(self, ctx: GuardContext) -> Verdict:
        output = ctx.model_output or ""
        scores = self._classifier.classify(output, ctx.contexts)

        if scores.get("error"):
            return Verdict(
                guardrail=self.name,
                passed=False,
                severity=max(self._severity, Severity.HIGH),
                action_hint=self._action,
                detail="classificador de segurança indisponível (fail-closed)",
                stage=self.stage,
            )

        score = float(scores.get("toxicity", 0.0))
        if score >= self._threshold:
            sev = Severity.CRITICAL if score >= 0.9 else self._severity
            return Verdict(
                guardrail=self.name,
                passed=False,
                severity=sev,
                action_hint=self._action,
                detail=f"toxicidade {score:.2f} >= limiar {self._threshold:.2f}",
                stage=self.stage,
            )

        return Verdict.ok(self.name, f"toxicidade {score:.2f} dentro do limite", stage=self.stage)


# Regras de domínio (saúde): frases que caracterizam diagnóstico definitivo ou
# prescrição. Determinísticas e transparentes. Uma política real teria mais.
_DIAGNOSIS_RE = re.compile(
    r"(?:voc[êe] (?:tem|está com|esta com)|o diagn[óo]stico [ée]|com certeza [ée]|"
    r"definitivamente [ée]|isso [ée] (?:c[âa]ncer|covid|dengue))",
    re.IGNORECASE,
)
_PRESCRIPTION_RE = re.compile(
    r"(?:tome|tomar|use|usar|aplique)\s+\d+\s*(?:mg|ml|g|comprimidos?|gotas?|c[áa]psulas?)"
    r"|receit[oa]\s+(?:o|a|para voc[êe])"
    r"|prescrev[oa]",
    re.IGNORECASE,
)


class DomainPolicyGuard:
    """Guardrail de conformidade de política de domínio (saúde) — saída."""

    name = "domain_policy"
    stage = "output"

    def __init__(
        self,
        *,
        action: Action = Action.BLOCK,
        severity: Severity = Severity.HIGH,
    ) -> None:
        self._action = action
        self._severity = severity

    def check(self, ctx: GuardContext) -> Verdict:
        output = ctx.model_output or ""
        violacoes: list[str] = []

        if _DIAGNOSIS_RE.search(output):
            violacoes.append("diagnóstico definitivo")
        if _PRESCRIPTION_RE.search(output):
            violacoes.append("prescrição/dosagem")

        if not violacoes:
            return Verdict.ok(self.name, "sem violação de política de domínio", stage=self.stage)

        return Verdict(
            guardrail=self.name,
            passed=False,
            severity=self._severity,
            action_hint=self._action,
            detail="política de domínio violada: " + ", ".join(violacoes),
            stage=self.stage,
        )
