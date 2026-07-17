"""Política de tópico (fora de escopo).

Em domínio regulado, entrada fora do escopo permitido é sinalizada e escalada ou
barrada. Ex: num sistema de saúde, pedir conselho jurídico ou financeiro está
fora de escopo.

Implementação determinística: um léxico por tópico conhecido. Se o texto casa
com um tópico que **não** está na lista de permitidos, o guardrail dispara. Se o
texto não casa com nenhum tópico reconhecível, ele passa (INFO) — preferimos não
gerar falso positivo aqui; casos ambíguos são pegos por outros guardrails.
"""

from __future__ import annotations

import re

from guardrails.types import Action, GuardContext, Severity, Verdict

# Léxico mínimo por tópico. Pequeno e transparente de propósito — o objetivo é
# demonstrar a mecânica, não cobrir todo o vocabulário de cada domínio.
_TOPIC_LEXICON: dict[str, tuple[str, ...]] = {
    "saude": (
        "sintoma", "sintomas", "dor", "febre", "remédio", "remedio", "medicamento",
        "diagnóstico", "diagnostico", "consulta", "médico", "medico", "doença",
        "doenca", "tratamento", "exame", "pressão", "pressao", "vacina", "saúde",
        "saude", "dose", "posologia",
    ),
    "juridico": (
        "processo", "advogado", "contrato", "cláusula", "clausula", "juiz",
        "ação judicial", "acao judicial", "indenização", "indenizacao", "recurso",
        "petição", "peticao", "jurídico", "juridico", "lei", "direito trabalhista",
    ),
    "financeiro": (
        "investimento", "investir", "ações", "acoes", "bolsa", "cripto",
        "criptomoeda", "empréstimo", "emprestimo", "financiamento", "juros",
        "declaração de imposto", "declaracao de imposto", "renda fixa", "tesouro direto",
    ),
}


def _compile(terms: tuple[str, ...]) -> re.Pattern[str]:
    # \b não funciona bem com acentos em algumas engines; usamos limites simples.
    alt = "|".join(re.escape(t) for t in terms)
    return re.compile(rf"(?<!\w)(?:{alt})(?!\w)", re.IGNORECASE)


_TOPIC_RE = {topic: _compile(terms) for topic, terms in _TOPIC_LEXICON.items()}


class TopicalityGuard:
    """Guardrail de escopo de tópico (entrada)."""

    name = "topicality"
    stage = "input"

    def __init__(
        self,
        *,
        allowed_topics: list[str] | None = None,
        action: Action = Action.ESCALATE,
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        self._allowed = {t.strip().lower() for t in (allowed_topics or [])}
        self._action = action
        self._severity = severity

    def check(self, ctx: GuardContext) -> Verdict:
        text = ctx.user_input
        matched = {topic for topic, rx in _TOPIC_RE.items() if rx.search(text)}

        # Tópicos reconhecidos que não estão na lista de permitidos.
        forbidden = sorted(matched - self._allowed)

        if not forbidden:
            if matched:
                return Verdict.ok(self.name, f"tópico permitido: {sorted(matched)}", stage=self.stage)
            return Verdict.ok(self.name, "nenhum tópico proibido identificado", stage=self.stage)

        return Verdict(
            guardrail=self.name,
            passed=False,
            severity=self._severity,
            action_hint=self._action,
            detail=f"tópico fora de escopo: {forbidden} (permitidos: {sorted(self._allowed)})",
            stage=self.stage,
        )
