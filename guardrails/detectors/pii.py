"""Detecção e redação de PII (determinístico).

Encontra dados pessoais — e-mail, CPF, CNPJ, telefone, RG, data de nascimento e
nome — e os mascara. Roda em duas frentes:

- **Entrada:** mascara PII *antes* de mandar pro modelo e antes de logar. O
  modelo nunca deveria ver o CPF do usuário.
- **Saída:** o modelo pode ter reproduzido PII vinda do contexto; mascaramos de
  novo antes de entregar (o guardrail `pii_leak` da política).

É 100% determinístico, com regex. Para produção séria, o caminho natural é
plugar uma biblioteca de NER (ex: Microsoft Presidio) atrás da mesma interface;
a assinatura de `redact_pii` não mudaria.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guardrails.types import Action, GuardContext, Severity, Stage, Verdict


@dataclass
class RedactionResult:
    """Resultado de uma passada de redação."""

    text: str                          # texto já mascarado
    categories: dict[str, int] = field(default_factory=dict)  # categoria -> qtde

    @property
    def found(self) -> bool:
        return bool(self.categories)

    @property
    def total(self) -> int:
        return sum(self.categories.values())


# Cada regra é (categoria, regex, placeholder). A ORDEM importa: padrões mais
# específicos e longos vêm antes dos mais genéricos, para não fatiar um dado
# grande (CNPJ) em pedaços (CPF/telefone). O placeholder nunca casa de novo.
_RULES: list[tuple[str, re.Pattern[str], str]] = [
    # E-mail primeiro: contém caracteres que outros padrões ignoram.
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[PII:EMAIL]",
    ),
    # CNPJ (14 dígitos) antes de CPF (11), senão o CPF casaria um pedaço.
    (
        "CNPJ",
        re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
        "[PII:CNPJ]",
    ),
    (
        "CPF",
        re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
        "[PII:CPF]",
    ),
    # RG rotulado, para não confundir com outros números soltos.
    (
        "RG",
        re.compile(r"\bRG[:\s]*\d{1,2}\.?\d{3}\.?\d{3}-?[\dxX]\b", re.IGNORECASE),
        "[PII:RG]",
    ),
    # Data (dd/mm/aaaa) — cobre data de nascimento.
    (
        "DATA",
        re.compile(r"\b\d{2}/\d{2}/\d{4}\b"),
        "[PII:DATA]",
    ),
    # Telefone BR: com ou sem +55, DDD entre parênteses, 8 ou 9 dígitos.
    # Sem \b inicial de propósito: "(" e "+" são não-palavra, e um \b à esquerda
    # faria a captura começar depois deles, deixando o prefixo pra trás.
    (
        "TELEFONE",
        re.compile(
            r"(?:\+?55[\s.-]?)?(?:\(?\d{2}\)?[\s.-]?)?9?\d{4}[\s.-]?\d{4}\b"
        ),
        "[PII:TELEFONE]",
    ),
]

# Nome: heurística conservadora. Duas ou mais palavras Capitalizadas em sequência,
# permitindo conectores minúsculos (da, de, do, dos, das, e). Cobre "João da
# Silva", "Maria Santos". Não é NER; é um proxy determinístico e testável.
_NAME_RE = re.compile(
    r"\b[A-ZÀ-Ý][a-zà-ÿ]+(?:\s+(?:d[aeo]s?|e)\s+[A-ZÀ-Ý][a-zà-ÿ]+|\s+[A-ZÀ-Ý][a-zà-ÿ]+)+\b"
)

# Gatilhos explícitos de nome ("meu nome é X"), que aumentam a confiança e
# capturam também nomes de uma palavra só logo após o gatilho.
_NAME_TRIGGER_RE = re.compile(
    r"(?:meu nome (?:é|e)|me chamo|chamo-me|sou (?:o|a))\s+([A-ZÀ-Ý][a-zà-ÿ]+(?:\s+[A-ZÀ-Ý][a-zà-ÿ]+)*)",
    re.IGNORECASE,
)


def redact_pii(text: str) -> RedactionResult:
    """Mascara toda PII reconhecida em `text` e conta o que foi achado."""
    categories: dict[str, int] = {}
    redacted = text

    for category, pattern, placeholder in _RULES:
        def _sub(_m: re.Match[str], _cat: str = category) -> str:
            categories[_cat] = categories.get(_cat, 0) + 1
            return placeholder

        redacted = pattern.sub(_sub, redacted)

    # Nomes por último: os placeholders acima já não têm formato de nome, e
    # assim evitamos mascarar números como se fossem nome.
    def _count_name() -> None:
        categories["NOME"] = categories.get("NOME", 0) + 1

    # Gatilho explícito primeiro (captura até nome de uma palavra só), depois o
    # padrão geral (dois ou mais termos capitalizados). Substituímos só o trecho
    # do nome (group 1), preservando o restante do gatilho na frase.
    def _sub_trigger(m: re.Match[str]) -> str:
        _count_name()
        return m.group(0).replace(m.group(1), "[PII:NOME]")

    def _sub_name(_m: re.Match[str]) -> str:
        _count_name()
        return "[PII:NOME]"

    redacted = _NAME_TRIGGER_RE.sub(_sub_trigger, redacted)
    redacted = _NAME_RE.sub(_sub_name, redacted)

    return RedactionResult(text=redacted, categories=categories)


class PIIGuard:
    """Guardrail de PII, usável na entrada (redação) e na saída (vazamento).

    Ao achar PII, devolve um veredito com `modified_payload` = texto mascarado e
    `action_hint` = a ação configurada (tipicamente REDACT). O orquestrador
    aplica o payload modificado ao contexto para que a versão limpa siga adiante.
    """

    def __init__(
        self,
        *,
        stage: Stage = "input",
        name: str | None = None,
        action: Action = Action.REDACT,
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        self.stage: Stage = stage
        self.name = name or ("pii_redaction" if stage == "input" else "pii_leak")
        self._action = action
        self._severity = severity

    def check(self, ctx: GuardContext) -> Verdict:
        target = ctx.user_input if self.stage == "input" else (ctx.model_output or "")
        result = redact_pii(target)

        if not result.found:
            return Verdict.ok(self.name, "nenhuma PII encontrada", stage=self.stage)

        resumo = ", ".join(f"{k}={v}" for k, v in sorted(result.categories.items()))
        return Verdict(
            guardrail=self.name,
            passed=False,
            severity=self._severity,
            action_hint=self._action,
            detail=f"PII detectada e mascarada ({resumo})",
            modified_payload=result.text,
            stage=self.stage,
        )
