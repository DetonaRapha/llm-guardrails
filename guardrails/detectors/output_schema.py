"""Conformância de schema da saída.

Se a resposta do modelo deveria ser estruturada (JSON com certas chaves), este
guardrail valida. Fora do formato, barra — nunca entrega ao usuário um payload
que o sistema a jusante não consegue consumir.

O schema esperado vem de duas fontes, nesta ordem:

1. `ctx.metadata["output_schema"]`, um dict ``{"required": [...]}`` — deixa a
   expectativa viajar por interação (RAG/rota diferente pede formato diferente).
2. As `required_keys` passadas na construção do guardrail (default fixo).

Se nenhuma expectativa de schema existir, o guardrail passa: não há o que validar.
A validação é intencionalmente leve (JSON + chaves obrigatórias) para não puxar
uma dependência; o gancho para Pydantic/JSON Schema é o parâmetro `validator`.
"""

from __future__ import annotations

import json
from typing import Callable

from guardrails.types import Action, GuardContext, Severity, Verdict

# Um validador customizado recebe o objeto já parseado e devolve
# (ok, mensagem_de_erro). Permite plugar Pydantic/JSON Schema sem mudar o resto.
Validator = Callable[[object], tuple[bool, str]]


class OutputSchemaGuard:
    """Guardrail de conformância de schema (saída)."""

    name = "schema"
    stage = "output"

    def __init__(
        self,
        *,
        required_keys: list[str] | None = None,
        validator: Validator | None = None,
        action: Action = Action.BLOCK,
        severity: Severity = Severity.HIGH,
    ) -> None:
        self._required_keys = required_keys
        self._validator = validator
        self._action = action
        self._severity = severity

    def _expected_keys(self, ctx: GuardContext) -> list[str] | None:
        schema = ctx.metadata.get("output_schema")
        if isinstance(schema, dict) and isinstance(schema.get("required"), list):
            return [str(k) for k in schema["required"]]
        return self._required_keys

    def check(self, ctx: GuardContext) -> Verdict:
        required = self._expected_keys(ctx)
        # Sem schema esperado e sem validador => nada a impor.
        if required is None and self._validator is None:
            return Verdict.ok(self.name, "nenhum schema exigido", stage=self.stage)

        raw = ctx.model_output or ""
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return self._fail("saída não é JSON válido")

        if required is not None:
            if not isinstance(obj, dict):
                return self._fail("saída JSON não é um objeto")
            missing = [k for k in required if k not in obj]
            if missing:
                return self._fail(f"chaves obrigatórias ausentes: {missing}")

        if self._validator is not None:
            ok, msg = self._validator(obj)
            if not ok:
                return self._fail(f"validador rejeitou a saída: {msg}")

        return Verdict.ok(self.name, "saída em conformidade com o schema", stage=self.stage)

    def _fail(self, motivo: str) -> Verdict:
        return Verdict(
            guardrail=self.name,
            passed=False,
            severity=self._severity,
            action_hint=self._action,
            detail=f"schema inválido: {motivo}",
            stage=self.stage,
        )
