"""Abstração de detector baseado em modelo, com stub determinístico como default.

Os detectores caros (jailbreak sutil, groundedness, toxicidade) precisam de um
classificador. Em vez de amarrar o repo a uma API, definimos um `Classifier`
plugável:

- `StubClassifier`: determinístico, sem rede, roda no CI. É o **default**. Usa
  heurísticas transparentes (sobreposição léxica, listas de termos) para produzir
  scores estáveis. Nunca é "inteligente"; é previsível, que é o que um teste quer.
- `ModelClassifier`: adaptador para um LLM ou endpoint de moderação real. Recebe
  uma função `classify_fn` injetada. Se ela falhar, o classificador devolve um
  resultado marcado como não-confiável — e a postura fail-closed do resto do
  sistema transforma isso em BLOCK/ESCALATE, nunca em ALLOW.

O contrato `classify` devolve um dict com scores em [0.0, 1.0]:

    {
        "jailbreak":    float,  # probabilidade de tentativa de burla
        "toxicity":     float,  # probabilidade de conteúdo tóxico/inseguro
        "groundedness": float,  # o quanto o texto é sustentado pelos contextos
        "error":        bool,   # True se o classificador não pôde decidir
    }
"""

from __future__ import annotations

import re
from typing import Callable, Protocol, runtime_checkable

# Chaves que todo classificador deve devolver, com defaults seguros.
_DEFAULT_SCORES: dict[str, float | bool] = {
    "jailbreak": 0.0,
    "toxicity": 0.0,
    "groundedness": 1.0,
    "error": False,
}


@runtime_checkable
class Classifier(Protocol):
    """Interface do detector baseado em modelo."""

    def classify(self, text: str, contexts: list[str]) -> dict: ...


# ---------------------------------------------------------------------------
# Stub determinístico (default do repo)
# ---------------------------------------------------------------------------

# Termos e padrões que um classificador de jailbreak "sutil" pegaria além dos
# padrões literais do detector determinístico de injeção. Ficam aqui para o stub
# ter algum sinal sem depender de rede.
_JAILBREAK_HINTS = (
    "developer mode",
    "modo desenvolvedor",
    "sem restrições",
    "sem restricoes",
    "no restrictions",
    "pretend you are",
    "finja que você",
    "finja que voce",
    "act as if",
    "aja como se",
    "bypass",
    "burlar",
    "contorne",
    "unfiltered",
    "sem filtro",
    "dan mode",
)

# Léxico simples de toxicidade/conteúdo inseguro. Deliberadamente pequeno e
# transparente — o objetivo é ser testável, não abrangente. Um `ModelClassifier`
# com Llama Guard ou endpoint de moderação faz o trabalho de verdade.
_TOXIC_HINTS = (
    "idiota",
    "imbecil",
    "otário",
    "otario",
    "vá se matar",
    "va se matar",
    "kill yourself",
    "how to build a bomb",
    "como fazer uma bomba",
    "fabricar explosivo",
    "arma caseira",
)

_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _tokens(text: str) -> set[str]:
    """Conjunto de tokens minúsculos, para medir sobreposição léxica."""
    return {t.lower() for t in _WORD_RE.findall(text)}


class StubClassifier:
    """Classificador determinístico, o default do repo.

    Não usa rede nem modelo. Produz scores estáveis a partir de heurísticas
    explícitas, o que torna os testes reprodutíveis. É "burro" de propósito.
    """

    #: palavras curtas ignoradas ao medir groundedness (baixo valor informativo).
    _STOPWORDS = frozenset(
        "a o e de da do que em para com no na os as um uma se por é são"
        " the of and to in for is are with that this it as be".split()
    )

    def classify(self, text: str, contexts: list[str]) -> dict:
        scores = dict(_DEFAULT_SCORES)
        low = text.lower()

        # Jailbreak: fração de dicas presentes, saturando rápido.
        hits = sum(1 for h in _JAILBREAK_HINTS if h in low)
        scores["jailbreak"] = min(1.0, hits * 0.5)

        # Toxicidade: presença de qualquer termo do léxico já é forte sinal.
        tox_hits = sum(1 for h in _TOXIC_HINTS if h in low)
        scores["toxicity"] = min(1.0, tox_hits * 0.6)

        # Groundedness: proporção de tokens significativos do texto que aparecem
        # em algum contexto. Sem contexto, não há como sustentar => score baixo.
        scores["groundedness"] = self._groundedness(text, contexts)
        return scores

    def _groundedness(self, text: str, contexts: list[str]) -> float:
        content = _tokens(text) - self._STOPWORDS
        if not content:
            return 1.0  # nada a sustentar (texto vazio/sem conteúdo)
        if not contexts:
            return 0.0  # afirmações sem nenhum contexto de apoio
        support = set()
        for c in contexts:
            support |= _tokens(c)
        support -= self._STOPWORDS
        overlap = content & support
        return round(len(overlap) / len(content), 4)


# ---------------------------------------------------------------------------
# Adaptador para modelo real (opcional, plugável)
# ---------------------------------------------------------------------------

# Uma função de classificação real recebe (text, contexts) e devolve o mesmo
# dict de scores. É injetada de fora (um wrapper de LLM, Llama Guard, etc.).
ClassifyFn = Callable[[str, list[str]], dict]


class ModelClassifier:
    """Adaptador para um classificador baseado em modelo/endpoint real.

    Recebe `classify_fn` injetada. Nunca é dependência obrigatória: se ninguém
    passar uma função, ou se ela falhar, devolvemos ``error=True`` com scores
    conservadores (pior caso), deixando a política aplicar fail-closed.
    """

    def __init__(self, classify_fn: ClassifyFn | None = None) -> None:
        self._fn = classify_fn

    def classify(self, text: str, contexts: list[str]) -> dict:
        if self._fn is None:
            return self._unavailable("nenhuma função de classificação configurada")
        try:
            raw = self._fn(text, contexts)
        except Exception as exc:  # noqa: BLE001 - qualquer falha vira fail-closed
            return self._unavailable(f"classificador falhou: {exc}")
        # Normaliza: garante todas as chaves e faz clamp em [0, 1].
        scores = dict(_DEFAULT_SCORES)
        for key in ("jailbreak", "toxicity", "groundedness"):
            if key in raw:
                try:
                    scores[key] = max(0.0, min(1.0, float(raw[key])))
                except (TypeError, ValueError):
                    return self._unavailable(f"score inválido para {key!r}")
        scores["error"] = bool(raw.get("error", False))
        return scores

    @staticmethod
    def _unavailable(_reason: str) -> dict:
        """Resultado de pior caso: marca erro e assume tudo suspeito.

        jailbreak/toxicity altos e groundedness zero fazem qualquer política
        razoável agir de forma restritiva. A `_reason` fica disponível para
        quem quiser logar; o dict em si não a carrega para não vazar detalhe.
        """
        return {
            "jailbreak": 1.0,
            "toxicity": 1.0,
            "groundedness": 0.0,
            "error": True,
        }
