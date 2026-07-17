"""Garante que o pacote `guardrails` seja importável ao rodar `pytest` da raiz,
mesmo sem `pip install -e .`. O pytest insere o diretório deste conftest no
início do sys.path.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
