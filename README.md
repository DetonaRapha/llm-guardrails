# llm-guardrails

Uma camada de guardrails que envolve uma chamada de LLM em domínio regulado:
valida e sanitiza o que entra, verifica e contém o que sai, decide uma ação
(deixar passar, redigir, barrar, escalar ou pedir aprovação humana) e registra
tudo numa trilha de auditoria. É o cérebro de segurança entre o usuário e o modelo.

[![CI](https://github.com/DetonaRapha/llm-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/DetonaRapha/llm-guardrails/actions/workflows/ci.yml)

---

## O problema e o porquê

Em domínio regulado (saúde, jurídico, financeiro), o modelo **sozinho não é
confiável**. Ele pode vazar PII, ser manipulado por injeção de prompt, inventar
fatos (alucinar), sair do escopo permitido ou produzir uma resposta insegura. E
"confie no modelo" não é uma postura de conformidade.

A resposta da engenharia de segurança é **defesa em profundidade**: nenhuma
camada sozinha é confiável, então você empilha várias. Este repositório aplica
esse padrão a LLM — um pipeline de checagens compostas antes e depois da chamada,
com uma decisão central e auditoria de tudo.

Por padrão, **fail-closed**: se qualquer coisa falha ou fica em dúvida, a
resposta segura vence. Em domínio regulado, na dúvida, barra.

---

## A arquitetura em um diagrama

```
                        ┌───────────────────────────────────────┐
                        │        política declarativa (YAML)     │
                        │   liga/desliga · thresholds · ações     │
                        └───────────────────┬───────────────────┘
                                            │ configura
   usuário                                  ▼
     │           ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
     │  entrada  │  Guardrails  │   │              │   │  Guardrails  │
     ├──────────▶│  de ENTRADA  │──▶│    MODELO    │──▶│  de SAÍDA    │
     │           │  (pré-modelo)│   │  (call_model)│   │ (pós-modelo) │
     │           └──────┬───────┘   └──────────────┘   └──────┬───────┘
     │                  │  vereditos          ▲               │ vereditos
     │                  ▼                     │ curto-circuito ▼
     │           ┌─────────────────────────────────────────────────┐
     │           │           MOTOR DE POLÍTICA (fail-closed)         │
     │           │   agrega vereditos → decide a AÇÃO final          │
     │           └───────────────────────┬─────────────────────────┘
     │                                    │
     │            ┌───────────────────────┼───────────────────────┐
     │            ▼                        ▼                       ▼
     │      ALLOW / REDACT       ESCALATE / REQUIRE_APPROVAL     BLOCK
     │            │                (HITL, roteamento)              │
     ◀────────────┴────────── resposta final (ou resposta segura) ┘
                  │
                  ▼
        ┌────────────────────┐
        │  TRILHA DE AUDITORIA │  (todo veredito e decisão, com PII redigida)
        └────────────────────┘
```

- **Curto-circuito:** se a entrada já resolve em BLOCK/ESCALATE/REQUIRE_APPROVAL,
  o modelo **nem é chamado** — entrada maliciosa não gasta chamada nem cria risco.

---

## Como rodar

Requer apenas Python 3.10+ e PyYAML. **Modo determinístico, sem API key.**

```bash
git clone https://github.com/DetonaRapha/llm-guardrails.git
cd llm-guardrails
pip install -e .

# 1) A demo ponta a ponta (cinco cenários):
python -m examples.demo

# 2) A suíte de testes, incluindo fail-closed e red-team:
pytest -q
```

Uso mínimo em código:

```python
from guardrails import Guard

g = Guard.from_policy_file("policies/health.yaml")

def meu_modelo(ctx):
    # aqui entraria a chamada real ao LLM; ctx.user_input já vem sanitizado
    return "Recomenda-se repouso e hidratação."

r = g.run(
    "Meu CPF é 123.456.789-00, estou com febre.",
    call_model=meu_modelo,
    contexts=["Para febre, recomenda-se repouso e hidratação."],
)
print(r.action)        # Action.REDACT / ALLOW / BLOCK / ESCALATE / REQUIRE_APPROVAL
print(r.final_output)  # o que volta pro usuário (a PII já não chegou no modelo)
```

### Ligando os detectores baseados em modelo

Os detectores caros (jailbreak sutil, groundedness, toxicidade) são plugáveis
atrás do protocolo `Classifier`. O **default é o `StubClassifier`**, determinístico
e sem rede — por isso o repo roda no CI sem API key. Para usar um modelo real:

```python
from guardrails import Guard, ModelClassifier

def minha_fn(text, contexts):
    # chame aqui Llama Guard, um endpoint de moderação, ou um LLM juiz
    return {"jailbreak": 0.1, "toxicity": 0.0, "groundedness": 0.9}

g = Guard.from_policy_file("policies/health.yaml", classifier=ModelClassifier(minha_fn))
```

Se a função de classificação falhar, o `ModelClassifier` devolve um resultado
marcado como erro, e a postura fail-closed transforma isso em BLOCK/ESCALATE —
nunca em ALLOW.

---

## As camadas e os guardrails

**Entrada (antes do modelo):**

- `pii_redaction` — detecta e mascara PII (nome, CPF, CNPJ, RG, telefone, e-mail, data) antes de ir ao modelo e ao log.
- `prompt_injection` — pega injeção de prompt e jailbreak (padrões determinísticos + classificador).
- `topicality` — sinaliza entrada fora do escopo permitido (ex: jurídico num sistema de saúde).

**Saída (depois do modelo):**

- `schema` — valida a conformância de schema da resposta estruturada; fora do formato, barra.
- `pii_leak` — redige PII que o modelo tenha reproduzido do contexto.
- `groundedness` — verifica se a resposta é sustentada pelo contexto (anti-alucinação).
- `safety` — passa a saída por um classificador de toxicidade/conteúdo inseguro.
- `domain_policy` — regras do domínio (saúde): sem diagnóstico definitivo nem prescrição.

**Transversal:**

- **Motor de política** — agrega vereditos e decide a ação, com fail-closed.
- **Trilha de auditoria** — todo veredito e decisão viram evento estruturado, com PII redigida.
- **HITL e escalonamento** — ação consequente retida até aprovação; roteamento de baixa confiança.

---

## A política declarativa

O que está ligado, os thresholds e a ação por severidade moram num arquivo
versionado (`policies/health.yaml`), revisável em code review. **Mudar
comportamento é mudar o arquivo, não o código** — isso é governança de verdade.

```yaml
version: 1
fail_closed: true
input:
  pii_redaction:    {enabled: true, action: redact}
  prompt_injection: {enabled: true, action: block,    min_severity: medium}
  topicality:       {enabled: true, action: escalate, allowed_topics: [saude]}
output:
  schema:           {enabled: true, action: block}
  pii_leak:         {enabled: true, action: redact}
  groundedness:     {enabled: true, action: escalate, threshold: 0.7}
  safety:           {enabled: true, action: block,    threshold: 0.5}
  domain_policy:    {enabled: true, action: block}
severity_actions:
  critical: block
  high:     escalate
```

Ordem de força das ações: `allow < redact < require_approval < escalate < block`.
A ação mais severa entre os vereditos vence, e `severity_actions` pode elevá-la.

---

## Segurança e conformidade

O coração do repo. Os controles mapeiam diretamente para dois frameworks que o
mercado sério cita:

### ISO/IEC 42001 — Sistema de Gestão de IA

| Controle do repo | Evidência de gestão |
|---|---|
| Validação de entrada/saída (`detectors/`) | Controles operacionais sobre o uso do sistema de IA |
| Redação de PII (`pii.py`, auditoria) | Proteção de dados pessoais ao longo do ciclo |
| Política declarativa versionada (`policies/*.yaml`) | Política documentada, controlada e revisável |
| HITL (`hitl.py`) | Supervisão humana sobre decisões consequentes |
| Trilha de auditoria (`audit.py`) | Registro e rastreabilidade para revisão e melhoria contínua |

### NIST AI RMF — Governar, Mapear, Medir, Gerir

| Função | Onde o repo a implementa |
|---|---|
| **Mapear** | O pipeline de guardrails identifica os riscos por interação (PII, injeção, alucinação, toxicidade, escopo). |
| **Medir** | Cada guardrail emite veredito com severidade; a observabilidade sobre taxas de bloqueio/escalonamento quantifica o risco. |
| **Gerir** | O motor de política decide e trata (redigir, barrar, escalar, HITL), com fail-closed. |
| **Governar** | A política versionada + a trilha de auditoria dão o registro auditável que sustenta a governança. |

Cross-link: junto com o [`mcp-health-server`](https://github.com/DetonaRapha)
(que aplica o mesmo rigor no lado das *ferramentas* que o modelo pode executar),
fecha a história — um cuida do que o modelo **executa**, este do que ele
**recebe e responde**.

---

## Decisões de design e tradeoff

Por que pipeline composável, fail-closed, determinístico primeiro, política
declarativa e auditoria de tudo — e por que **não** um framework pronto ou
checagens soltas no código. O raciocínio completo, estilo RFC, está em
[DESIGN.md](DESIGN.md).

---

## Futuro (fora do escopo deste repo)

Vizinhos citados de propósito, **não** implementados aqui:

- **Rate limiting / WAF** — pertence à borda da rede, não a esta camada.
- **Serviço hospedado / SLA** — este é um exemplo fechado, não um produto de moderação gerenciado.
- **Classificador próprio treinado** — usamos detector determinístico ou modelo pronto; não treinamos.
- **NER de PII industrial** (ex: Microsoft Presidio) — encaixa atrás da mesma interface de `redact_pii`.

---

## Licença

MIT — ver [LICENSE](LICENSE).
