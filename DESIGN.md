# DESIGN — llm-guardrails

Documento de decisões, estilo RFC. Explica **por que** o sistema foi desenhado
assim, e o **por que não** dos caminhos alternativos. O "por que não do outro
jeito" é o sinal de senioridade — e é o que separa quem só constrói de quem
governa o que construiu.

---

## 1. Contexto

Um LLM em domínio regulado (saúde, jurídico, financeiro) opera sob duas verdades
incômodas:

1. **O modelo não é confiável isoladamente.** Ele pode vazar PII, ser induzido
   por injeção de prompt, alucinar fatos, sair do escopo ou gerar conteúdo
   inseguro. Nenhum desses riscos é hipotético; todos têm exploração conhecida.
2. **"Confie no modelo" não passa numa auditoria.** Em domínio regulado, é
   preciso *demonstrar* controle: o que foi checado, o que foi decidido, por que,
   e com qual evidência. Sem trilha, não há conformidade.

Domínio regulado muda tudo porque inverte o default. Num produto comum, o custo
de um falso positivo (barrar algo legítimo) costuma superar o de um falso
negativo (deixar passar algo ruim). Em domínio regulado é o contrário: deixar
vazar PII ou dar um diagnóstico definitivo indevido é o dano caro. Logo, o
default precisa ser **fail-closed** — na dúvida, barra.

---

## 2. Decisão

Adotamos o padrão de **defesa em profundidade** da engenharia de segurança,
aplicado a LLM, com cinco decisões estruturais:

### 2.1 Pipeline composável

Cada guardrail é um `check` independente com uma interface comum
(`Guardrail.check(ctx) -> Verdict`). Liga, desliga e combina sem tocar no resto.
O orquestrador não conhece o detalhe de cada detector; só roda a lista e coleta
vereditos. Isso dá testabilidade (cada guardrail é uma unidade) e extensibilidade
(novo detector = nova classe, zero mudança no núcleo).

### 2.2 Fail-closed

A postura de segurança central. Se um detector lança erro, se um classificador
fica indisponível, se o modelo falha — a decisão final é BLOCK ou ESCALATE,
**jamais** ALLOW. Isso é imposto em três lugares: cada guardrail roda dentro de
`try/except` (exceção vira veredito de erro CRÍTICO), a chamada ao modelo idem, e
o motor de política resolve qualquer veredito de erro para o fallback. É o
comportamento provado no teste mais importante do repo (`test_fail_closed_*`).

### 2.3 Determinístico primeiro, modelo depois

Os detectores baratos e determinísticos (PII por regex, injeção por padrões,
schema, topicalidade) rodam sem rede e no CI. Os caros e baseados em modelo
(jailbreak sutil, groundedness, toxicidade) ficam atrás de uma abstração
(`Classifier`), com um **stub determinístico como default**. Consequência: o repo
inteiro roda, testa e demonstra sem nenhuma API key. O modelo é um upgrade
opcional, não uma dependência obrigatória.

### 2.4 Política declarativa e versionada

O que está ligado, os thresholds e a ação por severidade moram num arquivo YAML
com número de versão. Mudar comportamento é mudar o arquivo, revisável em code
review — não mexer no código nem redeployar lógica. Separar *política* de
*mecanismo* é o que transforma "um monte de ifs" em governança.

### 2.5 Auditoria de tudo

Todo veredito e toda decisão viram evento estruturado, com timestamp e PII
redigida. A auditoria não confia que alguém já limpou: ela mesma passa todo texto
livre por `redact_pii` antes de persistir. Rastreabilidade é requisito, não
enfeite — é a evidência que sustenta a conformidade.

---

## 3. Alternativas consideradas

### 3.1 Usar um framework pronto (NeMo Guardrails, Guardrails AI)

**Prós:** menos código, comunidade, detectores prontos.

**Contras que pesaram mais aqui:**
- **Transparência e controle.** Frameworks generalistas trazem abstrações
  próprias (DSLs, "rails", grafos de fluxo) que escondem a decisão. Em domínio
  regulado, preciso poder apontar a linha exata onde a PII é redigida e onde o
  fail-closed acontece. Uma dependência opaca vira um risco de auditoria.
- **Aderência a norma.** Amarrar cada controle a ISO/IEC 42001 e NIST AI RMF é
  mais direto quando eu controlo o mapeamento; com um framework, eu mapearia a
  *configuração do framework*, não o meu sistema.
- **Postura de segurança.** O default fail-closed e o comportamento sob erro de
  detector são decisões que quero *provar em código*, não herdar de terceiros.

**Quando eu escolheria o framework:** um produto genérico multi-domínio, com
time grande, onde a velocidade de cobrir muitos casos supera a necessidade de
transparência regulatória. Não é este caso.

### 3.2 Colar checagens soltas no código

**Contras decisivos:** vira `if` espalhado, sem interface comum, sem lugar único
para a decisão, sem política versionada, sem auditoria consistente. Impossível de
testar em isolamento e impossível de governar. É exatamente a armadilha de
"erguer o genérico antes do concreto" ou, pior, nunca sair do concreto bagunçado.

---

## 4. Tradeoffs (o que ganhamos e o que abrimos mão)

| Ganhamos | Abrimos mão de |
|---|---|
| **Controle e transparência** — cada decisão é rastreável a uma linha. | Conveniência de detectores prontos de um framework. |
| **Testabilidade** — cada guardrail e o motor testados em isolamento; CI verde sem rede. | Cobertura "de fábrica" de casos exóticos que um framework maduro já traria. |
| **Aderência a norma** — controles mapeados a ISO 42001 e NIST AI RMF. | Nada relevante — este era um objetivo, não um custo. |
| **Roda sem API key** (stub determinístico) — barreira de entrada zero. | Precisão dos detectores baseados em modelo até que o usuário os ligue. |
| **Governança** (política declarativa versionada). | Um pouco de indireção: comportamento mora em dois lugares (código + YAML). |
| **Fail-closed por padrão.** | Taxa maior de falsos positivos — aceitável e desejável em domínio regulado. |

### Limitações conhecidas (honestas)

- Os detectores determinísticos são **transparentes e testáveis, não
  abrangentes**. O regex de nome é heurístico; o léxico de toxicidade e de
  tópicos é pequeno. São a base correta; a precisão vem ao plugar Presidio /
  Llama Guard / um LLM juiz atrás das interfaces já existentes.
- A groundedness do stub é sobreposição léxica, não verificação factual. É um
  *proxy* honesto para CI; o `ModelClassifier` é o caminho para o real.
- O léxico e as regras de domínio têm sabor de saúde. É um exemplo fechado de
  propósito — não pretende ser um framework universal.

---

## 5. Fluxo de decisão (resumo executável)

```
entrada → guardrails de entrada → vereditos
        → política decide
             ├─ BLOCK/ESCALATE/REQUIRE_APPROVAL → curto-circuito (não chama o modelo)
             └─ ALLOW/REDACT → chama o modelo (com a entrada já sanitizada)
                             → guardrails de saída → vereditos
                             → política decide (entrada + saída) → ação final
                             → HITL, se ação consequente
        → auditoria de tudo (PII redigida)
        → GuardedResult
```

O motor de política, em uma frase: **pega a ação mais severa entre os vereditos,
eleva conforme a severidade, e trata erro como fallback — nunca como ALLOW.**
