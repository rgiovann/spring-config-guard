# Backlog Técnico — spring-config-guard

Este documento consolida limitações conhecidas e itens de dívida técnica
identificados durante o desenvolvimento, para que fiquem registrados e
priorizáveis em vez de esquecidos ou descobertos tarde demais em produção.

Cada item foi **confirmado com código real rodando** (não é suposição) antes
de ser registrado aqui — a menos que marcado explicitamente como "não
verificado".

---

## Prioridade Alta

### BL-01 — `EffectiveConfig.properties()` não é protegido contra mutação externa

**Onde:** `ProfileMerger.merge()`, construção de cada `EffectiveConfig`.

**Problema:** o `Map<String,String>` exposto por `EffectiveConfig.properties()`
é o `LinkedHashMap` mutável interno, sem nenhuma proteção
(`Collections.unmodifiableMap` ou equivalente). Qualquer código que receba
uma `EffectiveConfig` pode chamar `.properties().put(...)` ou `.remove(...)`
livremente.

**Por que importa:** `RuleEngine` reutiliza o **mesmo objeto** `EffectiveConfig`
entre múltiplas `Rule` em sequência (para um dado profile, todas as regras
registradas recebem a mesma instância). Se qualquer `Rule` — atual ou futura —
tiver um bug que mute o mapa recebido, a contaminação **vaza silenciosamente**
para todas as regras seguintes que avaliarem o mesmo `EffectiveConfig`, sem
exceção, sem log, sem sinal de que algo deu errado.

**Confirmado com código:** sim — `dev.properties().put("chave-maliciosa", "x")`
foi aceito sem exceção, e a mutação persistiu em leituras subsequentes do
mesmo objeto.

**Custo de correção estimado:** **baixo**. Envolver os mapas com
`Collections.unmodifiableMap(...)` antes de construir cada `EffectiveConfig`
em `ProfileMerger.merge()` (nos dois pontos: construção do "base" e construção
de cada profile fundido).

**Teste de regressão já escrito:**
`effectiveConfigNaoEProtegidoContraMutacaoExterna` (documenta o estado atual,
não corrigido).

---

### BL-02 — Sentinela `"base"` colide com nome de profile real

**Onde:** `ProfileMerger.BASE_PROFILE_LABEL` (constante `"base"`) vs.
`ConfigDocument.profile()` de um documento nomeado pelo usuário.

**Problema:** o Spring não reserva a palavra `base` como nome de profile —
`spring.config.activate.on-profile: base` é sintaticamente válido. Como
`ProfileMerger` usa a string literal `"base"` como sentinela para "nenhum
profile ativo", um profile real chamado `base` colide com essa sentinela.

**Por que importa:** o resultado de `merge()` passa a conter **duas**
`EffectiveConfig` com `profileLabel="base"` — uma sintética (config
incondicional) e outra do profile nomeado pelo usuário (já fundida com o
base). Qualquer busca por rótulo (`findFirst()`, `Map` indexado por
`profileLabel`, etc.) só enxerga a primeira, tornando a segunda **inacessível
por nome**, ainda que presente na lista.

**Confirmado com código:** sim — `merge()` gerou 2 `EffectiveConfig` com
`profileLabel="base"` simultaneamente.

**Custo de correção estimado:** **médio-alto**, envolve uma decisão de design,
não só um ajuste local. Duas rotas possíveis:
1. Validar/rejeitar (ou emitir warning) quando um profile literal `base` for
   encontrado no `ConfigLoader`, antes de chegar ao `ProfileMerger`.
2. Trocar `EffectiveConfig.profileLabel: String` por um tipo que distinga
   estruturalmente "sintético" de "nomeado pelo usuário" (ex: `sealed
   interface ProfileLabel { record Synthetic(), record Named(String name) }`).
   Isso reabre a decisão de design anterior de manter `profileLabel` como
   `String` puro (nunca `Optional`/nulo) por simplicidade — avaliar
   custo/benefício antes de reverter essa decisão.

**Teste de regressão já escrito:**
`profileExplicitamenteChamadoBaseColideComBaseSintetico` (documenta a
colisão, não corrigida).

---

## Prioridade Média

### BL-03 — Purga de lista não detecta redefinição via lista vazia nem via relaxed-binding escalar

**Onde:** `ConfigLoader.flatten()` (origem do problema) +
`ProfileMerger.mergeProperties()` (onde o sintoma aparece).

**Problema:** o algoritmo de purga de lista em `mergeProperties` só detecta
"isso é uma lista sendo redefinida" através da presença de `[` na chave do
overlay. Dois cenários reais de config Spring escapam dessa detecção:

- **(a) Lista vazia explícita** (`allowed-origins: []`): `flatten()` produz
  **zero chaves** para uma lista YAML vazia — não há nenhum rastro no mapa
  achatado de que a chave foi mencionada. Um profile que tenta *limpar* uma
  lista herdada do base acaba, ao contrário da intenção, **herdando ela
  inteira**.
- **(b) Relaxed-binding escalar** (`allowed-origins: "a.com,b.com"`, sintaxe
  válida e documentada do Spring para popular `List<String>`): gera uma chave
  **sem** `[` (`cors.allowed-origins`), que não aciona a purga. O resultado é
  um estado inconsistente — a chave nova coexiste com os índices órfãos do
  base (`cors.allowed-origins[0]`, `[1]`, etc.), que nunca deveriam ter
  sobrevivido.

**Por que importa:** numa ferramenta de segurança, esse tipo de imprecisão
tende para **falso positivo** (um valor perigoso do base "sobrevive" na config
efetiva de um profile que tentou removê-lo/substituí-lo) — menos grave que
falso negativo, mas ainda mina a confiança na ferramenta.

**Confirmado com código:** sim, para os dois sub-casos, separadamente.

**Custo de correção estimado:** **médio**. Requer nova lógica de detecção
em pelo menos um dos dois pontos:
- Para (a): `flatten()` poderia emitir uma chave-sentinela quando encontrar
  uma lista vazia (ex: `cors.allowed-origins.__empty__ = true`), permitindo
  que `mergeProperties` reconheça a intenção de "lista redefinida como vazia"
  e purgue mesmo sem chaves indexadas no overlay.
- Para (b): `mergeProperties` poderia, ao montar `listRootsInOverlay`,
  também checar se alguma chave do overlay **coincide exatamente** (sem `[`)
  com um prefixo de lista já existente no base, tratando isso como sinal de
  redefinição escalar e disparando a mesma purga.

Recomendação: resolver os dois juntos numa mesma sessão dedicada, já que
compartilham a mesma causa raiz (detecção de "isso é uma lista sendo
redefinida" incompleta).

**Testes de regressão já escritos:**
`limitacaoConhecida_hashDentroDeAspasQuebraOValor` *(não relacionado — nome
similar apenas por convenção)*; os relevantes aqui ainda precisam ser
adicionados como protótipos de `ProfileMergerTest` documentando o
comportamento atual (ver casos discutidos: lista vazia e escalar-vs-lista).

---

## Prioridade Baixa

### BL-04 — `findBaseProperties` perde dado silenciosamente se invariante de "documento único-base" for violada

**Onde:** `ProfileMerger.findBaseProperties()`.

**Problema:** o método assume que existe no máximo 1 `ConfigDocument` com
profile vazio por `ConfigFile` — invariante hoje **garantida pelo
`ConfigLoader`** (múltiplos documentos-base já são fundidos entre si lá,
testado e confirmado), mas **não verificada de forma independente** pelo
`ProfileMerger`. Se essa invariante for violada (bug futuro no `ConfigLoader`,
ou construção manual de `ConfigFile` fora do pipeline normal), o primeiro
documento-base encontrado "vence" e os demais são descartados sem aviso.

**Por que a prioridade é baixa:** a violação só ocorre se uma garantia de
**outra camada**, já testada e validada, for quebrada — não é um cenário que
a configuração real de um usuário pode disparar através do pipeline normal.

**Questão em aberto:** vale a pena `ProfileMerger` ter defesa em profundidade
própria (fundir todos os documentos-base que encontrar, redundante com o
`ConfigLoader`) ou é aceitável confiar no contrato implícito da camada
inferior? Decisão de trade-off entre robustez e duplicação de lógica — a
decidir antes de implementar.

**Confirmado com código:** sim — segundo documento-base construído
manualmente teve seu conteúdo completamente descartado, sem exceção.

**Custo de correção estimado:** **baixo**, se optar por resolver (trocar
"pega o primeiro" por "funde todos que achar").

**Teste de regressão já escrito:**
`doisDocumentosBaseApenasPrimeiroEUsadoSegundoEPerdido`.

---

## Itens de Backlog Anteriores (sessões passadas, ainda válidos)

Registrados aqui apenas para manter o documento como fonte única de verdade —
não fazem parte da revisão de hoje.

### BL-05 — Expressões de profile não suportadas
`on-profile: "prod & !test"` (lógica booleana de profiles) está fora de
escopo. Tratado hoje como profile "complexo/desconhecido" — comportamento
exato ainda a formalizar com teste dedicado.

### BL-06 — Múltiplos profiles ativos simultaneamente não suportados
A ferramenta hoje avalia cada profile **isoladamente** contra o base (nunca
`dev,mysql` juntos, por exemplo). Fora de escopo por decisão deliberada —
explode combinatoriamente (2^N profiles) se implementado ingenuamente.

### BL-07 — Teste placeholder de documento vazio após último separador
`documentoVazioAposUltimoSeparadorNaoDeveQuebrar` em `ConfigLoaderTest` ainda
falha propositalmente (`assertTrue(false, ...)`). A lógica já foi validada
via sandbox — falta só formalizar o `assertEquals` real.

---

## Resumo por prioridade

| ID | Item | Prioridade | Custo estimado |
|----|------|------------|-----------------|
| BL-01 | `EffectiveConfig` não blindado contra mutação | 🔴 Alta | Baixo |
| BL-02 | Colisão de nome de profile "base" | 🔴 Alta | Médio-alto (decisão de design) |
| BL-03 | Purga de lista não detecta lista vazia / relaxed-binding escalar | 🟡 Média | Médio |
| BL-04 | Perda silenciosa se invariante de base único for violada | 🟢 Baixa | Baixo |
| BL-05 | Expressões de profile | 🟢 Baixa (backlog antigo) | Alto |
| BL-06 | Múltiplos profiles simultâneos | 🟢 Baixa (backlog antigo) | Alto |
| BL-07 | Teste placeholder pendente | 🟢 Baixa (sprint atual) | Trivial |
