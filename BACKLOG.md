# Backlog

Este arquivo é o estado planejado do projeto: o que está em andamento e as
próximas regras candidatas, em ordem de prioridade. Não é um contrato — é
esperado que itens sejam descobertos, descartados, divididos, combinados ou
repriorizados conforme o projeto avança.

A lista de regras já implementadas é
`src/main/resources/META-INF/services/dev.scg.core.Rule`, com os IDs
validados por `RuleRegistryTest`. Este arquivo não a duplica.

## Próximas regras candidatas

Ordem por relação esforço/valor, não por dependência técnica.

1. **`management.endpoint.health.show-details=always`** — vaza detalhes
   internos do sistema (disco, DB, filas) via `/actuator/health` sem
   autenticação.
2. **TLS desabilitado em URIs de conexão com serviços de apoio** — JDBC
   `useSSL=false`/`verifyServerCertificate=false`, Postgres
   `sslmode=disable`, Mongo/Redis `ssl=false`. Ângulo de transporte que
   complementa o parsing de URI já feito pela SCG007 (focado em
   credenciais).
3. **(Prioridade baixa) Upload multipart sem limite** —
   `spring.servlet.multipart.max-file-size`/`max-request-size`
   ilimitado ou `-1`. Mais adjacente a DoS do que a
   confidencialidade/integridade, por isso a prioridade menor.
4. **(Prioridade baixa, deliberada) `InsecureTransportProtocolRule`** —
   `http://` em propriedades arbitrárias fora do escopo de CORS (ex:
   `jhipster.mail.base-url`, webhooks, callback URLs, `issuer-uri` de
   OAuth2/OIDC). Confirmado que hoje não há sobreposição: a SCG004
   (`CorsInsecureProtocolsRule`) só olha
   `management.endpoints.web.cors.allowed-origins`/`-origin-patterns`; a
   SCG006 (`HardcodedSecretsRule`) é sobre segredos, não protocolo. É
   um vetor de transporte diferente do item 2 acima (que mira parâmetros
   de conexão JDBC/Postgres/Mongo/Redis, não propriedades de domínio
   arbitrárias) — complementares, não duplicados.
   Prioridade baixa é deliberada, não um descuido: definir quais chaves
   arbitrárias contam como "transporte crítico" exige esforço semântico
   alto para um retorno marginal comparado a vetores diretamente
   exploráveis (SCG001 Actuator exposto, SCG003/004/005 CORS permissivo,
   SCG006 segredo vazado), com risco real de ruído em mocks locais,
   containers isolados e service mesh com TLS no sidecar — o tipo de
   falso positivo que mina a confiança na ferramenta logo nas primeiras
   execuções.

## Débito técnico e features de plataforma

### Sentinel de profile base vaza para a saída da CLI

`ProfileMerger.BASE_PROFILE_LABEL` (`__spring_config_guard_base__`) é o
label sintético usado internamente para "sem profile ativo" — ver o
Javadoc da constante em
[ProfileMerger.java:22](src/main/java/dev/scg/core/ProfileMerger.java:22)
para o porquê de não ser simplesmente `"base"` (colidiria com um profile
Spring real chamado literalmente `base`, sintaticamente válido embora
raro). O problema é que `Finding.toString()`
([Finding.java:29](src/main/java/dev/scg/core/Finding.java:29)) imprime
`profileLabel` cru, então o `ConsoleReporter` hoje mostra o sentinel
interno direto pro usuário:

```
[HIGH] SCG003 (demo-project\application.yml) [profile: __spring_config_guard_base__]
```

que parece ser um profile Spring real, mas não é.

Comportamento desejado: `application.yml` → `[base]`;
`application-prod.yml` → `[profile: prod]` (nomes reais de profile
preservados exatamente como no arquivo — a distinção deve vir da origem
estrutural do arquivo, não de inferência sobre o nome do profile, já que
um profile real pode se chamar quase qualquer coisa).

Fix pertence à camada de apresentação, não ao modelo interno: manter
`BASE_PROFILE_LABEL` como está (não criar um profile reservado chamado
`"base"` — seria reintroduzir exatamente o problema que a constante já
resolveu) e traduzir apenas na formatação do `ConsoleReporter`/
`Finding.toString()`. Vale decidir também o que fazer no `JsonReporter`
— que hoje serializa o `Finding` bruto via Jackson, então o mesmo
sentinel aparece no JSON; para um formato consumido por máquina isso é
plausivelmente aceitável (valor estável para matching), mas é uma
decisão em aberto, não assumida aqui.

### Mensagem da SCG001 superestima o vazamento quando `show-values` fica no default

Descoberto investigando o gap de `show-values` (sessão 2026-09-10), fora do
escopo daquele fix — é sobre o finding *original* de wildcard, não o novo.

`ActuatorExposureRuleTest`/`ActuatorExposureRule.java` — o finding de
`exposure.include=*` com endpoint irrestrito diz *"exposes actual secrets
in memory"*. Confirmado no source real do Spring Boot
(`org.springframework.boot.actuate.endpoint.Sanitizer`): `show-values` é
um master switch — no default (`never`), **todo** valor é mascarado, sem
nem rodar o pattern-matching de chaves sensíveis (`password`, `secret`,
`token`...). Ou seja, um endpoint `env`/`configprops` reachable +
irrestrito, mas com `show-values` ainda no default, vaza nomes de
propriedades e estrutura de config — não os valores em si. A frase atual
superestima esse cenário específico.

Não é urgente corrigir: a severidade HIGH continua correta (a estrutura
exposta já é reconhecimento útil pra um atacante, e a maioria dos deploys
reais não deixa `show-values` no default junto de um wildcard por muito
tempo), é só a redação que fala mais do que o dado prova. Ajuste seria
puramente de wording na mensagem do finding de wildcard, sem mudar
lógica/severidade/testes.

### Camada de Policy: supressão binária de findings por regra + profile

Feature nova — não existe hoje. Registra um design já discutido e
decidido, não apenas uma ideia solta.

**Motivação:** as regras do projeto são — e devem continuar sendo —
agnósticas a profile: recebem uma `EffectiveConfig`, avaliam, emitem
`Finding` com severidade fixa definida pela própria regra, sem embutir
política de "profile X merece menos rigor" (ver
[[feedback_zero_trust_no_profile_exemption]]). Decisões desse tipo (ex:
"aceitamos segredo hardcoded em dev") pertencem a cada time analisado,
não à ferramenta — por isso saem da regra e viram uma camada separada,
pós-avaliação.

**Design confirmado:**

1. **Posição no pipeline:** entre `RuleEngine.run()` (produz
   `List<Finding>`) e `Reporter`/`ExitCodeResolver` — confirmado contra
   o wiring atual em
   [Main.java:64-69](src/main/java/dev/scg/Main.java:64): hoje é
   `findings = engine.run(...)` seguido direto por `reporter.report(...)`
   e `new ExitCodeResolver().resolve(...)`; a Policy entraria filtrando
   `findings` entre essas duas chamadas. Nem `Reporter` nem
   `ExitCodeResolver` precisam saber que a política existe.
2. **Escopo inicial:** supressão binária apenas (ignora o finding
   inteiro). Ajuste gradual de severidade (rebaixar em vez de suprimir)
   foi cogitado e deliberadamente adiado — mesmo raciocínio YAGNI já
   aplicado em outras partes do projeto (ex: `RelaxedBoolean`): não
   generalizar antes de uma segunda necessidade real aparecer.
3. **Granularidade:** por regra + profile (não só por profile) —
   motivação explícita: um time pode querer manter algumas regras ativas
   mesmo em profiles seguros (ex: SCG002 suprimida em `dev`, mas SCG006
   continua ativa em `dev`).

## Descartado / fora de escopo

* **CSRF desabilitado** — normalmente feito via `http.csrf().disable()`
  em um bean `SecurityFilterChain` Java, não em
  `application.yml`/`.properties`. O projeto só faz parsing estático de
  arquivos de config (sem dependência do Spring Boot, sem análise de
  bytecode/AST), então não há superfície de propriedade para detectar
  isso. Exigiria mudança de escopo do projeto inteiro, não uma regra
  nova.
* **Springfox (`springfox.documentation.*`)** — legado, incompatível com
  Spring Boot 3/Java 21 (o alvo declarado do projeto). Descartado por
  YAGNI; só valeria a pena se um projeto legado real em Boot 2 aparecesse
  no escopo.
