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
2. **(Prioridade baixa) Upload multipart sem limite** —
   `spring.servlet.multipart.max-file-size`/`max-request-size`
   ilimitado ou `-1`. Mais adjacente a DoS do que a
   confidencialidade/integridade, por isso a prioridade menor.
3. **(Prioridade baixa, deliberada) `InsecureTransportProtocolRule`** —
   `http://` em propriedades arbitrárias fora do escopo de CORS (ex:
   `jhipster.mail.base-url`, webhooks, callback URLs, `issuer-uri` de
   OAuth2/OIDC). Confirmado que hoje não há sobreposição: a SCG004
   (`CorsInsecureProtocolsRule`) só olha
   `management.endpoints.web.cors.allowed-origins`/`-origin-patterns`; a
   SCG006 (`HardcodedSecretsRule`) é sobre segredos, não protocolo. É
   um vetor de transporte diferente da SCG012 (que mira parâmetros
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
