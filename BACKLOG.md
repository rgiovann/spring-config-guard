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
2. **Transporte inseguro no Kafka (`spring.kafka.security.protocol`)** —
   descoberto revisando o escopo da SCG012 (sessão 2026-09-11): Kafka
   ficou fora dela de propósito, não por esquecimento — ver
   [ADR-001](ARCHITECTURE.md#adr-001-decoupling-uri-property-catalogs-between-security-rules-scg007-vs-scg012)
   pro contexto da decisão de catálogo de URIs, e a discussão da mesma
   sessão sobre por que Kafka não se encaixa na forma de evidência da
   SCG012. `spring.kafka.bootstrap-servers` não é uma URI com query
   string (é só `host1:porta1,host2:porta2`) — forçá-la no `uri-based`
   da SCG012 seria uma entrada morta que nunca dispara, dando falsa
   sensação de cobertura. O sinal real é outra propriedade: valores
   conhecidos de `security.protocol` são `PLAINTEXT`, `SSL`,
   `SASL_PLAINTEXT`, `SASL_SSL` — `PLAINTEXT` é sem TLS/sem auth;
   `SASL_PLAINTEXT` tem autenticação SASL mas o transporte continua em
   texto claro, então credenciais e dados ainda vazam na rede. Mesma
   forma de evidência da SCG001/SCG002/SCG009 (comparar valor de
   propriedade contra um enum conhecido), não da SCG012 (parsing de
   query param em URI) — regra nova, não extensão.
   Decisão pendente: `Rule` simples ou `ConfigurableRule`? Os valores do
   enum são fatos fixos do protocolo Kafka, não algo específico de
   organização, o que sugeriria `Rule` simples (mesmo raciocínio da
   SCG009/SCG011) — mas vale reavaliar quando for especificar de
   verdade.
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

### Matching de valores de enum não replica o binding lenient real do Spring Boot (SCG001, SCG010)

Descoberto durante revisão da SCG013 (sessão 2026-09-14): `ActuatorExposureRule`
(`RISKY_SHOW_VALUES`, [ActuatorExposureRule.java:71](src/main/java/dev/scg/rules/ActuatorExposureRule.java:71))
e `VerboseErrorResponseRule` (`RISKY_ENUM_VALUES`,
[VerboseErrorResponseRule.java:63](src/main/java/dev/scg/rules/VerboseErrorResponseRule.java:63))
comparam o valor resolvido contra um `Set` fixo de variantes de separador
(`WHEN_AUTHORIZED`, `WHEN-AUTHORIZED`, `ON_PARAM`, `ON-PARAM`, ...) via
`value.toUpperCase(Locale.ROOT)`.

Isso não corresponde ao binding real do Spring Boot. Confirmado contra o
algoritmo de `LenientObjectToEnumConverterFactory.getCanonicalName()`
(`org.springframework.boot.convert`, spring-boot-project/spring-boot): tanto o
valor recebido quanto a constante do enum são reduzidos a "somente
letras/dígitos, minúsculo" antes da comparação — ou seja, `when-authorized`,
`when_authorized`, `whenAuthorized` e `WHENAUTHORIZED` são todos equivalentes
para o Spring, independente de separador ou posição de maiúscula. Um `Set` de
variantes escritas à mão nunca cobre todas as formas; especificamente,
`whenAuthorized`/`onParam` (camelCase, sem separador) escapam do
`toUpperCase()` + `Set` atual e geram falso negativo (`WHENAUTHORIZED` !=
nenhuma entrada do `Set`, que só tem as formas com `_`/`-`).

A correção já está implementada como modelo em SCG013
([HealthDetailsExposureRule.canonicalize()](src/main/java/dev/scg/rules/HealthDetailsExposureRule.java:124)):
reduzir o valor a letras/dígitos minúsculos e comparar contra um `Set` de
formas já canônicas, em vez de enumerar separadores manualmente.

Adiado deliberadamente: SCG013 ainda não está madura (implementada nesta
mesma sessão), e mexer em SCG001/SCG010 agora desviaria o foco antes de
confirmar se a SCG013 em si está estável — e revisar SCG013 pode revelar mais
problemas do mesmo tipo que ainda afetariam esse retrofit. Aplicar o mesmo
padrão de `canonicalize()` às duas regras existentes quando o foco puder
migrar para elas, sem mudar severidade ou qualquer outro comportamento —
escopo é puramente a forma de comparação do valor.

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
