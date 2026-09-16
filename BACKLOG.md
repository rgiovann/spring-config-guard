# Backlog

Este arquivo é o estado planejado do projeto: o que está em andamento e as
próximas regras candidatas, em ordem de prioridade. Não é um contrato — é
esperado que itens sejam descobertos, descartados, divididos, combinados ou
repriorizados conforme o projeto avança.

A lista de regras já implementadas é
`src/main/resources/META-INF/services/dev.scg.core.Rule`, com os IDs
validados por `RuleRegistryTest`. Este arquivo não a duplica.

## Próximas regras candidatas

Ordem por relação esforço/valor, não por dependência técnica. Levantados
na sessão 2026-09-15 ao mapear a superfície de propriedades de segurança
do Spring Boot/Security/Cloud ainda não coberta pelas 16 regras
existentes (ver `src/main/resources/META-INF/services/dev.scg.core.Rule`
pra lista atual).

1. **Transporte inseguro em OAuth2 Resource Server JWT
   (`spring.security.oauth2.resourceserver.jwt.issuer-uri` /
   `.jwk-set-uri`)** — regra dedicada (motivou a remoção da
   `InsecureTransportProtocolRule` genérica do backlog, ver "Descartado /
   fora de escopo"). Qualquer uma das duas propriedades em HTTP permite a
   um atacante na rede servir uma JWKS forjada e a aplicação aceitar
   tokens assinados por ele — bypass de autenticação, não só vazamento de
   dado. As duas propriedades são alternativas pro mesmo propósito (JWKS
   direto vs. descoberta OIDC via issuer), então a regra deve cobrir
   ambas, não só `issuer-uri`.
2. **Algoritmo JWT fraco/inadequado no OAuth2 Resource Server
   (`spring.security.oauth2.resourceserver.jwt.jws-algorithms`)** —
   mesma família de hardening do item 1, mas mecanismo diferente:
   confirmado que a propriedade existe de verdade (Spring Security 5.2+,
   consumida pelo `NimbusJwtDecoder` quando `jwk-set-uri`/`issuer-uri`
   está configurado). Vetor real e histórico — *algorithm confusion*: se
   a lista inclui um algoritmo simétrico (`HS256`/`HS384`/`HS512`) num
   cenário onde o JWKS serve chaves assimétricas (RSA/EC), um atacante
   pode assinar um token usando a chave pública (conhecida) como
   "segredo" HMAC, forjando autenticação. Sugerido originalmente pelo
   Gemini num brainstorm externo sem visibilidade do projeto — avaliado
   e filtrado nesta sessão (2026-09-15): dos 5 itens que ele propôs, 2
   eram duplicatas de regras já implementadas (Actuator wildcard = SCG001,
   H2 console = SCG002), 1 já estava descartado no backlog com razão
   documentada (CSRF — sem superfície de propriedade), 1 era factualmente
   incorreto (desserialização polimórfica do Jackson não é controlável
   via `spring.jackson.*` — o vetor real de RCE, `default typing`, não é
   uma propriedade bindável do Spring Boot), e este foi o único que se
   sustentou. Falta confirmar antes do design: o que o `NimbusJwtDecoder`
   aceita quando a propriedade não é setada (default real), e se o
   literal `none` é sequer um valor que o binding aceita.
3. **(Prioridade mais baixa — ressalva de ruído) Transporte inseguro em
   AWS S3 / SQS / SNS / DynamoDB / RDS / SES
   (`spring.cloud.aws.s3.endpoint`, `.sqs.endpoint`, `.sns.endpoint`,
   `.dynamodb.endpoint`, `.rds.endpoint`, `.ses.endpoint`)** — mesmo
   mecanismo de baixo custo do endpoint global/Secrets Manager/Parameter
   Store (já implementado, ver nota abaixo), mas carrega dado de negócio
   (payload de fila/objeto/item de tabela), não segredo de bootstrap —
   por isso prioridade menor, não descartado. Ressalva de ruído mais
   forte que qualquer chave já na SCG012 (inclusive as recém-
   implementadas): o uso mais comum dessas propriedades na prática **é
   LocalStack** (`http://localhost:4566`) pra teste local — ainda mais
   universal que "JDBC em localhost". Como a SCG012 deliberadamente não
   tem exceção de loopback (decisão já tomada e travada pela suíte de
   testes), essa família provavelmente seria a que mais gera finding
   esperado/intencional em configs de dev/teste entre todas as chaves do
   `uri-based`. Não é motivo pra não adicionar — a Policy layer (ver
   "Débito técnico" abaixo) é a resposta arquitetural certa pra esse
   ruído — mas é a maior faca de dois gumes já candidatada. **Antes de
   implementar:** a propriedade de e-mail divergiu entre as duas fontes
   consultadas — apareceu como `spring.cloud.aws.ses.endpoint` numa
   busca e `spring.cloud.aws.mail.endpoint` na outra (o módulo de envio
   de e-mail do Spring Cloud AWS pode nomear o prefixo pela capacidade
   "mail", não pela sigla AWS "ses") — e `rds.endpoint` só foi
   confirmado numa única fonte, confiança mais baixa que as demais desta
   lista. Confirmar todas as 6 grafias contra o `*Properties.java` fonte
   de cada módulo antes de escrever o YAML (mesmo cuidado que já rendeu
   uma correção real no item do endpoint global/Secrets Manager/
   Parameter Store — `parameterstore` não `paramstore` — antes dele ser
   implementado).
4. **(Prioridade a avaliar — ressalva de ruído) Redis sem senha
   (`spring.data.redis.host`/`spring.redis.host` não-loopback presente,
   sem `spring.data.redis.password`)** — Redis aberto sem autenticação é
   um vetor real e documentado (inclusive campanhas de ransomware via
   Redis exposto publicamente). Mas é um design "ausência = inseguro"
   como Kafka/RabbitMQ (SCG014/SCG015), e Redis é comumente protegido só
   por isolamento de rede (containers, VPC), não por senha de aplicação
   — mesmo tipo de ruído que já levou Eureka/Consul/Zipkin/OTEL pra
   "Pós-1.0" abaixo. Não é auto-evidente que o custo/benefício feche;
   fica registrado pra avaliação, não como decisão tomada.

Saíram dessa lista, implementadas com esforço mínimo direto na SCG012
(chave nova em `uri-based` no `SCG012.yml`, `http://` já cadastrado em
`risky-schemes` — sem exceção de loopback, mesma decisão de design já
validada pelas outras chaves da lista e travada pela suíte de testes
existente da SCG012):

* Spring Cloud Config Server (`spring.cloud.config.uri` em HTTP).
* AWS Secrets Manager / Parameter Store / endpoint global
  (`spring.cloud.aws.endpoint`, `.secretsmanager.endpoint`,
  `.parameterstore.endpoint` em HTTP) — grafia de `parameterstore`
  confirmada contra uma issue real do repositório
  `awspring/spring-cloud-aws` antes de escrever a chave (não é
  `paramstore`, prefixo antigo do Spring Cloud AWS 2.x; também não deve
  ser confundida com `spring.cloud.config.server.awsparamstore.endpoint`,
  propriedade de um componente diferente — o backend AWS Parameter
  Store do Spring Cloud Config Server).

Com SCG016 (Vault), a família "transporte inseguro" original (JDBC/
Mongo/Redis/RabbitMQ/ActiveMQ/LDAP/Kafka/Vault) está fechada pra v1.0
(SCG011/SCG012/SCG014/SCG015/SCG016 já implementadas); o item de
issuer-uri/jwk-set-uri e o item de AWS S3/SQS/SNS/DynamoDB/RDS/SES acima
são propriedades novas descobertas depois desse fechamento, não uma
reabertura dele — o item de algoritmo JWT fraco não é sequer da família
"transporte", é um mecanismo de assinatura diferente. Novos candidatos
de descoberta/observabilidade entram na seção "Pós-1.0" abaixo por
padrão, não aqui, a menos que passem no critério de triagem descrito lá.

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

### SCG001: cobertura incompleta de endpoints sensíveis do Actuator

Não é uma regra nova — é uma lacuna real na `ActuatorExposureRule`
existente, achada na sessão 2026-09-15 ao ler `check()` com cuidado
(não só a Javadoc/descrição).

1. **Caminho de inclusão explícita não é verificado:** o finding de
   "endpoint sensível ainda irrestrito" (`stillEnabled`) só roda dentro
   do `if (hasWildcardExposure)`. Se `exposure.include` lista endpoints
   explicitamente sem `*` (ex: `exposure.include=threaddump,beans`), a
   regra fica totalmente silenciosa — mesmo com `threaddump`/`beans`
   tendo `access=unrestricted` por padrão (ao contrário de
   `heapdump`/`shutdown`), então já ficam de fato alcançáveis sem
   nenhuma configuração adicional.
2. **`SENSITIVE_ENDPOINTS` está desatualizado frente à superfície real
   do Actuator:** hoje é `{env, heapdump, threaddump, shutdown,
   configprops, beans}`. Revisado na sessão 2026-09-16 (segunda opinião
   externa — Gemini — corrigiu duas imprecisões da nota original; ambas
   verificadas contra fonte antes de aceitar, não tomadas de graça):
   * **`restart`/`refresh`** — não são endpoints nativos do
     `spring-boot-actuator`, são do **Spring Cloud Context**
     (`org.springframework.cloud.context.restart.RestartEndpoint`,
     `org.springframework.cloud.endpoint.RefreshEndpoint`, confirmado
     via source no repositório `spring-cloud/spring-cloud-commons`).
     Isso não os desqualifica pro escopo deste projeto — SCG016 (Vault),
     a extensão do SCG012 pro Config Server e AWS Secrets Manager/
     Parameter Store já tratam `spring.cloud.*` como escopo válido — mas
     a nota original os descrevia incorretamente como se fossem Actuator
     core; corrigido aqui. **Defaults confirmados contra o source
     (sessão 2026-09-16):** `RestartEndpoint` é
     `@Endpoint(id="restart", enableByDefault=false)` — desabilitado por
     padrão, igual `shutdown`/`heapdump` — entra em
     `RESTRICTED_BY_DEFAULT`, não só em `SENSITIVE_ENDPOINTS`.
     `RefreshEndpoint` é `@Endpoint(id="refresh")` sem override — ou
     seja, habilitado por padrão — entra em `SENSITIVE_ENDPOINTS` puro,
     mesma categoria de `threaddump`/`beans`/`env`/`configprops`.
   * **`jolokia`** — **removido da lista de candidatos.** Confirmado que
     o Spring Boot 3 parou de incluir auto-configuração do Jolokia
     ("Spring Boot 3 removed support for Jolokia in the sense that it no
     longer included auto-configuration for Jolokia"). O projeto declara
     Java 21/Spring Boot 3 como alvo (CLAUDE.md) — incluir `jolokia`
     seria ruído morto pro público real da ferramenta, não um gap.
   * **`loggers`/`sessions`** — Actuator core, ambos confirmados contra
     o source (`LoggersEndpoint`/`SessionsEndpoint`, sessão 2026-09-16):
     `@Endpoint(id="loggers")` e `@Endpoint(id="sessions")`, nenhum dos
     dois com `enableByDefault` — habilitados por padrão, mesma
     categoria de `SENSITIVE_ENDPOINTS` puro que `refresh`. O ponto do
     Gemini sobre `loggers` ser "frequentemente exposto de propósito"
     não é uma questão de pesquisa, é uma calibração de severidade —
     recomendação (não fato verificado): não abrir exceção, mesmo
     raciocínio Zero-Trust já usado pelo resto da SCG001 ("a config base
     deve declarar só endpoints seguros, independente de contexto");
     `sessions` inclusive expõe sessão de usuário real e tem operação
     `DELETE` capaz de derrubar sessão alheia — se algo, mais sensível
     que `loggers`, não menos.
   **Pronto pra implementar:** `restart` (com `RESTRICTED_BY_DEFAULT`),
   `refresh`, `loggers`, `sessions` (os três últimos em
   `SENSITIVE_ENDPOINTS` puro) — `jolokia` fora da lista.

## Pós-1.0 (catalogado, não descartado)

Diferente da seção "Descartado" abaixo: os itens aqui são tecnicamente
viáveis, mas adiados deliberadamente pra depois da v1.0 por uma razão
específica (não por falta de ideia) — registrados pra não serem
re-propostos do zero.

**Critério de triagem** (sessão 2026-09-14, ao avaliar candidatos de
transporte inseguro em ferramentas de microsserviços além de
Kafka/RabbitMQ/Vault): a propriedade carrega credencial ou payload de
dados real (entra na lista de regras candidatas acima), ou é só endereço
de descoberta/observabilidade (fica aqui)? O segundo grupo tem alto risco
de ruído pelo mesmo motivo já documentado em "Descartado / fora de escopo"
abaixo pra `InsecureTransportProtocolRule`: esses componentes são classicamente
implantados intra-cluster/intra-mesh (Docker network, namespace do k8s,
sidecar Istio/Linkerd cuidando do TLS), então `http://` ali é
frequentemente uma configuração legítima, não uma falha real — o tipo de
falso positivo que mina confiança logo nas primeiras execuções.

* **Service Discovery inseguro (Eureka/Consul —
  `eureka.client.service-url.defaultZone`,
  `spring.cloud.consul.discovery.scheme`)** — o endereço aponta pro
  *registry*, não prova por si só que o tráfego inter-serviço real é
  inseguro. Agravante: o default do Consul
  (`spring.cloud.consul.discovery.scheme`) já é `http`, então a maioria
  dos projetos Consul dispararia isso sem estar genuinamente exposta.
* **Exportação de telemetria insegura (Zipkin/OTEL —
  `management.zipkin.tracing.endpoint`,
  `management.otlp.metrics.export.url`)** — coletor de tracing/métricas
  quase sempre roda como sidecar ou dentro do mesmo cluster privado;
  severidade também mais baixa (MEDIUM, não HIGH) por não carregar
  credencial de aplicação, só metadado de requisição/trace.

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
* **Transporte inseguro em SMTP/Mail
  (`spring.mail.properties.mail.smtp.starttls.enable` /
  `mail.smtp.ssl.enable`)** — descartado por custo/benefício (sessão
  2026-09-15): o design é confirmadamente mais caro que RabbitMQ/Vault
  (SCG015/SCG016) — duas condições alternativas de segurança (STARTTLS na
  porta 587 *ou* SSL implícito na porta 465, não um único enum/boolean) e
  chave aninhada no mapa genérico `spring.mail.properties.*` — sem
  confirmação de que o time realmente usa SMTP cru (vs. serviço de e-mail
  transacional via API) para justificar esse esforço. Deixado pra um
  contribuidor externo com um caso de uso específico que precise dela,
  não descartado por ser tecnicamente inviável.
* **Upload multipart sem limite
  (`spring.servlet.multipart.max-file-size`/`max-request-size`)** —
  descartado (sessão 2026-09-15): Spring Boot já tem padrões seguros
  nativos (defaults não-ilimitados), e o limite de payload de upload
  costuma ser travado na camada de borda (gateway/load balancer), não na
  aplicação — o que essa regra detectaria é mais adjacente a DoS do que
  ao escopo de confidencialidade/integridade que o projeto prioriza, e a
  superfície de risco real já é coberta fora da aplicação na maioria dos
  ambientes de produção.
* **`InsecureTransportProtocolRule`** (scanner genérico de `http://` em
  propriedades arbitrárias) — descartado por princípio de design (sessão
  2026-09-15), não só por custo/ruído: quando uma propriedade genérica
  específica tem impacto de segurança desastroso em HTTP (ex.:
  `spring.security.oauth2.resourceserver.jwt.issuer-uri`, que expõe a
  aplicação a falsificação de token JWT se o endpoint JWKS for buscado
  sem TLS), o design correto é uma regra dedicada e restrita a essa
  chave — não um scanner genérico de `http://` que varre toda
  `EffectiveConfig`. Uma regra dedicada consegue expressar o *porquê* do
  risco na mensagem do finding e calibrar severidade pelo dano real da
  chave específica; o scanner genérico não distingue uma
  `jhipster.mail.base-url` de baixo risco de um `issuer-uri` que permite
  bypass de autenticação via token forjado — mesma classe de raciocínio que já levou a
  manter Kafka (SCG014) e Vault (SCG016) como regras dedicadas em vez de
  entradas genéricas no SCG012.
