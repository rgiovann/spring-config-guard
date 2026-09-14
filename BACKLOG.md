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

1. **Transporte inseguro no RabbitMQ (`spring.rabbitmq.ssl.enabled`)** —
   mesma forma de evidência já usada em SCG012/SCG014: mensageria com
   payload real trafegando sem TLS. Padrão AMQP mais usado no Spring ao
   lado do Kafka. A confirmar antes de especificar: o default de
   `spring.rabbitmq.ssl.enabled` (suspeita é `false`, o que replicaria o
   design "ausência = inseguro" já resolvido na SCG014 — gatilho por
   evidência de uso via `spring.rabbitmq.host`/`spring.rabbitmq.addresses`,
   não por valor explícito). Complementar, não redundante, ao mecanismo
   `risky-schemes` já implementado na SCG012 (sessão 2026-09-14): aquele
   só pega a forma explícita `amqp://`/`amqps://` em `addresses`; a forma
   mais comum (`host:port` puro, sem scheme) fica sem sinal de TLS
   nenhum ali — é exatamente essa lacuna que esta regra nova fecha.
2. **Transporte inseguro no Vault (`spring.cloud.vault.uri` /
   `spring.cloud.vault.scheme`)** — Vault é gerenciador de segredos: se o
   transporte é inseguro, as credenciais que a própria aplicação carrega
   no bootstrap trafegam em claro — mesma classe de severidade de
   SCG007/SCG012, mais grave que um simples endereço de descoberta (ver
   seção "Pós-1.0" abaixo pro porquê isso importa na triagem). A
   confirmar: o default de `spring.cloud.vault.scheme` (suspeita é
   `https`, o que tornaria essa regra mais simples que a SCG014 — sem
   precisar do design "ausência = inseguro").
3. **(Prioridade a avaliar) Transporte inseguro em SMTP/Mail
   (`spring.mail.properties.mail.smtp.starttls.enable` /
   `mail.smtp.ssl.enable`)** — descoberto na mesma sessão 2026-09-14 ao
   avaliar LDAP/Elasticsearch. Carrega credencial real (SMTP AUTH) e
   payload de e-mail, mesma classe de valor de SCG007/SCG012 — mas o
   design é mais caro que RabbitMQ/Vault: duas condições alternativas de
   segurança (STARTTLS na porta 587 *ou* SSL implícito na porta 465, não
   um único enum/boolean), e a chave vive aninhada dentro do mapa
   genérico `spring.mail.properties.*` (mesmo padrão pass-through da
   SCG014 pro Kafka), não como propriedade tipada direta. Prioridade
   depende de quão comum é SMTP direto (vs. serviço de e-mail
   transacional via API) nas aplicações reais do time — o próprio
   backlog já cita `jhipster.mail.base-url` como exemplo no item abaixo,
   o que sugere que configuração de mail *é* comum no contexto do time,
   mas isso não confirma que seja especificamente via SMTP cru.
4. **(Prioridade baixa) Upload multipart sem limite** —
   `spring.servlet.multipart.max-file-size`/`max-request-size`
   ilimitado ou `-1`. Mais adjacente a DoS do que a
   confidencialidade/integridade, por isso a prioridade menor.
5. **(Prioridade baixa, deliberada) `InsecureTransportProtocolRule`** —
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

Com RabbitMQ e Vault, a família "transporte inseguro" fica fechada pra
v1.0 (junto com SCG011/SCG012/SCG014 já implementadas) — novos candidatos
da mesma família entram na seção "Pós-1.0" abaixo por padrão, não aqui,
a menos que passem no critério de triagem descrito lá.

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
de ruído pelo mesmo motivo já documentado no item 5 acima
(`InsecureTransportProtocolRule`): esses componentes são classicamente
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
