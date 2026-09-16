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

Item 1 desta lista (transporte inseguro em OAuth2 Resource Server JWT)
foi implementado nesta sessão como SCG017
(`JwtResourceServerInsecureTransportRule`). Item 2 (algoritmo JWT
fraco/inadequado) foi descartado após verificação contra o código-fonte
real — ver "Descartado / fora de escopo" abaixo. O antigo item 3 (AWS
S3/SQS/SNS/DynamoDB/RDS/SES) foi implementado nesta mesma sessão direto
na SCG012 — ver nota abaixo. O antigo item 4 (Redis sem senha) foi
descartado (mesma seção) após reavaliação. **Lista vazia** — nenhuma
regra candidata pendente no momento (sessão 2026-09-16).

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
* AWS S3 / SQS / SNS / DynamoDB / SES (`spring.cloud.aws.s3.endpoint`,
  `.sqs.endpoint`, `.sns.endpoint`, `.dynamodb.endpoint`, `.ses.endpoint`
  em HTTP) — sessão 2026-09-16. As 5 grafias confirmadas contra o
  `*Properties.java` de cada módulo no repositório
  `awspring/spring-cloud-aws` (todas estendem a base comum
  `AwsClientProperties`, que declara o campo `endpoint`, sob o prefixo
  próprio de cada módulo). `rds.endpoint` descartado da lista original:
  não existe — busca por `RdsProperties`/`"rds"` no diretório
  `autoconfigure` do repositório não retornou nenhum resultado; acesso a
  RDS passa pelo `spring.datasource.url` (JDBC) já coberto acima, não por
  um endpoint override dedicado. `spring.cloud.aws.ses.endpoint` também
  confirmado (não `.mail.endpoint`, hipótese de uma das duas fontes
  originais). Diferente das duas entradas anteriores, essas 5 chaves
  carregam dado de negócio (payload de fila/tópico/item de
  tabela/objeto/e-mail de saída), não segredo de bootstrap — mesmo CWE-319
  em HTTP, classe de impacto diferente. Adicionadas mesmo sabendo que o
  uso mais comum na prática é apontar pra LocalStack em dev/teste: é o
  mesmo trade-off de ruído já aceito pras duas entradas acima (nenhuma
  delas tem exceção de loopback), não um caso novo que justificasse
  adiar pra depois da Policy layer — a Policy layer já está deliberadamente
  atrás do fechamento desta lista (ver "Débito técnico" abaixo), então
  bloquear uma regra esperando a outra criaria uma dependência circular.

Com SCG016 (Vault), a família "transporte inseguro" original (JDBC/
Mongo/Redis/RabbitMQ/ActiveMQ/LDAP/Kafka/Vault) está fechada pra v1.0
(SCG011/SCG012/SCG014/SCG015/SCG016 já implementadas); o item de
issuer-uri/jwk-set-uri (SCG017) e o item de AWS S3/SQS/SNS/DynamoDB/SES
acima são propriedades novas descobertas depois desse fechamento, não
uma reabertura dele — o item de algoritmo JWT fraco não é sequer da
família "transporte", é um mecanismo de assinatura diferente. Novos candidatos
de descoberta/observabilidade entram na seção "Pós-1.0" abaixo por
padrão, não aqui, a menos que passem no critério de triagem descrito lá.

## Débito técnico e features de plataforma

### Camada de Policy: supressão binária de findings por regra + profile — implementada (sessão 2026-09-16)

Implementada como `dev.scg.policy.Policy` (`load`/`none`/`apply`), fechando
a lista de regras candidatas conforme decisão registrada acima. Design
final bate com o confirmado abaixo, com dois refinamentos definidos
durante a implementação:

* **Wildcard de profile (`"*"`)**: suprime uma regra em qualquer profile
  sem precisar listar cada um. Não fere a granularidade por regra — só
  afeta a regra em que foi declarado.
* **Transparência da supressão**: `Main` imprime
  `"N finding(s) suppressed by policy"` em `System.err` quando
  `suppressedCount > 0` — contagem apenas, sem conteúdo, sem tocar no
  contrato de `Reporter` (nem `ConsoleReporter` nem `JsonReporter` sabem
  que a Policy existe, decisão original preservada; a impressão acontece
  em `Main`, comparando `allFindings.size()` antes e depois do filtro).

Arquivo de política é input do usuário (boundary real, diferente de
`rules-metadata/*.yml`, que é interno ao projeto): `Policy.load()` falha
rápido com mensagem clara pra YAML malformado, arquivo vazio, valor que
não é uma lista, ou `ruleId` desconhecido (typo) — nunca um
`ClassCastException` cru ou uma supressão que silenciosamente não
funciona. Alias `"base"` resolve pro sentinel
`ProfileMerger.BASE_PROFILE_LABEL`, mesmo rótulo humano que
`Finding.toString()` já usa.

Integração via nova flag `--policy=<path>` (`CliOptions`/
`CliArgumentParser`), opcional — ausente é `Policy.none()`, comportamento
idêntico ao anterior à Policy existir.

**Motivação original** (por que a Policy existe em vez de embutir a
supressão nas regras): as regras do projeto são — e devem continuar
sendo — agnósticas a profile: recebem uma `EffectiveConfig`, avaliam,
emitem `Finding` com severidade fixa definida pela própria regra, sem
embutir política de "profile X merece menos rigor" (ver
[[feedback_zero_trust_no_profile_exemption]]). Decisões desse tipo (ex:
"aceitamos segredo hardcoded em dev") pertencem a cada time analisado,
não à ferramenta — por isso saem da regra e viram uma camada separada,
pós-avaliação.

**Design confirmado antes da implementação** (mantido como registro):

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

### SCG001: cobertura incompleta de endpoints sensíveis do Actuator — resolvido (sessão 2026-09-16)

Lacuna achada em 2026-09-15 na `ActuatorExposureRule` existente (não uma
regra nova), fechada em três commits: (1) `check()` agora avalia
reachability via `isEndpointReachable()` independente de wildcard — uma
lista explícita como `exposure.include=threaddump,beans` já dispara o
finding, não só `include=*`; (2) `loggers` e `restart` adicionados a
`SENSITIVE_ENDPOINTS` (`restart` também em `RESTRICTED_BY_DEFAULT`,
default `enableByDefault=false` confirmado no source do
`RestartEndpoint`); (3) Javadoc da classe atualizada pra refletir o
comportamento corrigido.

Decisão final divergiu do plano intermediário registrado antes da
implementação: `refresh` e `sessions` foram deliberadamente **excluídos**
(não implementados), apesar de ambos estarem habilitados por padrão no
próprio source — motivo é que os dois são auto-configurados
condicionalmente a um bean/dependência opcional que esta ferramenta não
enxerga (`spring-cloud-context` pro `refresh`;
`FindByIndexNameSessionRepository` do Spring Session indexado pro
`sessions`), então marcá-los sem essa distinção arriscaria recomendar
restringir um endpoint que não existe de fato na maioria das apps reais —
raciocínio completo documentado no Javadoc da própria
`ActuatorExposureRule`. `jolokia` continua fora (sem auto-configuração no
Spring Boot 3+). 694 testes passando, sem pendência.

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

* **Redis sem senha (`spring.data.redis.host`/`spring.redis.host`
  não-loopback presente, sem `spring.data.redis.password`)** —
  descartado (sessão 2026-09-16), reclassificado de "avaliação pendente"
  pra descarte estrutural, não por ruído/prioridade. Motivo: ao contrário
  da SCG014 (Kafka), onde ausência de `security.protocol` no cliente
  *determina* o protocolo de fio usado (decisão inteiramente client-side,
  garantida pela biblioteca — daí "ausência = PLAINTEXT" ser um sinal
  confiável), a ausência de `spring.data.redis.password` no cliente não
  diz nada sobre se o servidor Redis exige autenticação: `requirepass` é
  uma decisão inteiramente server-side, invisível a um linter estático de
  `application.yml`. Se o Redis real exige senha e a app não configura
  uma, a conexão falha (`NOAUTH Authentication required`) — já quebraria
  em qualquer teste funcional básico, não precisa de lint estático. Se o
  Redis não exige senha (isolamento de rede legítimo *ou* exposição
  acidental), a config visível é idêntica nos dois casos — sem como
  distinguir estaticamente. Diferente de Eureka/Zipkin/OTEL (seção
  "Pós-1.0": sinal real, só que de baixo risco/prioridade), aqui o sinal
  em si não se correlaciona com o risco real — mesma classe de motivo que
  já descartou CSRF (sem superfície de propriedade confiável), não um
  "talvez mais tarde".
* **Algoritmo JWT fraco/inadequado no OAuth2 Resource Server
  (`spring.security.oauth2.resourceserver.jwt.jws-algorithms`)** —
  descartado por premissa factualmente incorreta (sessão 2026-09-16),
  confirmado contra o código-fonte real do Spring Boot/Security (não só
  documentação): `JwtDecoderConfiguration`/`ReactiveJwtDecoderConfiguration`
  convertem cada string configurada via
  `org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.from(String)`,
  cujo enum só tem 9 membros — `RS256/384/512`, `ES256/384/512`,
  `PS256/384/512` — nenhum algoritmo simétrico (`HS256`/`HS384`/`HS512`)
  existe nesse enum, e `from()` retorna `null` pra qualquer nome não
  reconhecido, o que a própria configuração transforma em
  `InvalidConfigurationPropertyValueException` — falha no startup da
  aplicação, não uma configuração aceita silenciosamente. O vetor de
  *algorithm confusion* que motivou o item (HS256 aceito ao lado de um
  JWKS assimétrico) não é exprimível através dessa propriedade: o
  binding do próprio Spring Boot já rejeita o valor antes da app subir.
  Adicionalmente, o caminho via `issuer-uri`
  (`supplyJwtDecoderByIssuerUri()`) nem consome `jws-algorithms` — a
  propriedade só é aplicada no caminho `jwk-set-uri`/chave pública. Mesma
  classe de erro já filtrada no brainstorm original do item (Jackson
  default typing): uma sugestão de segurança plausível na superfície, mas
  que não sobrevive à leitura do código-fonte real da propriedade.
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
