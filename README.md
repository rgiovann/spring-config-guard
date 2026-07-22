# spring-config-guard

Um linter de configuração para projetos Spring Boot que roda **no seu build**,
não depois que o problema já vazou pra produção.

Ferramentas existentes de verificação de Actuator/config (ex: scanners de
pentest) rodam de fora, contra uma URL já em produção — quando você descobre
o problema, ele já está exposto. `spring-config-guard` lê `application.yml` /
`application.properties` do seu próprio código-fonte e falha o build (exit
code 1) antes do deploy.

## Uso

```bash
mvn package
java -jar target/spring-config-guard.jar caminho/do/seu/projeto
```

## Regras implementadas

| ID     | O que verifica |
|--------|-----------------|
| SCG001 | `management.endpoints.web.exposure.include=*` sem endpoints sensíveis (env, heapdump, threaddump, shutdown, configprops, beans) explicitamente desabilitados |

## Roadmap (próximas regras)

- [ ] SCG002 — `spring.h2.console.enabled=true` fora do profile `dev`/`test`
- [ ] SCG003 — segredos em texto plano (`password:`, `secret:`, `token:`) sem referência a variável de ambiente
- [ ] SCG004 — CORS liberado (`allowed-origins: "*"`) combinado com `allow-credentials: true`
- [ ] Integração como plugin Maven (goal `verify`) e Gradle task
- [ ] GitHub Action pronta pra plugar em qualquer repo

## Por que zero dependências na v0.1

O parser YAML em `ConfigLoader` é escrito à mão — suporta o que 90% das
configs Spring realmente usam (mapeamentos aninhados por indentação), mas
não suporta listas YAML nem âncoras. Isso é uma limitação documentada, não
um bug escondido. Ver comentário em `ConfigLoader.loadYaml` para trocar por
`snakeyaml` se precisar de suporte completo.

## Contribuindo

Cada regra nova é uma classe que implementa `dev.scg.core.Rule` — veja
`ActuatorExposureRule` como referência. PRs de novas regras são bem-vindos.
