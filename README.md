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

## Contribuindo

Cada regra nova é uma classe que implementa `dev.scg.core.Rule` — veja
`ActuatorExposureRule` como referência. PRs de novas regras são bem-vindos.
