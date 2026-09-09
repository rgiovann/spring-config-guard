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
java -jar target/spring-config-guard.jar <caminho-do-projeto> [--json] [--fail-on=HIGH|MEDIUM|LOW|NONE]
```

* `--json` — emite o relatório em JSON em vez do formato de console.
* `--fail-on` — severidade mínima que faz o processo sair com código de erro
  (útil para gate de CI). `NONE` nunca falha o build; por padrão, `HIGH`.

`demo-project/` traz fixtures YAML deliberadamente mal configuradas e
`demo-project-clean/` traz fixtures deliberadamente limpas — úteis para
validar manualmente o comportamento da CLI ponta a ponta.

## Contribuindo

Cada regra nova é uma classe que implementa `dev.scg.core.Rule` — veja
`ActuatorExposureRule` como referência. PRs de novas regras são bem-vindos.
