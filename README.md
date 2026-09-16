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
java -jar target/spring-config-guard.jar <caminho-do-projeto> [--json] [--fail-on=HIGH|MEDIUM|LOW|NONE] [--policy=<arquivo>]
```

* `--json` — emite o relatório em JSON em vez do formato de console.
* `--fail-on` — severidade mínima que faz o processo sair com código de erro
  (útil para gate de CI). `NONE` nunca falha o build; por padrão, `HIGH`.
* `--policy` — arquivo YAML de supressão binária de findings por regra +
  profile (ex: `SCG002: [dev]` suprime achados da SCG002 no profile `dev`;
  `"*"` suprime em todos os profiles; `base` suprime no profile comum/sem
  nome). Um finding suprimido some do relatório e do exit code; a contagem
  de suprimidos é impressa em stderr. Sem essa flag, nenhuma supressão é
  aplicada.
* `--help` / `-h` — mostra a mensagem de uso em inglês (flags, exemplos,
  códigos de saída — mesmo idioma das mensagens de `Finding`) e sai com
  código 0. Tem precedência sobre qualquer outro argumento.

`demo-project/` traz fixtures YAML deliberadamente mal configuradas e
`demo-project-clean/` traz fixtures deliberadamente limpas — úteis para
validar manualmente o comportamento da CLI ponta a ponta.

## Contribuindo

Cada regra nova é uma classe que implementa `dev.scg.core.Rule` — veja
`ActuatorExposureRule` como referência. PRs de novas regras são bem-vindos.
