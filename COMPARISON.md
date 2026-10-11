# SCG compared with other tools

How SCG compares with the tools a Spring Boot team is most likely to
already run: CodeQL, Semgrep and SonarQube. [VALIDATION.md](VALIDATION.md)
answers whether SCG's findings are right, against Spring itself; this file
answers what SCG adds to those tools, and where they do more.

This comparison was made on **2026-10-11**. The other tools change on their
own schedule, so every statement below names the version or commit it was
checked against; a later version may behave differently.

| Tool | Version checked | How |
|---|---|---|
| SCG | v1.21.0 | Run |
| Semgrep | 1.180.0, registry rules from [semgrep-rules `9bbf021`](https://github.com/semgrep/semgrep-rules/tree/9bbf021d0acffa3095fcffd17b2bc7787eb4796d) | Run: `spring-env-benchmark/competitor-comparison-scenarios.sh` |
| CodeQL | [github/codeql `b5b8165`](https://github.com/github/codeql/tree/b5b81654b6e16786e6c5669f696d423d8764e336) | Query source read, not run |
| SonarQube | Server documentation, version 2026.3 | Documentation read, not run |

## In short

* **Spring configuration rules.** SCG has 17. Semgrep's registry has 4,
  all about Actuator exposure. CodeQL's default suites have 1, about
  Actuator exposure, for `.properties` files only. In SonarQube's
  documentation we found secret detection, and no rule about Spring
  configuration.
* **Spring's semantics.** SCG merges profiles, applies relaxed binding and
  resolves `${VAR:default}` placeholders before judging a value. The other
  tools match a file's text. On 12 Actuator cases, SCG was right in all 12;
  Semgrep's rules were right in 7, missed 2, and were noisy in 3.
* **Where the other tools do more**: they analyse the application's code,
  recognise hundreds of token formats in any file, and report into code
  scanning with file and line. CodeQL also sees the build: it stays silent
  when `spring-boot-starter-security` is a dependency. SCG doesn't read
  code or the build, and doesn't produce SARIF.

## Semgrep, measured

Each case is a directory in
[`spring-env-benchmark/competitor-comparison/cases/`](spring-env-benchmark/competitor-comparison/cases)
holding one configuration, written in a form Spring accepts. The A cases
ran Semgrep's four Spring Actuator rules
(`java/spring/security/audit/spring-actuator-*.yaml`); the S cases its
generic secret rules (`generic/secrets/`, ported from gitleaks). SCG ran
with its defaults.

| # | Configuration | Semgrep | SCG |
|---|---|---|---|
| A1 | `management.endpoints.web.exposure.include=*` | found | SCG001 HIGH |
| A2 | the same in nested YAML, `include: "*"` | found | SCG001 HIGH |
| A3 | a dotted key in YAML: `management.endpoints.web.exposure.include: "*"` | **missed** (the YAML rule matches the nested form only) | SCG001 HIGH |
| A4 | a YAML flow mapping: `exposure: { include: "*" }` | found | SCG001 HIGH |
| A5 | `management.endpoints.web.exposure.include = *` | found, plus a second finding naming `" *"` as an endpoint | SCG001 HIGH |
| A6 | `…exposure.include=${ACTUATOR_EXPOSE:*}` | a warning about an endpoint named `${ACTUATOR_EXPOSE:*}`, not "fully enabled" | SCG001 HIGH (the default is `*`) |
| A7 | a comma-separated list in YAML: `include: health,env,heapdump` | **missed** (the YAML rule matches a sequence only) | SCG001 HIGH |
| A8 | `…exposure.include=health,info` | a warning (anything but `health` counts as dangerous) | silent (neither endpoint is sensitive) |
| A9 | `include: [health, env, heapdump]` | found (`env`, `heapdump`) | SCG001 HIGH |
| A10 | `include=*` in `application.properties`, `include=health` in `application-prod.properties` | found, on the base file | SCG001 HIGH for the base only: `prod` is clean |
| A11 | `include=*` in `application-prod.properties` only | found | SCG001 HIGH `[profile: prod]` |
| A12 | `include: "*"` in an `on-profile: prod` document of `application.yml` | found, on the file | SCG001 HIGH `[profile: prod]` |
| S1 | `spring.datasource.password`, `spring.mail.password` and `app.jwt.secret` written in `application.yml` | 2 of 3: the datasource password and the JWT secret; `spring.mail.password: mailPassw0rd!` **missed** | SCG006 HIGH, all 3 |
| S2 | `spring.data.mongodb.uri=mongodb://admin:S3cretPwd@…`, a JDBC URL with `sslmode=disable` | **nothing** | SCG007 HIGH (the URI's password), SCG012 HIGH (`sslmode=disable`) |

Semgrep's rules are literal patterns over one file's text: they match the
forms they were written for, and read anything else as text (A5, A6, A8).
A10 to A12 show the difference that is left when both find the exposure:
Semgrep reports the file, SCG reports the profiles it affects.

Every Spring rule area other than Actuator was checked by searching the
whole registry, at the commit above, for the property names: there is no
rule for the H2 console, CORS, the health endpoint's details, SpringDoc,
Kafka, RabbitMQ, JDBC TLS, Vault, OAuth2 endpoints, error responses,
logging levels, or the embedded server's SSL and cookies.

## CodeQL, from its source

CodeQL has one query for Spring configuration in its default suites,
`java/spring-boot-exposed-actuators-config`
([`SpringBootActuatorsConfigQuery.qll`](https://github.com/github/codeql/blob/b5b81654b6e16786e6c5669f696d423d8764e336/java/ql/lib/semmle/code/java/security/SpringBootActuatorsConfigQuery.qll)).
It reports Actuator exposure when all of these hold:

* the property is in a `.properties` file (`JavaProperty`): **YAML is not
  read**;
* the project is built with **Maven**, with a `pom.xml` whose parent's
  group is `org.springframework.boot`: a Gradle build, or a Maven build
  that imports Spring Boot's BOM, gets no result;
* that parent's version starts with **1.x, 2.x or 3.x**: Spring Boot 4
  gets no result;
* the pom doesn't declare `spring-boot-starter-security`. **This is
  something SCG can't do**: SCG doesn't read the build, and reports the
  exposure whatever protects it.

The value is compared as written (trimmed): no profile merging, relaxed
binding or placeholder resolution. The only other query that reads
properties files, `java/credentials-in-properties`, is experimental and
its module deprecated, so it isn't in the default suites.

## SonarQube, from its documentation

SonarQube's [secrets detection](https://docs.sonarsource.com/sonarqube-server/2026.3/analyzing-source-code/languages/secrets)
recognises known secret formats (cloud keys, API tokens and similar) in
the files its analyzers read. YAML and JSON files are scanned for secrets
only when enabled (`sonar.yaml.activate`, `sonar.json.activate`), from
SonarQube Server 2025.4 ([announcement](https://community.sonarsource.com/t/sonar-now-analyzes-yaml-and-json-files-for-secrets/147141)).
We found no rule about Spring configuration in its documentation; that is
what we searched, not a proof that none exists.

## Coverage by risk

| Risk in the configuration files | SCG | CodeQL | Semgrep registry | SonarQube |
|---|---|---|---|---|
| Actuator endpoints exposed over HTTP | SCG001 | partial (above) | partial (above) | none found |
| Hardcoded passwords and secrets | SCG006 | not in the default suites | partial: generic secret rules (S1) | partial: known token formats |
| Credentials in connection URIs and JAAS | SCG007 | none | missed in S2 | none found |
| H2 console enabled | SCG002 | none | none | none found |
| CORS: wildcard with credentials, `http://` origins, open methods and headers | SCG003 to SCG005 | none | none | none found |
| Swagger/OpenAPI UI enabled | SCG008 | none | none | none found |
| Verbose logging, verbose error responses | SCG009, SCG010 | none | none | none found |
| Embedded server TLS and session cookies | SCG011 | none | none | none found |
| Database and broker connections without TLS | SCG012 | none | none | none found |
| Health endpoint showing details | SCG013 | none | none | none found |
| Kafka and RabbitMQ without TLS or host verification | SCG014, SCG015 | none | none | none found |
| Vault and OAuth2 endpoints over plain HTTP | SCG016, SCG017 | none | none | none found |

## Where the other tools do more

* **The application's code.** CodeQL, Semgrep and SonarQube analyse Java
  code: injection, CSRF disabled in a `SecurityFilterChain`, unsafe
  deserialization. SCG reads only configuration files.
* **The build.** CodeQL's query reads `pom.xml` and stays silent when it
  declares `spring-boot-starter-security`. SCG can't tell, and its README
  says so ("A finding means the configuration is a risk if nothing else
  protects it").
* **Secret formats.** Semgrep's and SonarQube's secret rules recognise
  hundreds of token formats in any file, not only in Spring property keys.
* **Reporting.** All three report findings with file and line into GitHub
  code scanning or their own dashboards, IDEs and pull requests. SCG reports
  per configuration, in console or JSON, without SARIF.

SCG covers one area in depth, what a Spring Boot application's
configuration files allow, and is meant to run alongside a code scanner,
not instead of one.

## Reproducing

```bash
pip install semgrep==1.180.0
mvn -q package -DskipTests
spring-env-benchmark/competitor-comparison-scenarios.sh
```

The script fetches semgrep-rules at the pinned commit, runs both tools on
every case, and prints each finding with its rule and file (Semgrep) or
rule, severity and profile (SCG). It was run twice, with the same result.
CodeQL and SonarQube aren't run: CodeQL needs a database built from a Java
project, and SonarQube a server.
