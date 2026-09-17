# spring-config-guard

[![CI](https://github.com/rgiovann/spring-config-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rgiovann/spring-config-guard/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A configuration linter for Spring Boot projects that runs **in your build**,
not after the problem has already leaked into production.

Existing Actuator/config scanning tools (e.g. pentest scanners) run from the
outside, against a URL that's already in production — by the time you find
the problem, it's already exposed. `spring-config-guard` reads
`application.yml` / `application.properties` from your own source code and
fails the build (exit code 1) before deployment.


## Usage

```bash
mvn package
java -jar target/spring-config-guard.jar <project-path> [--json] [--fail-on=HIGH|MEDIUM|LOW|NONE] [--policy=<file>]
```

* `--json` — emits the report as JSON instead of the console format.
* `--fail-on` — minimum severity that makes the process exit with an error
  code (useful for a CI gate). `NONE` never fails the build; default is
  `HIGH`.
* `--policy` — YAML file for binary suppression of findings by rule +
  profile (e.g. `SCG002: [dev]` suppresses SCG002 findings in the `dev`
  profile; `"*"` suppresses across every profile; `base` suppresses in the
  common/unnamed profile). A suppressed finding disappears from both the
  report and the exit code; the suppressed count is printed to stderr.
  Without this flag, no suppression is applied.
* `--help` / `-h` — shows the usage message (flags, examples, exit codes)
  and exits with code 0. Takes precedence over any other argument.

`demo-project/` carries deliberately misconfigured YAML fixtures and
`demo-project-clean/` carries deliberately clean fixtures — useful for
manually validating the CLI's end-to-end behavior. Two showcase
subdirectories are a good starting tour:

* `demo-project/multi-profile-showcase/` — a single multi-document
  `application.yml` (`base`/`dev`/`prod` via `spring.config.activate.on-profile`)
  triggering 6 different rules across profiles, plus a `policy-demo.yml`
  example (`java -jar spring-config-guard.jar demo-project/multi-profile-showcase
  --policy=demo-project/multi-profile-showcase/policy-demo.yml`).
* `demo-project/properties-format-showcase/` — the same kind of findings
  expressed in flat `.properties` syntax, including a relaxed-binding
  (camelCase) key and an unresolved-placeholder finding.
* `demo-project-clean/properties-format-showcase/` — the clean
  counterpart of the fixture above: same keys, correct values (secrets
  referenced via env placeholders instead of hardcoded). Reports 2 INFO
  findings and still exits 0 even under the default `--fail-on=HIGH`,
  showing that INFO alone never fails the build.

All three are pinned by `DemoProjectShowcaseTest`, so they can't silently drift
out of sync with rule behavior as rules evolve.

## Rules

17 rules, `SCG001`–`SCG017`. Each reports [`Finding`](src/main/java/dev/scg/core/Finding.java)s
at `HIGH`, `MEDIUM`, `LOW`, or `INFO` — `INFO` never fails the build on its own
([`ExitCodeResolver`](src/main/java/dev/scg/cli/ExitCodeResolver.java) excludes it).
Authoritative source:
[`META-INF/services/dev.scg.core.Rule`](src/main/resources/META-INF/services/dev.scg.core.Rule),
enforced by `RuleRegistryTest`'s exact-ID assertion — this table mirrors it and
should be updated in the same PR that adds or removes a rule.

| ID | Severity | Description |
|---|---|---|
| SCG001 | HIGH / INFO | Actuator exposed via `exposure.include=*` without restricting sensitive endpoints |
| SCG002 | HIGH | H2 console enabled (flagged regardless of profile) |
| SCG003 | HIGH / MEDIUM | CORS with global or pattern-based wildcard in `allowed-origins`/patterns combined with `allow-credentials=true` |
| SCG004 | MEDIUM / INFO | Use of an insecure protocol (`http://`) in non-loopback CORS origins |
| SCG005 | MEDIUM / LOW / INFO | Permissive CORS configuration exposing all HTTP methods or sensitive/wildcard response headers |
| SCG006 | HIGH / INFO | Hardcoded plaintext credentials or sensitive secrets in configuration files |
| SCG007 | HIGH / INFO | Embedded plaintext credentials in connection URIs or JAAS configurations |
| SCG008 | MEDIUM / INFO | Exposed Swagger/OpenAPI documentation or UI endpoints in production |
| SCG009 | MEDIUM / INFO | Verbose logging enabled via `debug`/`trace` or a `DEBUG`/`TRACE` root logger level |
| SCG010 | HIGH / MEDIUM / INFO | Verbose HTTP error responses enabled via `server.error.include-*` properties |
| SCG011 | HIGH / MEDIUM / INFO | Insecure transport, management SSL, or session cookie settings in Spring Boot embedded server configuration |
| SCG012 | HIGH / INFO | Disabled or insecure TLS transport in database/broker connection URIs |
| SCG013 | MEDIUM / INFO | Actuator health endpoint discloses component details via `management.endpoint.health.show-details` |
| SCG014 | HIGH / INFO | Kafka cluster communication uses an unencrypted transport protocol (`PLAINTEXT` or `SASL_PLAINTEXT`) |
| SCG015 | HIGH / INFO | RabbitMQ connection (host/port form) without TLS transport encryption enabled |
| SCG016 | HIGH / INFO | HashiCorp Vault connection using an unencrypted (`http`) transport scheme |
| SCG017 | HIGH / INFO | Insecure transport (HTTP) configured for OAuth2 Resource Server JWT endpoints |

## Validated against real-world code

Run against [spring-projects/spring-boot](https://github.com/spring-projects/spring-boot)'s
own source (98 `application.{yml,yaml,properties}` files across its smoke-test
and integration-test modules, `--json --fail-on=NONE`):

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 21 | — | — | 21 |
| SCG002 | 3 | — | — | 3 |
| SCG006 | 24 | — | 7 | 31 |
| SCG007 | 2 | — | — | 2 |
| SCG009 | — | 1 | — | 1 |
| SCG013 | — | 6 | — | 6 |
| SCG014 | 1 | — | — | 1 |
| SCG017 | 1 | — | — | 1 |
| **Total** | **52** | **7** | **7** | **66** |

All 66 findings resolve to files under `smoke-test/`/`integration-test/` module
directories — code that exists to exercise a Spring Boot feature under test,
never deployed. Zero findings outside those directories, across the entire
repository.

```bash
git clone https://github.com/spring-projects/spring-boot.git
java -jar target/spring-config-guard.jar spring-boot --json --fail-on=NONE
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — build/test setup, how to add a
new rule, commit and PR conventions.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
