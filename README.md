# spring-config-guard

[![CI](https://github.com/rgiovann/spring-config-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rgiovann/spring-config-guard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/rgiovann/spring-config-guard)](https://github.com/rgiovann/spring-config-guard/releases/latest)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`spring-config-guard` (SCG) is a command-line linter for the
`application.{yml,yaml,properties}` files of Spring Boot projects. It reports
security misconfigurations, such as Actuator endpoints exposed over HTTP,
hardcoded credentials, permissive CORS and connections without TLS, and
sets its exit code so a CI job can fail on them before deployment.

It is static analysis: it reads the files in your repository and never
starts or contacts the application. It doesn't depend on Spring Boot.
Instead, it reproduces the parts of Spring's configuration model that decide
what a property's value is: profile merging, relaxed binding and
`${VAR:default}` placeholders.

## See it in action

Two files, `my-app/application.yml`:

```yaml
management:
  endpoints:
    web:
      cors:
        allowed-origin-patterns: "*"
spring:
  h2:
    console:
      enabled: ${H2_CONSOLE:true}
```

and `my-app/application-prod.yml`:

```yaml
management:
  endpoints:
    web:
      cors:
        allowCredentials: true
spring:
  h2:
    console:
      enabled: false
```

```console
$ java -jar spring-config-guard.jar my-app
[HIGH] SCG003 - my-app/application-prod.yml [profile: prod]
    Insecure CORS combination detected in key 'management.endpoints.web.cors.allowed-origin-patterns': a global wildcard pattern allows credentialed requests from any host (*, https://*, etc.). This combination exposes the application to severe Cross-Site Request Forgery (CSRF) and session data leakage. Replace global wildcards with explicit origins or restricted domain patterns.

[HIGH] SCG002 - my-app/application.yml [base]
    H2 console enabled (spring.h2.console.enabled=${H2_CONSOLE:true}): a web SQL client that connects to any JDBC URL typed into its login form. It answers loopback clients only, which can include requests forwarded by a reverse proxy or sidecar on the same machine. Disable it via 'spring.h2.console.enabled=false'.

Summary: 2 violation(s) - HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0
$ echo $?
1
```

What happened:

* **SCG003 in `prod` comes from two files.** The wildcard origin is in the
  base file, and credentials are enabled only in `prod`. Neither file holds
  the risky combination alone. It exists in `prod`'s effective
  configuration, which SCG builds by merging the base with the profile, as
  Spring does.
* **`allowCredentials` is the same property as `allow-credentials`.** Spring's
  relaxed binding treats the two spellings as one key, and so does SCG.
* **SCG002 in the base comes from a placeholder default.** Unless
  `H2_CONSOLE` is set, `${H2_CONSOLE:true}` resolves to `true`.
* **No SCG002 for `prod`.** `prod` overrides the value with `false`, so its
  effective configuration is clean.

### Compared with a per-file pattern scanner

A per-file pattern scanner, such as Semgrep in `generic` mode, can find a
single risky value with a rule written for it. That includes relaxed-binding
spellings, given a case-insensitive pattern such as
`(?i)show[-_]?details\s*[:=]\s*always`. Checked with Semgrep 1.179.0, that
pattern finds `showDetails: always`.

Such a scanner matches each file on its own, and it doesn't model how Spring
builds the configuration. In the example above:

* a rule that needs both CORS keys can't match, because no single file
  contains both;
* `${H2_CONSOLE:true}` doesn't match `enabled: true` unless the rule
  resolves placeholders;
* the scanner can't tell that `prod` turns the H2 console off.

SCG's rules are written for these semantics, and each one knows Spring's
default for the properties it checks.

## Quick start

Requires Java 21 or later.

```bash
curl -fLO https://github.com/rgiovann/spring-config-guard/releases/latest/download/spring-config-guard.jar
java -jar spring-config-guard.jar path/to/your-project
```

To see it report something, clone this repository and run it on a bundled
fixture:

```bash
java -jar spring-config-guard.jar demo-project/multi-profile-showcase
```

To build from source instead, run `mvn package`. The jar is
`target/spring-config-guard.jar`.

## Usage

```text
java -jar spring-config-guard.jar <project-path> [--json] [--config-server]
    [--fail-on=HIGH|MEDIUM|LOW|NONE] [--policy=<file>]
```

`<project-path>` must be the first argument. Options come after it.

| Option | Effect |
|---|---|
| `--json` | Writes the report as JSON instead of the console format. |
| `--config-server` | Treats `<project-path>` as a Spring Cloud Config Server repository. See [Config Server Mode](#config-server-mode). |
| `--fail-on=<level>` | The lowest severity that makes SCG exit with `1`: `HIGH` (default), `MEDIUM` or `LOW`. `NONE` always exits with `0`. Case-insensitive. |
| `--policy=<file>` | Suppresses findings by rule and profile. See [Policy](#policy). |
| `--help`, `-h` | Prints usage and exits with `0`. |
| `--version` | Prints the version and exits with `0`. |

Without `--config-server`, SCG walks `<project-path>` recursively and reads
every `application*.{yml,yaml,properties}` file. It skips `src/test/` and
the build output (`target/`, `build/`) next to a `pom.xml` or
`build.gradle[.kts]`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above `--fail-on`, or `--fail-on=NONE`. `INFO` findings never count. |
| `1` | At least one finding at or above `--fail-on`. |
| `2` | Usage or input error: an unknown argument, an invalid `--fail-on` value, a path that isn't a directory, a missing or invalid policy file, or a configuration file that can't be read or parsed (invalid YAML, or a `spring.config.activate.on-profile` Spring Boot would refuse to start with, such as `'a & b \| c'`). |

The report goes to stdout. Errors and coverage warnings go to stderr: an
unfollowed `spring.config.import`, config files in more than one Spring
location, documents only several active profiles apply, and the number of
findings a policy suppressed. See
[Scope & Limitations](#scope--limitations).

## Rules

17 rules, `SCG001` to `SCG017`. A rule may report more than one severity,
depending on the evidence. The authoritative list is
[`META-INF/services/dev.scg.core.Rule`](src/main/resources/META-INF/services/dev.scg.core.Rule).

| ID | Severities | Reports |
|---|---|---|
| SCG001 | HIGH / INFO | Sensitive Actuator endpoints exposed over HTTP without restricting access |
| SCG002 | HIGH / INFO | H2 console enabled (`spring.h2.console.enabled=true`) |
| SCG003 | HIGH / MEDIUM / LOW / INFO | CORS wildcard or `null` origin combined with `allow-credentials=true` (Actuator and Spring for GraphQL) |
| SCG004 | MEDIUM / LOW / INFO | Insecure protocol (`http://`) in non-loopback CORS origins (Actuator and Spring for GraphQL) |
| SCG005 | MEDIUM / LOW / INFO | Permissive CORS exposing all HTTP methods, or sensitive or wildcard response headers (Actuator and Spring for GraphQL) |
| SCG006 | HIGH / INFO | Hardcoded plaintext credentials or secrets |
| SCG007 | HIGH / INFO | Plaintext credentials embedded in connection URIs or JAAS configurations |
| SCG008 | MEDIUM / INFO | Swagger/OpenAPI documentation or UI endpoints enabled |
| SCG009 | MEDIUM / INFO | Verbose logging that can write secrets to the log: `debug`/`trace` set to anything but `false`, or `DEBUG`/`TRACE` on the root logger or on a logger known to log secrets (`INFO` for other loggers at those levels) |
| SCG010 | MEDIUM / INFO | Verbose HTTP error responses via `server.error.include-*` (Spring Boot before 4.0) or `spring.web.error.include-*` (4.0 and later) |
| SCG011 | HIGH / MEDIUM / INFO | Insecure transport, management SSL or session cookie settings of the embedded server |
| SCG012 | HIGH / MEDIUM / INFO | Disabled or insecure TLS in database and broker connection URIs |
| SCG013 | MEDIUM / INFO | Actuator health endpoint, or a health group, showing component details via `show-details`/`show-components` (`MEDIUM` to any caller; `INFO` to authenticated users, or for component names only) |
| SCG014 | HIGH / MEDIUM / INFO | Kafka over an unencrypted protocol (`PLAINTEXT` or `SASL_PLAINTEXT`), or over TLS with the broker host name check off (a blank `ssl.endpoint.identification.algorithm`) |
| SCG015 | HIGH / MEDIUM / INFO | RabbitMQ connection (host/port form) without TLS, or with TLS that doesn't verify the broker (`ssl.verify-hostname` or `ssl.validate-server-certificate` false) |
| SCG016 | HIGH / INFO | HashiCorp Vault over `http` |
| SCG017 | HIGH / INFO | OAuth2 Resource Server fetching its JWT keys (`jwk-set-uri`, `issuer-uri` or `public-key-location`, whichever Spring Boot uses) or its token introspection (`introspection-uri`) over HTTP |

How to read a severity:

* **`HIGH`, `MEDIUM`, `LOW`**: the risky value is written in the files, or
  is Spring's default for a property the files leave unset. A finding based
  on such a default is one level lower than one based on a written value.
* **`INFO`**: static analysis can't tell whether the value is a risk. `INFO`
  is reported but never fails the build.
* The transport rules (SCG012, SCG014 to SCG017) report a connection whose
  hosts are all written as loopback addresses (`localhost`, `127.0.0.0/8`,
  `::1`) as `INFO`. Its traffic doesn't leave the host unless something
  local relays it
  ([VALIDATION.md](VALIDATION.md#loopback-addresses-in-the-transport-rules)).

A finding means the configuration is a risk **if nothing else protects
it**. SCG can't see a Spring Security filter chain, a WAF, a network
policy, or any other control in Java code or infrastructure. A finding is
not proof that the deployed application is exploitable. A clean report means
no rule matched in the files SCG read. It doesn't mean the configuration is
secure.

## How SCG evaluates configuration

* **Profiles.** For each directory, SCG reads `application.yml` with its
  `application-{profile}.yml` files, and every document's
  `spring.config.activate.on-profile` as Spring does: a list of profile
  expressions (`!api-docs`, `a | b`, `a,b`). It evaluates the base, where
  Spring's `default` profile is active, and each profile any file name,
  expression or `spring.profiles.group` names, with the profiles its group
  activates. Each configuration applies, in Spring's order, every
  document whose conditions match: `.properties` over `.yml` over
  `.yaml`, profile-specific files over the rest, a later document in a
  file over an earlier one. Rules run on every resulting configuration and
  don't depend on the profile's name: a finding in a profile called `dev`
  is still reported. To accept a risk in a given profile, use a
  [Policy](#policy).
* **Relaxed binding.** `show-details`, `showDetails` and `show_details` are
  the same key, as in Spring. So is a bracketed map key
  (`spring.kafka.properties[security.protocol]`) and its dotted form.
* **Placeholders.** A `${VAR:default}` placeholder resolves to its default,
  recursively. A placeholder without a default can't be known at lint time.
  Rules treat it as a possible risk instead of assuming it is safe. For
  example, SCG006 reports a credential that depends on an unresolved
  placeholder as `INFO`.

The merge semantics are checked against the `Environment` of a running
Spring Boot app ([VALIDATION.md](VALIDATION.md)).

## Output Format

Both formats carry the same five fields: `ruleId`, `severity`, `message`,
`sourceFile` and `profileLabel`. Findings are sorted the same way on every
run, so the output of the same input is identical and can be diffed.

### Console output (default)

```text
[HIGH] SCG002 - my-app/application.yml [base]
    H2 console enabled (spring.h2.console.enabled=${H2_CONSOLE:true}): ...

Summary: 2 violation(s) - HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0
```

Each finding has a header, `[severity] ruleId - sourceFile [profile]`, and
the message on the next line. `[base]` is the configuration with no active
profile. `[profile: <name>]` is a named profile, spelled as in the file
name or in `on-profile`. The summary counts every finding, `INFO`
included. With no findings, the output is
`spring-config-guard: no violations found.`

### JSON output (`--json`)

```json
[ {
  "ruleId" : "SCG003",
  "severity" : "HIGH",
  "message" : "Insecure CORS combination detected in key ...",
  "sourceFile" : "my-app/application-prod.yml",
  "profileLabel" : "prod"
}, {
  "ruleId" : "SCG002",
  "severity" : "HIGH",
  "message" : "H2 console enabled (spring.h2.console.enabled=${H2_CONSOLE:true}): ...",
  "sourceFile" : "my-app/application.yml",
  "profileLabel" : "__spring_config_guard_base__"
} ]
```

The output is an array, `[ ]` when there are no findings. For the
configuration with no active profile, `profileLabel` is the sentinel
`__spring_config_guard_base__`, not `base`. A Spring profile can
legitimately be named `base`, and the sentinel keeps the two apart.

### What `sourceFile` points to

`sourceFile` is the file of the *configuration* that was evaluated: the
base's file, the profile's file or, in Config Server Mode, the service's
file. Its path starts with the `<project-path>` given on the command line.
When a
configuration is assembled from several files, a property from one of the
others is reported against that configuration's file. In the example
above, the SCG003 finding names `application-prod.yml`, but the wildcard
origin is written in `application.yml`. Other cases:

* With `application.yml` and `application.properties` in the same
  directory, base findings name `application.properties`, the file with
  higher precedence.
* A profile defined both by `application-prod.yml` and by an
  `on-profile: prod` document in `application.yml` is reported against
  `application-prod.yml`. In general, a profile's findings name the last
  file, in Spring's order, with a document for that profile; the base's,
  the last file applied to it (`application-default.yml`, when there is
  one).
* In Config Server Mode, a property from the Global `application.yml` is
  reported against the service's file.

If the reported file doesn't contain the property, look in the files that
configuration inherits from.

## Policy

`--policy=<file>` suppresses findings by rule and profile. It doesn't change
what rules detect: it accepts a known risk after the scan. A suppressed
finding is left out of the report and of the exit code, and SCG prints the
count to stderr (`spring-config-guard: N finding(s) suppressed by policy.`).

The file maps each rule ID to the profiles in which to suppress it:

```yaml
# policy.yml
SCG002:
  - dev          # the H2 console is expected locally

SCG012:
  - dev
  - qa           # test brokers run without TLS on purpose

SCG006:
  - base         # the configuration with no active profile

SCG008:
  - "*"          # every profile
```

* Profile names are case-sensitive, as in Spring, and must match the name
  shown in `[profile: <name>]`.
* `base` (case-insensitive) means the configuration with no active profile.
  As a result, a real profile named `base` can't be targeted by name; only
  `"*"` reaches it (see [Other known limitations](#other-known-limitations)).
* An unknown rule ID, an empty file, or a rule with an empty profile list is
  an error (exit code `2`), so a typo can't silently suppress nothing.

[`demo-project/multi-profile-showcase/policy-demo.yml`](demo-project/multi-profile-showcase/policy-demo.yml)
is a working example.

## Config Server Mode

A [Spring Cloud Config Server](https://docs.spring.io/spring-cloud-config/docs/current/reference/html/)
repository names its files after each client service (`customers-service.yml`),
not `application*`. The regular discovery would skip those files.
`--config-server` reads that layout instead:

```text
config-repo/
├── application.yml          # Global: shared by every service
├── customers-service.yml    # one service
└── vets-service.yml         # another service
```

* `application*.{yml,yaml,properties}` directly in the directory is the
  **Global** configuration.
* Every other `.yml`, `.yaml` or `.properties` file directly in the directory
  is one **service**, named after the file.
* A service's profiles come from the Global `application-{profile}`
  files and from the `spring.config.activate.on-profile` documents in the
  Global files or in that service's own files. Each configuration applies
  the documents that match, in this order, lowest to highest precedence:

  ```text
  Global application.*  <  the service's files  <  Global application-{profile}.*
  ```

  Every document of a file counts, its `on-profile` blocks included, so a
  service's base overrides a Global `on-profile` block.

* `sourceFile` is always the service's file.

Not read, by design:

* **Subdirectories.** The mode isn't recursive: a Config Server repository is
  usually one flat directory, and recursing would read unrelated YAML (CI
  workflows, `docker-compose.yml`) as Spring configuration.
* **`{service}-{profile}.yml` files**, e.g. `customers-service-mysql.yml`.
  Service names often contain hyphens, so the file name can't be split
  reliably into service and profile.

[`demo-project/config-server-showcase/`](demo-project/config-server-showcase/)
is a working example:

```bash
java -jar spring-config-guard.jar demo-project/config-server-showcase --config-server
```

## CI/CD Integration

A GitHub Actions workflow that fails on `HIGH` findings:

```yaml
# .github/workflows/spring-config-guard.yml
name: spring-config-guard
on: [push, pull_request]

jobs:
  config-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-java@v6
        with:
          distribution: temurin
          java-version: '21'
      - name: Lint Spring Boot configuration
        run: |
          curl -fLO https://github.com/rgiovann/spring-config-guard/releases/download/v1.18.0/spring-config-guard.jar
          java -jar spring-config-guard.jar . --fail-on=HIGH
```

* **Pin a version** instead of `releases/latest`. A release can add or
  remove findings, which can fail a build that didn't change, or let
  through one that should fail. Upgrade on purpose, after reading the
  release's **Detection changes** section
  ([CHANGELOG.md](CHANGELOG.md)).
* **Other CI systems** work the same way: SCG needs Java 21 and a shell
  step, and reports through its exit code.

## Scope & Limitations

SCG reads only `application.{yml,yaml,properties}` files. It doesn't depend
on Spring Boot and doesn't run the application. Within that boundary, "the
effective configuration" means the base or **one** active profile, per
directory or, in [Config Server Mode](#config-server-mode), per service. The cases below are outside it.
They aren't false negatives of a rule.

* **Runtime values.** Real environment variables, JVM system properties and
  command-line arguments exist only when the application starts. A
  placeholder resolves to its default, and one without a default is treated
  as a possible risk (see
  [How SCG evaluates configuration](#how-scg-evaluates-configuration)).
* **Several profiles active together** (e.g. `dev,cloud`). Each profile is
  evaluated on its own, with the profiles its `spring.profiles.group`
  activates
  ([ADR-013](ARCHITECTURE.md#adr-013-profile-groups-evaluated-with-the-profile-that-activates-them)).
  Any other combination of two profiles that set the same key isn't
  computed, and `spring.profiles.include` isn't read. A document only a
  combination activates
  (`on-profile: 'a & b'`, or an `on-profile` inside `application-x.yml`
  naming another profile) is applied to no configuration, and SCG prints:
  `spring-config-guard: N document(s) apply only when several profiles are active together, which is not evaluated.`
  See [ADR-012](ARCHITECTURE.md#adr-012-on-profile-evaluated-as-spring-boot-does-one-ordered-fold-per-set-of-active-profiles).
* **`spring.config.import`** isn't followed. When a scanned file uses it,
  SCG prints to stderr:
  `spring-config-guard: N file(s) import external configuration via spring.config.import that was not scanned.`
  See [ADR-004](ARCHITECTURE.md#adr-004-springconfigimport-surfaced-as-a-coverage-warning-not-followed).
* **Several Spring config locations.** Spring merges `classpath:/`,
  `classpath:/config/`, `file:./` and `file:./config/` into one
  `Environment`. SCG evaluates each directory independently, because guessing which
  directories belong to one application could fuse unrelated modules of a
  monorepo. When one module has config files in more than one of
  `src/main/resources`, `src/main/resources/config` and `config/`, SCG
  prints:
  `spring-config-guard: N application(s) have config files in more than one Spring config location, evaluated independently -- a risk split across locations can be missed, and a finding can be one that a setting in another location already turns off.`
  See [ADR-005](ARCHITECTURE.md#adr-005-multiple-spring-config-locations-surfaced-as-a-coverage-warning-not-merged).
* **Other file names.** A project started with
  `spring.config.name=myapp` uses `myapp.yml`, which SCG doesn't recognize.
  It scans clean without a warning.
* **Java code.** Security configured in Java, such as a
  `SecurityFilterChain`, CSRF settings or a `CorsConfigurationSource` bean,
  isn't visible.

### Other known limitations

* **Test sources and build output aren't scanned.** `src/test/` and the
  `target/` or `build/` directory of a Maven or Gradle project don't ship
  with the application. Build output also holds copies of
  `src/main/resources`, which would duplicate every finding. Passing one of
  these directories directly as `<project-path>` still scans it. See
  [ADR-006](ARCHITECTURE.md#adr-006-test-source-sets-and-build-output-excluded-from-the-scan).
* **A profile literally named `base` can't be targeted by name in a
  policy**, because `base` is the alias for the configuration with no
  active profile. Only `"*"` reaches it. This is a deliberate decision:
  changing the alias would break existing policies. The report itself tells
  the two apart: `[base]` and `__spring_config_guard_base__` versus
  `[profile: base]` and `"base"`.

## Troubleshooting

* **"no violations found" on a project you expected findings in.** Check
  that the files are named `application*.{yml,yaml,properties}` and aren't
  under `src/test/` or the build output. For a Config Server repository,
  add `--config-server`.
* **`Usage error: Unknown argument: ...`.** The project path must come
  before the options.
* **`UnsupportedClassVersionError`.** The JVM is older than Java 21.
* **A finding names a file that doesn't contain the property.** See
  [What `sourceFile` points to](#what-sourcefile-points-to).
* **A warning on stderr but no finding.** Coverage warnings report what SCG
  couldn't evaluate. See [Scope & Limitations](#scope--limitations).

## Demo fixtures

`demo-project/` holds deliberately misconfigured fixtures, and
`demo-project-clean/` holds deliberately clean ones. Their findings are
pinned by `DemoProjectShowcaseTest` and `ConfigServerShowcaseTest`.

| Fixture | Shows |
|---|---|
| `demo-project/multi-profile-showcase/` | One multi-document `application.yml` (base, `dev`, `prod`) with findings from six rules, plus `policy-demo.yml` |
| `demo-project/properties-format-showcase/` | The same kind of findings in `.properties` syntax, with a camelCase key and an unresolved placeholder |
| `demo-project-clean/properties-format-showcase/` | Its clean counterpart: 2 `INFO` findings and exit code `0` under the default `--fail-on=HIGH` |
| `demo-project/config-import-showcase/` | The `spring.config.import` warning next to a regular finding |
| `demo-project/config-location-showcase/` | A CORS risk split across two config locations: a clean report and the multi-location warning |
| `demo-project/config-server-showcase/` | Config Server Mode: a Global file and two services, one with its own profile |

## Validation

[VALIDATION.md](VALIDATION.md) holds the evidence behind what SCG reports:
public repositories scanned at pinned commits, each rule's scenarios
measured against a running Spring Boot app or client, and how to reproduce
each one.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build and test setup, adding a
rule, commit and PR conventions, and releases. Planned and discarded work is
in [BACKLOG.md](BACKLOG.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
