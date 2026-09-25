# spring-config-guard

[![CI](https://github.com/rgiovann/spring-config-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rgiovann/spring-config-guard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/rgiovann/spring-config-guard)](https://github.com/rgiovann/spring-config-guard/releases/latest)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A configuration linter for Spring Boot projects that runs **in your build**,
not after the problem has already leaked into production — catching things
like exposed Actuator endpoints, hardcoded credentials, insecure TLS
transport, and permissive CORS before they ship. Built for Spring Boot teams
that want this enforced automatically as a CI gate, not as a manual review
step.

Existing Actuator/config scanning tools (e.g. pentest scanners) run from the
outside, against a URL that's already in production — by the time you find
the problem, it's already exposed. `spring-config-guard` reads
`application.yml` / `application.properties` from your own source code and
fails the build (exit code 1) before deployment. The next section shows
exactly what that looks like, including a real, reproducible case where a
generic YAML/IaC scanner (Checkov, Semgrep) misses something SCG catches.

## See it in action

```yaml
# application.yml
spring:
  h2:
    console:
      enabled: true
---
spring.config.activate.on-profile: prod
spring:
  h2:
    console:
      enabled: false
```

```bash
java -jar spring-config-guard.jar my-project --json --fail-on=NONE
```

```json
[
  {
    "ruleId": "SCG002",
    "severity": "HIGH",
    "message": "H2 console enabled (spring.h2.console.enabled=true). High risk of remote code execution (RCE) and data exposure. Disable it via 'spring.h2.console.enabled=false' outside local environments.",
    "sourceFile": "application.yml",
    "profileLabel": "__spring_config_guard_base__"
  }
]
```

One finding, not two. The base config is genuinely insecure (H2 console
open to anyone who can reach the app), but `prod`'s effective configuration
explicitly overrides it to `false` — SCG computes that merge
([`ProfileMerger`](src/main/java/dev/scg/core/ProfileMerger.java)) first,
then runs its rules against the result, so the safe override in `prod`
correctly produces *no* finding while the insecure base does. This is the
actual output of running the two commands above against the YAML shown, not
a hypothetical (see [Scope & Limitations](#scope--limitations) for exactly
what "effective configuration" covers).

### Why not a generic YAML/IaC scanner (Checkov, Semgrep)?

A tool that pattern-matches one file at a time can catch a value like the
one above, but two things break it in practice — demonstrated below, not
just asserted:

**1. Relaxed binding.** Spring treats `show-details`, `showDetails`, and
`show_details` as the same property
([`RelaxedProperties`](src/main/java/dev/scg/core/RelaxedProperties.java)).
Given `application.yml` (base) with
`management.endpoint.health.showDetails: always` and
`application-prod.yml` with only `server.port: 8080` (no mention of health
at all):

```bash
semgrep --config show-details.semgrep.yml application.yml application-prod.yml
# -> Ran 1 rule on 2 files: 0 findings.
# (the rule's pattern-regex targets the canonical spelling: 'show-details:\s*(always|ALWAYS)')

java -jar spring-config-guard.jar . --json --fail-on=NONE
# -> 2 findings: SCG013 (MEDIUM) on application.yml AND on application-prod.yml
```

**2. Cross-file inheritance.** `application-prod.yml` in that same run never
mentions `health` or `show-details` — there is nothing in that file for a
per-file scanner to match — yet SCG still reports a finding for it, with
`profileLabel: "prod"`, because that property is genuinely part of `prod`'s
effective configuration once merged with the base. A scanner that evaluates
each file in isolation has no way to know that.

Checkov doesn't offer a comparable way to even attempt this: its
custom-check framework is scoped to specific IaC resource types (Terraform,
CloudFormation, Kubernetes, Dockerfile, ...; run `checkov --help` and check
the `--framework` list), not arbitrary YAML key paths the way Semgrep's
`generic` language mode allows — so this comparison is written against
Semgrep, where an equivalent ad hoc rule is actually possible to write.

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
| SCG008 | MEDIUM / INFO | Exposed Swagger/OpenAPI documentation or UI endpoints |
| SCG009 | MEDIUM / INFO | Verbose logging enabled via `debug`/`trace` or a `DEBUG`/`TRACE` root logger level |
| SCG010 | HIGH / MEDIUM / INFO | Verbose HTTP error responses enabled via `server.error.include-*` (Spring Boot 3.x) or `spring.web.error.include-*` (4.0) properties |
| SCG011 | HIGH / MEDIUM / INFO | Insecure transport, management SSL, or session cookie settings in Spring Boot embedded server configuration |
| SCG012 | HIGH / INFO | Disabled or insecure TLS transport in database/broker connection URIs |
| SCG013 | MEDIUM / INFO | Actuator health endpoint discloses component details via `management.endpoint.health.show-details` |
| SCG014 | HIGH / INFO | Kafka cluster communication uses an unencrypted transport protocol (`PLAINTEXT` or `SASL_PLAINTEXT`) |
| SCG015 | HIGH / INFO | RabbitMQ connection (host/port form) without TLS transport encryption enabled |
| SCG016 | HIGH / INFO | HashiCorp Vault connection using an unencrypted (`http`) transport scheme |
| SCG017 | HIGH / INFO | Insecure transport (HTTP) configured for OAuth2 Resource Server JWT endpoints |

## Scope & Limitations

"Effective configuration" here means: the base document merged with one
named profile document, per `application.yml`/`application-{profile}.yml`
pair ([`ProfileMerger`](src/main/java/dev/scg/core/ProfileMerger.java)), or,
in [Config Server Mode](#config-server-mode), the 4-layer
Global-base/Global-profile/Service-base/Service-profile cascade. That is the
full extent of what "effective configuration" means in this project. Four
mechanisms Spring Boot's own `Environment` resolves at runtime are
deliberately outside that scope, for different reasons:

* **Real environment variable values, JVM system properties, and CLI
  arguments.** These only exist once the application actually starts — a
  static analyzer that never runs the app cannot know them, by definition,
  not by an implementation gap. A `${VAR:default}` placeholder resolves
  statically to its default when one is given
  ([`EnvironmentPlaceholder`](src/main/java/dev/scg/core/EnvironmentPlaceholder.java));
  without a default, the property is treated as unknowable and rules flag it
  rather than silently assuming it's safe.
* **Multiple simultaneously active profiles** (e.g. `dev,cloud` both
  active at once). Each named profile is evaluated today as its own
  independent overlay on the base — SCG does not compute the combined
  effective configuration of two or more profiles applied together, which
  can differ from either profile alone if they override the same key.
  Tracked for a later release, not v1.0.
* **`spring.config.import`.** A file that imports another file/location
  through this property is not followed — the imported content stays
  invisible to every rule. What SCG does instead: it prints an
  always-visible coverage warning to stderr
  (`spring-config-guard: N file(s) import external configuration via
  spring.config.import that was not scanned.`,
  [`ConfigImportCoverage`](src/main/java/dev/scg/core/ConfigImportCoverage.java)),
  deliberately kept separate from per-rule findings so it can't get lost
  among unrelated INFO findings — the incompleteness is surfaced, not
  resolved. Actually resolving the import graph is a deliberately larger
  scope change (it includes import locations, like
  `spring.config.import=configserver:`, that are only resolvable by
  contacting a running server over the network — not statically, at any
  effort level) and is not planned; see
  [ADR-004](ARCHITECTURE.md#adr-004-springconfigimport-surfaced-as-a-coverage-warning-not-followed)
  for the full reasoning.
* **Merging across Spring config locations.** Spring merges
  `classpath:/`, `classpath:/config/`, `file:./` and `file:./config/` into
  one `Environment`; SCG evaluates each directory independently, so a risky
  combination split across two locations (e.g. `allowed-origins: "*"` in
  `src/main/resources/application.yml` and `allow-credentials: true` in
  `config/application-prod.yml`) produces no finding. Guessing which
  directories belong to the same application risks silently fusing unrelated
  modules of a monorepo, so SCG doesn't merge them. What it does instead:
  when one module has config files in more than one of
  `src/main/resources`, `src/main/resources/config` and `config/`, it
  prints a coverage warning to stderr
  (`spring-config-guard: N application(s) have config files in more than
  one Spring config location, evaluated independently -- risks split across
  locations are not detected.`,
  [`ConfigLocationCoverage`](src/main/java/dev/scg/core/ConfigLocationCoverage.java)),
  the same way it surfaces an unfollowed `spring.config.import`. See
  [ADR-005](ARCHITECTURE.md#adr-005-multiple-spring-config-locations-surfaced-as-a-coverage-warning-not-merged).

None of this is a defect to report as a false negative against SCG's
existing rules — it's the boundary of what a tool that only parses
`application.{yml,yaml,properties}` files, with no Spring Boot dependency
and no running application, can determine.

That boundary also shapes how to read a `Finding`'s severity: it reflects
the risk of the configuration property itself, on the assumption that no
unverified runtime mitigation is in place — SCG has no visibility into a
Spring Security filter chain, a WAF, a network policy, or any other
Java-code or infrastructure-level control that might restrict access in
practice. A `HIGH` finding means "this property is a genuine anti-pattern
if nothing else is protecting it," not "this was confirmed exploitable in
your specific deployment." The same reasoning applies from the other
direction to a clean report: treat it as "no violation found in what SCG
reads," not as "this configuration is safe under every possible runtime
override."

### Other known limitations

* **Test source sets and build output are not scanned.** The recursive walk
  skips `src/test/` and a `target/` or `build/` directory next to a
  `pom.xml`/`build.gradle`/`build.gradle.kts`: none of them ship with the
  application. Build output holds copies of `src/main/resources` — scanning
  them would duplicate every finding and, after a stale build or Maven
  resource filtering, evaluate content that differs from the versioned
  source. Test config (an H2 console on, a fixed test password) is expected
  there, and a [Policy](#policy) can't silence it without also silencing the
  same rule for the main config, because suppression is per rule and
  profile, not per directory. Passing one of these directories directly as
  `<project-path>` still scans it. See
  [ADR-006](ARCHITECTURE.md#adr-006-test-source-sets-and-build-output-excluded-from-the-scan).
* **A Spring profile literally named `base` can't be targeted by name in a
  [Policy](#policy) file.** `base` in a policy is an alias for the "no
  active profile" configuration, so a real profile with that exact name
  can only be suppressed through `"*"`, which suppresses the rule in every
  profile. Decided not to change: freeing the word `base` would break every
  existing policy that uses the alias, to serve a profile name that is
  valid in Spring but rare in practice. The report itself is unaffected —
  it tells the two apart (`[base]` vs. `[profile: base]`, see
  [Multi-profile example](#multi-profile-example-including-a-profile-literally-named-base)).

## Usage

Download the latest release jar and run it directly — no build step required:

```bash
curl -LO https://github.com/rgiovann/spring-config-guard/releases/latest/download/spring-config-guard.jar
java -jar spring-config-guard.jar <project-path> [--json] [--config-server] [--fail-on=HIGH|MEDIUM|LOW|NONE] [--policy=<file>]
```

Or build it from source:

```bash
mvn package
java -jar target/spring-config-guard.jar <project-path> [--json] [--config-server] [--fail-on=HIGH|MEDIUM|LOW|NONE] [--policy=<file>]
```

* `--json` — emits the report as JSON instead of the console format.
* `--config-server` — treats `<project-path>` as a Spring Cloud Config
  Server repository instead of a single Spring Boot project. See
  [Config Server Mode](#config-server-mode) below. Without this flag, SCG
  analyzes `<project-path>` the regular way (one or more
  `application*.{yml,yaml,properties}` files, recursively, skipping
  `src/test/` and build output — see
  [Other known limitations](#other-known-limitations)).
* `--fail-on` — minimum severity that makes the process exit with an error
  code (useful for a CI gate). `NONE` never fails the build; default is
  `HIGH`.
* `--policy` — YAML file for binary suppression of findings by rule +
  profile. See [Policy](#policy) below for the file schema and examples.
  Without this flag, no suppression is applied.
* `--help` / `-h` — shows the usage message (flags, examples, exit codes)
  and exits with code 0. Takes precedence over any other argument.
* `--version` — prints the version (`spring-config-guard 1.3.0`) and exits
  with code 0, ignoring other arguments except `--help`, which wins.

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
* `demo-project/config-import-showcase/` — a `spring.config.import` that
  SCG doesn't follow, alongside a normal SCG002 finding, showing the
  coverage warning
  (`spring-config-guard: N file(s) import external configuration via
  spring.config.import that was not scanned.`) on stderr next to a regular
  scan — identically in console and `--json` format.
* `demo-project/config-location-showcase/` — `allowed-origins: "*"` in
  `src/main/resources/application.yml` and `allow-credentials: true` in
  `config/application-prod.yml`: Spring would resolve `prod` to the SCG003
  combination, but each directory is evaluated on its own, so the report is
  clean and the multi-location coverage warning on stderr is what surfaces
  the gap — identically in console and `--json` format.

All five are pinned by `DemoProjectShowcaseTest`, so they can't silently drift
out of sync with rule behavior as rules evolve.

`demo-project/config-server-showcase/` is the equivalent tour for
[Config Server Mode](#config-server-mode) — run it with
`java -jar spring-config-guard.jar demo-project/config-server-showcase --config-server --fail-on=NONE`.
Pinned by `ConfigServerShowcaseTest`.

## CI/CD Integration

A minimal GitHub Actions job that downloads the jar and fails the build on
`HIGH` findings:

```yaml
# .github/workflows/scg.yml
- name: Security config lint (spring-config-guard)
  run: |
    curl -LO https://github.com/rgiovann/spring-config-guard/releases/download/v1.3.0/spring-config-guard.jar
    java -jar spring-config-guard.jar . --fail-on=HIGH
```

Pin a version in CI rather than using `releases/latest`: a new release can
add or remove findings (new detection, fixed false positives), which could
fail — or silently relax — your gate on a build that didn't change. Upgrade
on purpose, after reading the release's "Detection changes" section (see
[Releases](CONTRIBUTING.md#releases)).

Any CI system that can run a JVM and a shell step works the same way —
GitHub Actions is just the example above.

## Output Format

Both report formats carry the same five
[`Finding`](src/main/java/dev/scg/core/Finding.java) fields — `ruleId`,
`severity`, `message`, `sourceFile`, `profileLabel` — they only differ in how
`profileLabel` is rendered.

**What `sourceFile` means.** It identifies the *configuration* that was
evaluated, not necessarily the file where the offending property is
written. Each effective configuration carries one file: the base's own
file, the profile's own file, or, in Config Server Mode, the service's
file. When that configuration was assembled from several files, a property
defined in one of the others is still reported against it:

* A property inherited from the base shows up in a profile's finding with
  that profile's file (H2 enabled in `application.yml` is reported for
  `prod` against `application-prod.yml`).
* With `application.yml` and `application.properties` in the same
  directory, base findings name `application.properties`, the
  highest-precedence file, even for a property defined in `application.yml`.
* A profile defined by both `application-prod.yml` and an `on-profile: prod`
  block in `application.yml` is reported against `application-prod.yml`.
* In Config Server Mode, a property coming from the Global `application.yml`
  is reported against the service's file.

Detection is unaffected — the finding is real either way. When the reported
file doesn't contain the property, look in the files that configuration
inherits from or was merged with.

### Console output (default)

A short header line per finding, followed by the message on its own
indented line, with a blank line between findings so long messages don't
visually run into the next one:

```
[HIGH] SCG002 - application.yml [profile: dev]
    H2 console enabled (spring.h2.console.enabled=true). High risk of remote code execution (RCE) and data exposure. Disable it via 'spring.h2.console.enabled=false' outside local environments.
```

Format: `[severity] ruleId - sourceFile [profileDisplay]` header, then the
message indented on the next line.

* `profileDisplay` is `base` for the configuration that applies with no
  active profile (the common section every profile inherits from — no
  Spring profile actually named `base` needs to exist for this to show up),
  or `profile: <name>` for a named profile, using the exact name from
  `spring.config.activate.on-profile` (or the `application-<name>.yml`
  filename).

Followed by a summary line:

```
Summary: 3 violation(s) - HIGH: 3, MEDIUM: 0, LOW: 0, INFO: 0
```

### JSON output (`--json`)

Each finding is serialized as-is from the `Finding` record, with no
human-friendly substitution:

```json
[
  {
    "ruleId": "SCG001",
    "severity": "HIGH",
    "message": "...",
    "sourceFile": "application.yml",
    "profileLabel": "__spring_config_guard_base__"
  }
]
```

`profileLabel` here is SCG's internal value, not the console's display
string:

* for a named profile, it's the profile name exactly as declared
  (`"dev"`, `"prod"`, ...).
* for the "no active profile" configuration, it's the internal sentinel
  `"__spring_config_guard_base__"`
  ([`ProfileMerger.BASE_PROFILE_LABEL`](src/main/java/dev/scg/core/ProfileMerger.java)) —
  not the word `"base"`. This is intentional: JSON output is meant for
  machine consumption (CI pipelines, other tooling re-parsing the report),
  and using `"base"` there would be ambiguous with an actual Spring profile
  literally named `base` (syntactically valid, if unusual). The sentinel
  keeps `profileLabel` unambiguous and round-trips through
  serialize/deserialize regardless of what profiles the scanned project
  defines.

### Multi-profile example, including a profile literally named `base`

```yaml
management.endpoints.web.exposure.include: "*"
---
spring.config.activate.on-profile: dev
management.endpoints.web.exposure.include: health
spring.h2.console.enabled: true
---
spring.config.activate.on-profile: base
management.endpoints.web.exposure.include: health
spring.h2.console.enabled: true
```

This one file produces three effective configurations: the unnamed base
(only `exposure.include: "*"` applies), `dev` (overrides the wildcard,
enables H2), and a profile that happens to be literally named `base` (same
override, same H2). Console output tells the sentinel-backed "no active
profile" case apart from the real `base` profile purely through the
`profile:` prefix:

```
[HIGH] SCG001 - application.yml [base]
    management.endpoints.web.exposure.include contains '*' and exposes all endpoints via HTTP ...

[HIGH] SCG002 - application.yml [profile: base]
    H2 console enabled (spring.h2.console.enabled=true). ...

[HIGH] SCG002 - application.yml [profile: dev]
    H2 console enabled (spring.h2.console.enabled=true). ...
```

The equivalent `--json` output makes the same distinction through the raw
`profileLabel` value instead of a prefix:

```json
[
  {
    "ruleId": "SCG001",
    "severity": "HIGH",
    "message": "management.endpoints.web.exposure.include contains '*' and exposes all endpoints via HTTP ...",
    "sourceFile": "application.yml",
    "profileLabel": "__spring_config_guard_base__"
  },
  {
    "ruleId": "SCG002",
    "severity": "HIGH",
    "message": "H2 console enabled (spring.h2.console.enabled=true). ...",
    "sourceFile": "application.yml",
    "profileLabel": "base"
  },
  {
    "ruleId": "SCG002",
    "severity": "HIGH",
    "message": "H2 console enabled (spring.h2.console.enabled=true). ...",
    "sourceFile": "application.yml",
    "profileLabel": "dev"
  }
]
```

Note `"profileLabel": "__spring_config_guard_base__"` (the sentinel, unnamed
base) versus `"profileLabel": "base"` (the real profile that happens to
share the word "base") — two distinct strings. Using `"base"` for both is
exactly the collision the sentinel exists to avoid.

## Policy

`--policy=<file>` suppresses findings by rule ID + profile, without
changing what a rule detects — rules stay profile-agnostic by design (no
rule decides *whether* to fire based on the profile), so suppression is
strictly a separate, explicit risk-acceptance layer on top. A suppressed
finding disappears from both the report and the exit-code calculation;
SCG prints the suppressed count to stderr
(`spring-config-guard: N finding(s) suppressed by policy.`), so it's never
silent. Without `--policy`, no suppression is applied at all.

The file is a YAML map: each key is a rule ID, each value a list of
profiles to suppress that rule in.

```yaml
# policy.yml
SCG002:
  - dev          # H2 console is expected to be open locally

SCG012:
  - dev
  - qa           # test brokers in dev/qa run without TLS on purpose

SCG006:
  - base         # one specific base-config finding, accepted as-is
```

* A real profile name (`dev`, `qa`, `prod`, ...) must match exactly what
  shows up in the report's `[profile: <name>]` — matched case-sensitively,
  the same way Spring itself treats profile names.
* `base` (case-insensitive) is a tool-provided alias for the "no active
  profile" configuration, the same human-facing label the console report
  already uses for it — you never need to know or write the internal
  sentinel (`__spring_config_guard_base__`). **Known limitation:** if the
  scanned project has a real Spring profile *literally* named `base`
  (syntactically valid, though unusual — see the "Multi-profile example"
  above), writing `base` in a policy always resolves to the sentinel, never
  to that real profile — there is currently no way to suppress a rule for
  that specific real profile by name; `"*"` (below) is the only suppression
  that also reaches it, at the cost of suppressing every profile at once.
  This is a deliberate decision, not a pending one — see
  [Other known limitations](#other-known-limitations).
* `"*"` suppresses a rule across every profile at once, instead of listing
  each one:

```yaml
# accept SCG008 (Swagger/OpenAPI exposure) project-wide
SCG008:
  - "*"
```

* An unknown rule ID, an empty file, or a rule mapped to an empty list of
  profiles all fail fast with a specific error instead of silently
  suppressing nothing — a typo in a rule ID is caught immediately rather
  than looking like it worked.

[`demo-project/multi-profile-showcase/policy-demo.yml`](demo-project/multi-profile-showcase/policy-demo.yml)
is a working example you can point `--policy` at directly.

## Config Server Mode

`--config-server` scans a [Spring Cloud Config Server](https://docs.spring.io/spring-cloud-config/docs/current/reference/html/)
backing repository instead of a single Spring Boot project's own
`src/main/resources`. Without this flag, a repository shaped like this — files
named after each client service (`spring.application.name`), not
`application*` — mostly goes unanalyzed: SCG's regular file discovery only
recognizes `application*.{yml,yaml,properties}`, so every per-service file
would be silently skipped.

**Quick reference — what's read, what isn't** (reasoning and full precedence
rules below):

| Reads | Does not read |
|---|---|
| `application*.{yml,yaml,properties}` directly in the given directory, as the shared Global config | The same directory's subdirectories — **not recursive** |
| Every other `.yml`/`.yaml`/`.properties` file directly in that directory, as one service each | A **`{service}-{profile}.yml`** file per service+profile (e.g. `customers-service-mysql.yml`) — not a supported naming convention |
| Profiles declared via `spring.config.activate.on-profile` inside the Global file or that service's own file | A service's profile expressed any other way |

```text
config-repo/
├── application.yml          # Global — shared by every service
├── customers-service.yml    # one service
├── api-gateway.yml          # another service
└── vets-service.yml         # another service
```

`application*` is the **Global** config, shared by every client. Every other
`.yml`/`.yaml`/`.properties` file directly in the given directory (not
recursive — see above) is treated as one **service**, named after the file
itself. For each service, SCG produces one `EffectiveConfig` per profile —
the union of profiles declared via `spring.config.activate.on-profile` in
*either* the Global file or that service's own file — by cascading four
layers, lowest to highest precedence:

```text
Global-base  <  Global-profile  <  Service-base  <  Service-profile
```

This precedence was confirmed against the Spring Cloud Config reference doc
before implementing it: *"the server creates an Environment from
application.yml (shared) and foo.yml (with foo.yml taking precedence) ...
these same rules apply in a standalone Spring Boot application"* — i.e. it's
exactly what a client named `foo` would resolve locally with
`spring.config.name=application,foo`. A profile a given service never
mentions, and that Global doesn't define either, simply produces no
`EffectiveConfig` for that service — profiles are never invented, only
inherited or overridden. In the report, `sourceFile` is always the
**service's** file (never `application.yml` itself, which only ever appears
merged into every service — the same way an unnamed base config never gets
reported standalone today) — this is enough to identify which service a
finding belongs to, so `Finding`'s fields are unchanged from the regular
mode.

Two deliberate scope decisions behind the matrix above, not oversights:

* **Not recursive.** A Config Server repository is conventionally one flat
  directory. Recursing (like the regular mode does, to find
  `application.yml` inside each module of a multi-module build) risks
  reading unrelated YAML — CI workflows, `docker-compose.yml` — as if it
  were Spring configuration.
* **No `{service}-{profile}.yml` file convention.** Unlike the fixed
  `"application"` prefix, a service name is arbitrary and routinely
  contains hyphens itself (`customers-service`, `api-gateway`), so a file
  like `customers-service-mysql.yml` can't be reliably split into service +
  profile without already knowing the set of valid service names. Profiles
  for a service are read only from `on-profile` documents inside that
  service's own file, exactly as shown above — the same mechanism SCG
  already uses everywhere else.

[`demo-project/config-server-showcase/`](demo-project/config-server-showcase/)
is a working example (Global + two services, one of which adds its own
profile), pinned by `ConfigServerShowcaseTest`.

Validated against a real Spring Cloud Config Server repository, not just this
fixture — see the first entry in [VALIDATION.md](VALIDATION.md).

## Validated against real-world code

Extended, run-by-run validation reports (exact repositories, pinned commits,
finding tables, and how to reproduce each run) live in a separate document
so this README stays focused on what the tool is and how to use it:
see **[VALIDATION.md](VALIDATION.md)**.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — build/test setup, how to add a
new rule, commit and PR conventions.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
