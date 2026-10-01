# Validated against real-world code

Each run below is included as a **precision check on the linter** — every
finding is technically accurate for the property values on disk. What every
run demonstrates is that the linter behaves the same regardless of *why* a
config file exists or which profile (or, in Config Server Mode, which
service) a finding lands in. SCG has no notion of "this is just a demo/test
profile, skip it" — a rule either triggers on the effective properties or it
doesn't, base config and named profiles alike (several rules document this
explicitly as a deliberate "no profile exemption" decision, e.g.
[`H2ConsoleExposedRule`](src/main/java/dev/scg/rules/H2ConsoleExposedRule.java)).
What SCG does skip is a *location*, not a profile: `src/test/` source sets and
Maven/Gradle build output are not scanned at all, since they never ship with
the application (see [ADR-006](ARCHITECTURE.md#adr-006-test-source-sets-and-build-output-excluded-from-the-scan)).

**Update after ADR-006:** the numbers below were recorded before `src/test/`
was excluded from the scan. Re-running the same four commands at the same
pinned target commits changes only the `spring-boot` run, from 66 findings
in 41 files to **64 findings in 39 files**. The two findings that drop both
came from test-only config:

* SCG006 HIGH — `module/spring-boot-security-test/src/test/resources/application.properties`
* SCG013 MEDIUM, profile `endpoints` —
  `smoke-test/spring-boot-smoke-test-actuator/src/test/resources/application-endpoints.properties`

No finding was added in any run, and `spring-boot-admin`,
`spring-petclinic` and `spring-petclinic-microservices-config` (Config
Server Mode, which never recursed) are unchanged.

**Update after ADR-010:** a finding based only on an absent key with an
insecure default is now MEDIUM instead of HIGH ([ADR-010](ARCHITECTURE.md#adr-010-a-finding-based-on-an-absent-key-is-reported-one-level-below-a-written-value)).
Re-running every run below at the same pinned commits, against the v1.5.0
jar, changes severities only: the one SCG014 finding in `spring-boot`
(Kafka configured, `security.protocol` never set) and 31 of the 34 SCG014
findings in `spring-cloud-stream-samples` go from HIGH to MEDIUM. Every
finding keeps its rule, file and profile, and every other run is
byte-identical. The `spring-boot` table below predates ADR-006 and ADR-010
and is kept as recorded; the `spring-cloud-stream-samples` table is
current.

**Reproducibility:** all four runs below were reproduced against SCG
commit [`b0d15ec`](https://github.com/rgiovann/spring-config-guard/commit/b0d15ec25b85437b9579e9b76320482a3dc856eb)
(this repository's `main` at the time of writing); each run's own command
block below pins the exact commit of the *target* repository that produced
the numbers shown, since all four are real, actively-changing repositories —
without a pin, the same command run later against a newer commit could
legitimately return different numbers, not because SCG changed, but because
the target project did.

**Read finding counts as occurrences, not independent problems.** A single
misconfigured property in a shared/inherited file can multiply into many
findings without representing that many distinct issues. The clearest case
is the first run below: 53 findings trace back to 3 properties in one
Global file, inherited by all 8 services. The other three runs are, by
contrast, close to one finding per independently-authored file: Spring
Boot's 66 findings span 41 distinct files, Spring Boot Admin's 85 span 29 —
each smoke-test/sample module carries its own deliberately minimal config,
not a shared root. Check how concentrated a run's findings are in
shared/inherited files before treating a raw finding count, by itself, as a
severity signal.

**The first entry below is the one worth paying attention to.**
`spring-petclinic-microservices-config` is a real, actively-used Spring
Cloud Config Server backing repository — scanned exactly as it's meant to
be consumed, not a demo module living inside a larger codebase. It's also
the scenario that motivated [Config Server Mode](README.md#config-server-mode)
in the first place: without `--config-server`, every one of its 8 service
files is invisible to SCG, since none of them match the `application*`
naming its regular mode looks for. The other three runs (Spring Boot,
Spring Boot Admin, PetClinic) are sample/demo code, included to stress-test
precision rather than as a security assessment of those specific projects —
see each entry's own caveat below.

## Independent precision check (false positive / false negative review)

Everything above shows *what* SCG found. This section is about whether that's
*correct* — checked independently, not by re-reading SCG's own explanation of
its own output.

| Repository | Total findings | Independently verified | False negative found |
|---|---|---|---|
| `spring-petclinic` | 5 | All 17 rules (full manual read, all 3 files) | No |
| `spring-petclinic-microservices-config` | 53 | All 17 rules (full manual read, all 9 files) | No |
| `spring-boot` | 66 | All 8 rules that fired (SCG001, 002, 006, 007, 009, 013, 014, 017 — 66 of 66 findings) | No |
| `spring-boot-admin` | 85 | All 3 rules that fired (SCG001, 006, 013 — 85 of 85 findings) | No |
| `spring-cloud-stream-samples` | 46 | The 15 findings on explicit values against the file contents, plus every file declaring a password, secret or `security.protocol` read by hand | **Yes — 3 files, all fixed since** (see [its entry](#spring-cloudspring-cloud-stream-samples)) |

The paragraph and method below describe the first four repositories.
`spring-cloud-stream-samples` was added later, specifically for its Kafka
security configuration; its own entry says how it was checked.

Every rule that produced at least one finding in these 4 repositories has
now been independently checked. Deliberately still not a scalar
"0 false positives / 0 false negatives" table for the whole tool: 8 of the
17 rules (SCG003, 004, 005, 008, 010, 011, 015, 016) never fired in any of
these 4 repositories, so there was nothing here to independently verify for
them — that says something about these 4 repositories, not about those
rules' precision (see "Rules with nothing to check here" below).

**Method, by repository size:**

* **The two small repositories** (`spring-petclinic`, 3 files;
  `spring-petclinic-microservices-config`, 9 files) were reviewed by reading
  every file in full, deriving the expected finding count against all 17
  rules from first principles, and only then comparing against SCG's actual
  output.
* **The two large repositories** (`spring-boot`, 98 files;
  `spring-boot-admin`, dozens of files) are too large to hand-review file by
  file with real rigor, so instead: an independent script (plain `grep`,
  not SCG's own code — no shared logic, no shared bugs) scanned **every**
  `application*` file for the raw textual patterns behind the two or three
  most common rules in that repository's results, and the resulting file
  list was diffed against SCG's actual per-file findings. The exact commands
  (run from the same directory as the cloned repo, e.g. `spring-boot/` or
  `spring-boot-admin/`):

  ```bash
  # SCG001 (wildcard exposure.include), raw text match, not YAML-aware:
  grep -rlE "exposure\.include\s*[:=]\s*[\"']?\*|include:\s*[\"']?\*" \
    <repo-dir> --include="application*.yml" --include="application*.yaml" \
    --include="application*.properties"

  # SCG002 (H2 console enabled):
  grep -rlEi "h2[._-]?console[._-]?enabled\s*[:=]\s*true" \
    <repo-dir> --include="application*"

  # SCG006 (hardcoded password/secret/credential, deliberately naive:
  # excludes ${...} placeholders, which SCG itself does NOT treat as
  # automatically safe -- see the spring-boot result below):
  grep -rlEi "(password|secret|credential)\s*[:=]\s*['\"]?[A-Za-z0-9_!@#\$%^&*]+['\"]?\s*\$" \
    <repo-dir> --include="application*" | grep -viE '\$\{'

  # SCG007 (credential embedded in a connection URI, e.g. user:pass@host):
  grep -rlE "://[^:/[:space:]]+:[^@/[:space:]]+@" \
    <repo-dir> --include="application*"

  # SCG009 (debug/trace=true, or logging.level.root at DEBUG/TRACE):
  grep -rlEi "^\s*(debug|trace)\s*[:=]\s*true|logging\.level\.root\s*[:=]\s*(DEBUG|TRACE)" \
    <repo-dir> --include="application*"

  # SCG013 (health show-details at always/when-authorized, relaxed-binding-tolerant):
  grep -rlEi "show[._-]?details\s*[:=]\s*[\"']?(always|when-?authorized|when_authorized)" \
    <repo-dir> --include="application*"

  # SCG014 (Kafka configured, but security.protocol never set -- a 2-step
  # check, not one pattern: first find every Kafka-configured file, then
  # subtract the ones that DO set security.protocol explicitly):
  grep -rlE "spring\.kafka" <repo-dir> --include="application*"
  grep -rlE "spring\.kafka(\.[a-z]+)?\.security\.protocol" <repo-dir> --include="application*"

  # SCG017 (OAuth2 Resource Server issuer-uri/jwk-set-uri over http://):
  grep -rlEi "(issuer-uri|jwk-set-uri)\s*[:=]\s*[\"']?http://" \
    <repo-dir> --include="application*"
  ```

  Then compare the resulting file list against the `sourceFile` values in
  SCG's own `--json` output for the matching `ruleId`.

**Results:**

* **`spring-petclinic`**: expected 3× SCG001 (wildcard `exposure.include`
  inherited from base by `base`/`mysql`/`postgres`, none of them override it)
  + 2× SCG006 (`${MYSQL_PASS:petclinic}` / `${POSTGRES_PASS:petclinic}` —
  placeholder *with* a hardcoded default, which resolves to that default) =
  5. Matches exactly. Confirmed why SCG012 correctly stays silent: both JDBC
  URLs (`jdbc:mysql://localhost/petclinic`, `jdbc:postgresql://localhost/petclinic`)
  have no query string at all — no explicit `useSSL=false`/`sslmode=disable`
  for the rule to match — consistent with the project's documented
  explicit-value-only design (`SCG012.yml`), not a gap.
* **`spring-petclinic-microservices-config`**: expected 37× SCG001 + 8×
  SCG006 + 8× SCG012 = 53, reconciled exactly — including discovering that
  5 of the 8 services (`customers-service`, `genai-service`,
  `tracing-server`, `vets-service`, `visits-service`) declare their own
  `default` profile that the Global file never mentions, which is why the
  SCG001 count isn't a uniform 4-per-service (32) but 37. Also confirmed
  `eureka.client.serviceUrl.defaultZone: http://discovery-server:8761/eureka/`
  in several services is correctly *not* flagged — Eureka service discovery
  is a deliberately deferred candidate, not an oversight: the address
  points to the service registry, which is typically deployed
  intra-cluster, so `http://` there is frequently legitimate and flagging
  it would be mostly noise.
* **`spring-boot`** (all 8 rules that fired — SCG001, 002, 006, 007, 009,
  013, 014, 017 — 66 of 66 findings): **zero false negatives** across all
  of them. SCG001/002/006 findings are covered above. SCG007 (2 findings,
  `spring.r2dbc.url` with an embedded `user:secret@` credential), SCG009
  (1, bare `debug=true`), SCG014 (1, the *only* file in the whole repo
  mentioning `spring.kafka` at all, and it never sets
  `security.protocol`), and SCG017 (1, `jwk-set-uri: http://localhost:8080/oauth2/jwks`)
  each matched their independent grep exactly, file for file — small
  enough counts (1-2 each) that the raw file content was also read
  directly, not just diffed by filename. SCG013 (6 findings) matched
  exactly too. Two files SCG caught for SCG001 that the naive grep missed
  turned out to be a wildcard expressed as a YAML list (`include:` /
  `- "*"` on separate lines, which a single-line grep pattern can't see
  but SCG's YAML parser does); four files SCG caught for SCG006 that the
  grep missed were `client-secret: ${APP-CLIENT-SECRET}` — a placeholder
  **without** a default, which SCG correctly treats as unresolved/risky
  per its documented placeholder policy. The naive grep had (wrongly)
  treated any `${...}` as automatically safe and excluded it — a
  limitation of the independent check, not of SCG.
* **`spring-boot-admin`** (all 3 rules that fired — SCG001, 006, 013 — 85
  of 85 findings): **zero false negatives**. 20 of the 29 SCG001 files and
  20 of the 28 distinct SCG013 files the naive grep missed are the same
  profile files (`application-dev.yml`, `application-secure.yml`, etc.)
  that never mention `exposure` or `show-details` at all — confirmed by
  inspection (e.g. `spring-boot-admin-sample-consul/application-dev.yml`)
  that they inherit both properties from the sibling `application.yml` in
  the same module. This is the exact cross-file inheritance behavior the
  tool exists to catch, caught here in a real repository, not just the
  README's own constructed example. One file
  (`spring-boot-admin-sample-zookeeper/application.yml`) accounts for 3 of
  the 30 SCG013 findings by itself — it's a single multi-document YAML
  file with several profiles inside it (same file, several
  `EffectiveConfig`s, already noted for SCG001/006 earlier in this
  document), not a miscount.

**Rules with nothing to check here:** SCG003, SCG004, SCG005, SCG008,
SCG010, SCG011, SCG015, and SCG016 never fired in any of these 4
repositories — confirmed by their absence from every table below, not
assumed. That means these 4 real-world repositories simply don't happen to
exercise those properties, not that those rules are unverified; the
synthetic `demo-project`/`demo-project-clean` fixtures already carry
positive/negative pairs for several of them (see the README's Usage
section), and that pairing is a different, already-existing form of
verification, not a gap being reported here.

## spring-petclinic/spring-petclinic-microservices-config

Run against [spring-petclinic/spring-petclinic-microservices-config](https://github.com/spring-petclinic/spring-petclinic-microservices-config)
via `--config-server` (9 files — 1 Global `application.yml` + 8 services):

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 37 | — | — | 37 |
| SCG006 | 8 | — | — | 8 |
| SCG012 | 8 | — | — | 8 |
| **Total** | **53** | **0** | **0** | **53** |

All 53 findings trace back to the Global `application.yml`: an unrestricted
`management.endpoints.web.exposure.include: "*"` in its base section
(SCG001, inherited by every service and profile), and its `mysql` profile
hardcoding `username: root` / `password: petclinic` with `useSSL=false` on
the JDBC URL (SCG006 + SCG012) — inherited by all 8 services, none of which
override the datasource themselves. The 8 services found (`admin-server`,
`api-gateway`, `customers-service`, `discovery-server`, `genai-service`,
`tracing-server`, `vets-service`, `visits-service`) match the repository's
file listing one-to-one, and `application.yml` itself never appears as a
`sourceFile` — confirming it was folded into every service as the Global
layer, exactly as documented above, rather than skipped or double-counted.

```bash
git clone https://github.com/spring-petclinic/spring-petclinic-microservices-config.git
git -C spring-petclinic-microservices-config checkout 323993ce2519c6d02df63e08bf4458d123d3b611
java -jar target/spring-config-guard.jar spring-petclinic-microservices-config --config-server --json --fail-on=NONE
```

## spring-projects/spring-boot

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

64 of the 66 findings resolve to files under `smoke-test/`/`integration-test/`
module directories — code that exists specifically to exercise one feature
(Actuator, H2 console, OAuth2, Kafka, etc.) with the simplest config that
does it, never to simulate production. A hardcoded
`spring.security.user.password` in a smoke test is expected, not a leak.
The other two are test-support code too: one SCG006 in
`module/spring-boot-security-test/src/test/resources/application.properties`
(that module's own test config, no longer scanned since ADR-006) and one
SCG001 in `system-test/spring-boot-deployment-system-tests/src/main/resources/application.yml`
(a deployment system-test app exposing every Actuator endpoint on purpose).
None come from Spring Boot's own production modules.

```bash
git clone https://github.com/spring-projects/spring-boot.git
git -C spring-boot checkout adbbf047320013ee42284d6957293aaf75a56ad7
java -jar target/spring-config-guard.jar spring-boot --json --fail-on=NONE
```

## codecentric/spring-boot-admin

Run against [codecentric/spring-boot-admin](https://github.com/codecentric/spring-boot-admin)'s
sample suite (29 `application*.yml` files with findings, across 9 of its
`spring-boot-admin-samples` modules — consul, eureka, hazelcast, mcp,
reactive, servlet, servlet-graalvm, war, zookeeper — `--json --fail-on=NONE`):

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 31 | — | — | 31 |
| SCG006 | 24 | — | — | 24 |
| SCG013 | — | 30 | — | 30 |
| **Total** | **55** | **30** | **0** | **85** |

Same story as Spring Boot: every finding is under
`spring-boot-admin-samples/`, whose entire purpose is to showcase one
integration (Consul, Eureka, Hazelcast, Zookeeper, ...) with the most
minimal config that works, `secure`/`insecure` profiles included on
purpose to demonstrate the difference. The
`spring-boot-admin-sample-zookeeper/application.yml` case is a good
illustration of the profile-agnostic point above: its `insecure` profile is
an empty override (it only activates the profile, no properties of its own),
yet SCG still reports the same SCG001/SCG006/SCG013 findings there as on
`[base]`, because they're genuinely present in that profile's effective
config — inherited or not doesn't matter.

```bash
git clone https://github.com/codecentric/spring-boot-admin.git
git -C spring-boot-admin checkout 8699ebdfd3afa96f0fd2318addc7508f4be14def
java -jar target/spring-config-guard.jar spring-boot-admin --json --fail-on=NONE
```

## spring-projects/spring-petclinic

Run against [spring-projects/spring-petclinic](https://github.com/spring-projects/spring-petclinic)
(3 `application*.properties` files, `--json --fail-on=NONE`):

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 3 | — | — | 3 |
| SCG006 | 2 | — | — | 2 |
| **Total** | **5** | **0** | **0** | **5** |

Unlike the two runs above, this isn't a demo subdirectory inside a larger
real project — PetClinic's `src/main/resources/application.properties` *is*
the whole application, and it exists purely as a well-known reference/teaching
app, never as a deployed service. `management.endpoints.web.exposure.include=*`
in the base config (flagged even though the file's own comment says "Don't
do this in production, only for development and testing") and
`spring.datasource.password=${MYSQL_PASS:petclinic}` /
`${POSTGRES_PASS:petclinic}` in the `mysql`/`postgres` profiles (a plaintext
fallback behind an env placeholder) are exactly the kind of properties SCG
is built to catch — the profile-agnostic behavior just means the tool
doesn't quietly trust "it's only a profile-gated default" as a reason to
stay silent.

```bash
git clone https://github.com/spring-projects/spring-petclinic.git
git -C spring-petclinic checkout 818c4136ea971c21674525f9053de0d9c7ad8cfe
java -jar target/spring-config-guard.jar spring-petclinic --json --fail-on=NONE
```

## spring-cloud/spring-cloud-stream-samples

Run against [spring-cloud/spring-cloud-stream-samples](https://github.com/spring-cloud/spring-cloud-stream-samples)
(56 `application*.{yml,yaml,properties}` files outside `src/test/`,
`--json --fail-on=NONE`), with SCG commit
[`018c045`](https://github.com/rgiovann/spring-config-guard/commit/018c04565436100c1501d51ca602b7c7d7c3cb64),
not `b0d15ec` like the four runs above, then re-run after each fix below:
the SCG006 fix (3 findings added), ADR-009 (34 added) and ADR-010 (31
SCG014 findings from HIGH to MEDIUM). Nothing else changed. Added as the corpus's only real
Kafka security surface: hardcoded keystore passwords, `SASL_PLAINTEXT`, and
JAAS credentials configured through the Spring Cloud Stream Kafka binder
rather than `spring.kafka.*`.

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 1 | — | — | 1 |
| SCG006 | 8 | — | — | 8 |
| SCG007 | 2 | — | — | 2 |
| SCG013 | — | 1 | — | 1 |
| SCG014 | 3 | 31 | — | 34 |
| **Total** | **14** | **32** | **0** | **46** |

31 of the 34 SCG014 findings report a protocol that isn't set, MEDIUM since
ADR-010: 2 modules
using `spring.kafka.*`, and, since ADR-009, 29 binders in use (samples that
configure Kafka only through the Spring Cloud Stream binder, typically
`brokers: localhost:9092`), where Kafka's default is `PLAINTEXT`. They
follow from the absence of a key rather than from a value, so they are
counted, not read one by one.

The other 15 findings are on explicit values, all accurate for the values
on disk: literal passwords (`spring.datasource.password`,
`spring.security.user.password`, the binder's `jaas.options.password` in
`kafka-streams-jaas-security`, and the three numeric SSL passwords in
`kafka-ssl-demo`), the 2 JAAS passwords and 3 `SASL_PLAINTEXT` values
written in the binder (below), `exposure.include=*` and
`show-details: ALWAYS`. Like the other sample suites, these modules show one
feature each and are not deployed services.

**False negatives.** Every file declaring a password, secret or
`security.protocol` was read by hand, which found three files with a risk
SCG didn't report:

* `kafka-security-samples/kafka-ssl-demo` — **fixed.**
  `ssl.keystore.password`, `ssl.truststore.password` and `ssl.key.password`,
  all `123456`, under `spring.cloud.stream.kafka.binder.configuration`. SCG006
  matched the key names, but its precision heuristic skipped purely numeric
  values for pattern-matched keys (meant for values like
  `token-validity-in-seconds: 86400`). It now reports a numeric value when
  the key ends in a secret pattern, which names the secret itself; the three
  passwords are among the 12 findings above.
* `kafka-streams-samples/kafka-streams-jaas-security` — **fixed** (ADR-009).
  `security.protocol: SASL_PLAINTEXT` under
  `spring.cloud.stream.kafka.binder.configuration` (and the Kafka Streams
  binder's equivalent). SCG014 only read `spring.kafka.*`, so the binder's
  unencrypted protocol raised nothing; both keys are now reported. The JAAS
  password in the same file is caught by SCG006 through its key name.
* `multi-binder-samples/kafka-multi-binder-jaas` — **fixed** (ADR-009). Two
  JAAS configs with inline passwords in
  `spring.cloud.stream.binders.<name>.environment.spring.cloud.stream.kafka.binder.configuration.sasl.jaas.config`,
  and `SASL_PLAINTEXT` in the binder configuration. SCG007 only read
  `spring.kafka.properties.sasl.jaas.config` and `spring.kafka.jaas.options`,
  and SCG014 only `spring.kafka.*`, so the file raised nothing; it now raises
  2 SCG007 and 1 SCG014 findings.

The last two shared one cause: SCG007 and SCG014 covered Spring Boot's
`spring.kafka.*` namespace, not the Spring Cloud Stream Kafka binders'.
ADR-009 evaluates the binders, each named binder's environment as a context
of its own.

This repository uses no bracketed map keys, so it does not exercise
ADR-007.

```bash
git clone https://github.com/spring-cloud/spring-cloud-stream-samples.git
git -C spring-cloud-stream-samples checkout 2ff1168833cfcab14d2251219dad15a8919c1672
java -jar target/spring-config-guard.jar spring-cloud-stream-samples --json --fail-on=NONE
```

## ProfileMerger correctness benchmark (`/actuator/env` comparison)

The runs above check rule precision against real-world config. This
benchmark checks a lower-level claim instead: that `ProfileMerger`'s
effective configuration for a profile is equivalent to what a real, running
Spring Boot application resolves through `/actuator/env`. It's validation
infrastructure, not part of this repository's regular `mvn test` run — the
app it depends on (`spring-env-benchmark/`) lives in this repository as a
plain directory, not a Maven module of this build (same convention as
`demo-project/`/`demo-project-clean/`), so SCG's own build never resolves
or depends on Spring Boot because of it. The JUnit test that drives the
comparison (`ActuatorEnvComparisonTest`) is tagged `benchmark` and excluded
by default from `mvn test` (via the root `pom.xml`'s `excludedGroups`
property) for the same reason — it needs that app actually running.

**Fixture:** `spring-env-benchmark`'s `application.yml` (base + an
`on-profile: prod` document) + `application-prod.yml` (profile) +
`application.properties` exercise 6 `ProfileMerger`/`ConfigFileGrouper`
behaviors: scalar override, list replacement, relaxed binding across
base/profile (kebab-case base key, camelCase profile key), explicit-null
override, placeholder-with-default resolution, and — the same profile
(`prod`) sourced from both a named file and an on-profile block inside the
base file — the two merging together, with the named file winning a key
conflict.

A second set, under `app.bracket-map`, checks bracketed map keys
([ADR-007](ARCHITECTURE.md#adr-007-bracketed-map-keys-rewritten-into-dotted-form-at-load-time)):
a profile adding an entry keeps the base's entries; a profile overriding one
entry replaces only that one; `"[security.protocol]"` in `.yml` and
`security.protocol` in `.properties` are the same key, so `.properties`
wins; a dotted key nested in YAML without brackets is one entry; a
bracketed `.properties` key is overridden by the profile's `.yml`; an entry
only in the on-profile block survives; and the raw YAML spelling is
`app.bracket-map[com.acme-core]`, not `app.bracket-map.[com.acme-core]`.

A third set, under `app.lists`, checks the same list written in different
formats, where the comma-separated and indexed spellings are different keys
(`a` vs. `a[0]`): comma-separated `.properties` over an indexed `.yml` list
and the reverse, both replaced entirely by `.properties`; spaces after the
commas (Spring strips each element); an empty `.properties` value, which
Spring binds as an empty list, clearing the `.yml` list and, from a
profile, the base's list; `[]` in a profile's `.yml`, which Spring's YAML
loader stores as an empty string; a comma-separated profile value over an
indexed base list; and, as a control, a profile that doesn't mention the key
keeping the base's list.

A fourth set, under `app.object-lists`, checks lists of objects partially
overridden: a profile `.yml` or `.properties` setting only `[0].port` of a
base list of two objects, a same-directory `.properties` setting only
`[0].url`, a profile writing the index as a quoted `"[0]"` YAML key, and a
control. Spring takes the whole list from the highest-precedence source, so
fields the profile doesn't write (including a base `password`) are gone.
A profile skipping index 0 (only `[1]`) isn't a case: Spring refuses to
start ("elements ... were left unbound").

A fifth set, under `app.shapes`, puts a scalar and a map on the same key,
one in the base and the other in the profile, in both directions, bound as
a `Map`, a `String` and an object. Spring removes neither shape: both stay
in the property sources, and the target type decides which one binds (the
sub-keys for a `Map` or an object, the scalar for a `String`), even when the
ignored shape comes from the profile.

**Comparison method:** `/actuator/env`'s PropertySources are filtered down
to the file-based ones, resolved by canonical key
(`RelaxedProperties.canonicalize`), keeping the value from the
highest-precedence source per key — necessary because Spring keeps
`app.relaxed-binding-test` (base) and `app.relaxedBindingTest` (profile) as
two separate physical PropertySource entries; only `ProfileMerger` collapses
them into one. `EnvironmentPlaceholder.resolve()` is applied to the SCG side
before comparing the placeholder case, since `EffectiveConfig` stores the
raw `${VAR:default}` text — resolution happens lazily, per `Rule`, not at
merge time.

The bracketed map can't be checked the same way: `/actuator/env` lists each
source's raw keys, but merging map entries across sources and treating
`[a.b]` and `a.b` as one key happen in Spring's `Binder`, when the value is
read. So the benchmark app binds `app.bracket-map` into a
`@ConfigurationProperties` record (`BenchmarkProperties`), and SCG's map is
compared with what `/actuator/configprops` shows for it: Spring's final
answer. Besides one assertion per case, the two maps must be identical, so
an entry SCG drops or invents fails too.

The lists are read from `/actuator/configprops` for the same reason, one
`List<String>` per case. On the SCG side, each list is read as the rules
read it: the values of the key or of its indexed children, split on commas
and stripped. `ListFormatsTest` repeats the cases on the real
`management.endpoints.web.exposure.include` key, checking SCG001, and runs
in the regular build.

The one accepted divergence is pinned on both sides: Spring keeps
`[com.foo-bar]` (base) and `[com.foobar]` (profile) as two entries, while
SCG, after rewriting them into dotted form, sees one key under relaxed
binding and keeps the profile's value (ADR-007). A change on either side
fails the benchmark.

**Result:** all assertions match the real Spring Boot 4.1.1 output (6
benchmark tests). Run against the `ConfigLoader` from before ADR-007, the
bracketed map test fails on the first case: the base's
`[com.acme-core]` entry is lost once the profile adds one of its own. The
list format cases needed no code change: `ProfileMerger` already treats
`a` and `a[n]` as one list in both directions. With that purge disabled,
the list test fails on its first case (SCG sees `[*, health, info]`, both
spellings surviving).
The lists of objects found one divergence, fixed in ADR-008: SCG joined a
quoted `"[0]"` YAML key with a dot (`quoted-index.[0].url`), so the
profile's element wasn't recognized as part of the list and the base's
whole list survived. The other cases already matched.

Scalar vs. map needed no change either: SCG keeps both shapes, like
Spring's property sources, and a rule reads the shape of the property it
checks. The test pins that SCG keeps both; with the merge changed to purge
a base map when the profile sets a scalar, it fails on that case. What
remains is a limitation, not a divergence: SCG doesn't know types, so a
rule reading a key in the shape Spring ignores would see a value Spring
doesn't bind. No rule does so for a realistic configuration, and no
reference project writes one key in both shapes.

One difference in representation remains, harmless for every current rule:
for `[]` in a profile, SCG purges the base list and keeps no key, where
Spring keeps an empty string. Rules reading a list see the same empty list
either way; it would only matter to a rule treating an absent key as an
insecure default.

Exposing `configprops` changed what SCG reports on the benchmark app itself:
the same 4 SCG001 findings, whose messages now name `configprops` next to
`env`. Since the lists-of-objects cases, the app also reports 2 SCG006
findings, for the two literal passwords of the `partial-override` base list:
on the base only, since the `prod` profile replaces that list and Spring
drops them — the behavior ADR-008 fixed. 6 findings in total.

```bash
# 1. Start the benchmark app (plain directory in this repo, not a Maven module)
cd spring-env-benchmark
mvn spring-boot:run "-Dspring-boot.run.profiles=prod"

# 2. In a separate shell, back at the spring-config-guard root:
mvn test -Dgroups=benchmark -DexcludedGroups=
# -DexcludedGroups= (empty) overrides the pom's default exclusion of the
# "benchmark" group; no source edit needed, and it's excluded again next
# time you run a plain `mvn test`.
```

## SCG001 exposure scenarios (`/actuator` comparison)

Which sensitive Actuator endpoints SCG001 reports is checked against which
ones Spring Boot 4.1.1 actually exposes over HTTP. The same benchmark app is
started once per configuration, with the extra properties as command-line
arguments, and `/actuator` lists the endpoints it links to.

| # | With `exposure.include=*` | Sensitive endpoints Spring exposes |
|---|---|---|
| S1 | nothing else | `env`, `threaddump`, `configprops`, `beans`, `loggers` |
| S2 | `exposure.exclude=env,heapdump` | `threaddump`, `configprops`, `beans`, `loggers` |
| S3 | `endpoints.access.default=none` | none |
| S4 | `endpoint.env.enabled=false` (legacy) | as S1, without `env` |
| S5 | `endpoints.enabled-by-default=false` (legacy) | none |
| S6 | `management.server.port=-1` | none |
| S7 | `endpoint.heapdump.access=unrestricted` | as S1, plus `heapdump` |
| S8 | `access.default=none`, `env.access=unrestricted` | `env` |
| S9 | `enabled-by-default=false`, `env.enabled=true` (legacy) | `env` |
| S10 | `endpoints.access.default=unrestricted` | as S1, plus `heapdump` and `shutdown` |
| S11 | `max-permitted=read-only`, `heapdump.access=unrestricted` | as S1, plus `heapdump` |
| S12 | `exposure.exclude=*` | none |
| S13 | `enabled-by-default=true` (legacy) | as S1, plus `heapdump` and `shutdown` |
| S14 | `endpoints.access.max-permitted=none` | none |
| S15 | `endpoints.access.default=read-only` | as S1, plus `heapdump` (not `shutdown`: write-only) |
| S16 | `env.access` and `env.enabled` both set | the app refuses to start: mutually exclusive |
| S17 | `max-permitted=read-only`, `shutdown.access=unrestricted` | as S1 (not `shutdown`) |
| S18 | `shutdown.access=unrestricted` | as S1, plus `shutdown` |

Before this comparison, SCG001 read only `exposure.include` and each
endpoint's own `access`/`enabled`: S2, S3, S5, S6, S12 and S14 were false
positives (reported endpoints Spring doesn't expose), and S10, S13 and S15
false negatives (`heapdump`, and in S10 and S13 `shutdown`, exposed but not
reported). It now resolves each endpoint as Spring does, and
`ActuatorExposureRuleTest` asserts, per scenario, exactly the endpoints
listed above. `restart` isn't in the app (it needs Spring Cloud Context);
its `defaultAccess = NONE` was read in `spring-cloud-commons`' source, so it
follows `heapdump`.

None of the reference projects above uses these keys with a web
`exposure.include`, so their findings are unchanged.

```bash
cd spring-env-benchmark
mvn -q package -DskipTests
./actuator-exposure-scenarios.sh
```

## SCG006 key matching (Spring Boot 4.1.1 metadata)

Which keys SCG006 treats as secrets is checked against the 2650 properties in
the configuration metadata of Spring Boot 4.1.1's modules (96 of 97 module
jars from Maven Central; `spring-boot-webflux` couldn't be fetched), plus a
hand-built set of 30 keys: 20 non-secrets, native and third-party, 6
secrets as controls, and 4 secrets whose key doesn't end in the word.

SCG006 used to match a pattern (`password`, `secret`, `token`,
`credential`, ...) anywhere in the key, so a namespace, a map key, a nested
object or a package name containing the word was enough. With the v1.6.0
jar, 18 of the 20 non-secrets were reported as HIGH, including native
properties:

* `spring.security.oauth2.authorizationserver.client.<id>.token.*`
  (`access-token-time-to-live=5m`, `id-token-signature-algorithm=RS256`, and
  three more), `spring.security.oauth2.resourceserver.opaquetoken.client-id`,
  `spring.datasource.hikari.credentials-provider-class-name`,
  `spring.ldap.embedded.credential.username`;
* `logging.level.org.springframework.security.oauth2.server.authorization.token=DEBUG`;
* `spring.cloud.kubernetes.secrets.namespace`,
  `spring.cloud.gcp.secretmanager.project-id`, a Spring Cloud Stream binding
  named `tokenEvents`, `app.jwt.token-prefix=Bearer`.

A custom key is now HIGH only when it ends in a pattern, and
`logging.level`/`logging.group` are skipped. A key that only contains a
pattern is INFO, which never fails a build on its own (checked: exit 0 with
`--fail-on=LOW`): it may still name a secret, so it stays visible instead of
being silenced. Measured on the same keys:

| | v1.6.0 | Now |
|---|---|---|
| 20 non-secrets | 18 HIGH | 1 HIGH, 15 INFO, 4 silent |
| 6 secrets (controls) | 6 HIGH | 6 HIGH |
| 4 secrets named with the word before another one, in the plural, or behind a placeholder default (`app.secret-key-base`, `app.password-hash`, `app.api-keys`, `app.token-value`) | 4 HIGH | 4 INFO |

The remaining HIGH is
`server.ssl.certificate-private-key=/etc/tls/server.key` (a plain path;
accepted, see the rule's Javadoc); the 4 silent ones are the 2
`logging.level` keys, a boolean and a number. Against the metadata, 4 native
properties can now be INFO instead of HIGH, none of them a secret
(`api-token-type`, `credentials-provider-class-name`,
`embedded.credential.username`, `opaquetoken.client-id`), plus the 6
non-boolean fields of
`spring.security.oauth2.authorizationserver.client.<id>.token`, which the
metadata doesn't list since they sit inside a map; every native secret is
still HIGH. Every reference project above reports the same findings, byte
for byte, as with the v1.6.0 jar: all 80 SCG006 findings there were on keys
ending in a pattern, and no key there only contains one with a value that
could be a secret.

Where SCG006 stays silent was then reviewed case by case (CLAUDE.md,
"Findings"), which changed two of them:

* A key containing a pattern but ending in `-uri`/`-url`/`-endpoint`
  (`token-uri`) was silent whatever its value. Its URL is now checked: a
  password in the user-info is HIGH, a query string INFO, a plain URL or
  path silent. A secret in the path itself (a webhook URL) stays silent, an
  accepted limitation.
* A `classpath:` value in a key naming secret material was silent as a mere
  reference. It is INFO now: the material is packaged inside the jar,
  usually committed. `file:` stays silent. A certificate or its location is
  silent too (`public-material-suffixes`), since a certificate is public:
  without that, SAML's `...credentials[0].certificate-location` gave 4 INFO
  in `spring-boot`.

On 6 more hand-built keys, v1.6.0 was silent on all of them; now
`https://svc:s3cr3t@...` in `app.security.token-url` is HIGH, a
`?token=` query and `classpath:certs/server.key` in a `private-key` are
INFO, and a webhook URL, a GitHub `token-uri` and a SAML
`certificate-location` stay silent. On the reference corpus this adds 6
INFO in `spring-boot`, all private keys packaged with an application: the
`spring.ssl.bundle.pem.*.keystore.private-key` of the two SNI integration
test apps (4) and the SAML smoke test's `private-key-location` (2). Every
other reference project is byte-identical to v1.6.0.

`HardcodedSecretsRuleTest` pins these cases. Three
`high-risk-keys` entries that don't exist in Spring Boot 4.1.1 were replaced
(`spring.elasticsearch.rest.password`, removed in 3.0;
`spring.couchbase.env.ssl.key-store-password`, deprecated;
`spring.ldap.embedded.credential`, an object rather than a key) and 11
current ones added. That changes the message wording and reports a blank
value as INFO for those keys; detection was already HIGH through the
`password` pattern.

## SCG014 protocol precedence (Spring Boot 4.1.1 `KafkaProperties`)

Which `security.protocol` each Kafka client actually gets was checked by
binding properties to Spring Boot 4.1.1's own `KafkaProperties` and building
each client's configuration (`buildConsumerProperties()` and the others),
with kafka-clients 4.2.1, whose default protocol is `PLAINTEXT`. Precedence,
highest first: the client's `properties` map
(`spring.kafka.consumer.properties.security.protocol`), the client's typed
key (`spring.kafka.consumer.security.protocol`), the common
`spring.kafka.properties` map, the common typed key
(`spring.kafka.security.protocol`).

SCG014 used to evaluate every key on its own, so an insecure value
overridden by a secure one was still reported as HIGH:

| Scenario | Spring's result | SCG014 before | Now |
|---|---|---|---|
| P1 common typed `PLAINTEXT`, common map `SSL` | `SSL` everywhere | HIGH | none |
| P2 common typed `SSL`, common map `PLAINTEXT` | `PLAINTEXT` everywhere | HIGH (map) | HIGH (map) |
| P3 consumer `SSL`, common map `PLAINTEXT` | `PLAINTEXT` for the other clients | HIGH (map) | HIGH (map) |
| P4 consumer typed `PLAINTEXT`, consumer map `SSL` | consumer `SSL`, others unset | HIGH + MEDIUM | MEDIUM |
| P5 common `PLAINTEXT`, every client `SSL` | `SSL` everywhere | HIGH | none |
| P6 consumer `SSL` only | others unset | MEDIUM | MEDIUM |
| P7 consumer, producer, admin `SSL` | streams unset | MEDIUM | MEDIUM, naming streams |

SCG014 now resolves the protocol per client in that order and reports only
the keys a client actually uses, once each; inside a named binder's
environment too. An unresolved placeholder overrides what is below it,
since it resolves at runtime or the application doesn't start. The "not
set" finding names the clients left without a protocol, and the streams
client counts even without a `spring.kafka.streams.*` key: a Kafka Streams
application can take its application id from `spring.application.name`.
On the reference projects only the wording of the 3 "not set" findings
changes (1 in `spring-boot`, 2 in `spring-cloud-stream-samples`); every
other finding is byte-identical.

