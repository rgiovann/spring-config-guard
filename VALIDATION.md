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
| `spring-cloud-stream-samples` | 9 | All 9 findings against the file contents, plus every file declaring a password, secret or `security.protocol` read by hand | **Yes — 3 files** (see [its entry](#spring-cloudspring-cloud-stream-samples)) |

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
not `b0d15ec` like the four runs above. Added as the corpus's only real
Kafka security surface: hardcoded keystore passwords, `SASL_PLAINTEXT`, and
JAAS credentials configured through the Spring Cloud Stream Kafka binder
rather than `spring.kafka.*`.

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 1 | — | — | 1 |
| SCG006 | 5 | — | — | 5 |
| SCG013 | — | 1 | — | 1 |
| SCG014 | 2 | — | — | 2 |
| **Total** | **8** | **1** | **0** | **9** |

All 9 findings are accurate for the values on disk: literal passwords
(`spring.datasource.password`, `spring.security.user.password`, and the
binder's `jaas.options.password` in `kafka-streams-jaas-security`),
`exposure.include=*`, `show-details: ALWAYS`, and two modules using
`spring.kafka.*` without setting `security.protocol`. Like the other sample
suites, these modules show one feature each and are not deployed services.

**False negatives.** Every file declaring a password, secret or
`security.protocol` was read by hand, which found three files with a risk
SCG doesn't report:

* `kafka-security-samples/kafka-ssl-demo` —
  `ssl.keystore.password`, `ssl.truststore.password` and `ssl.key.password`,
  all `123456`, under `spring.cloud.stream.kafka.binder.configuration`. SCG006
  matches the key names, but its precision heuristic skips purely numeric
  values for pattern-matched keys (meant for values like
  `token-validity-in-seconds: 86400`), so a numeric password is never
  reported.
* `kafka-streams-samples/kafka-streams-jaas-security` —
  `security.protocol: SASL_PLAINTEXT` under
  `spring.cloud.stream.kafka.binder.configuration` (and the Kafka Streams
  binder's equivalent). SCG014 only reads `spring.kafka.*`, so the binder's
  unencrypted protocol raises nothing. The JAAS password in the same file is
  caught by SCG006 through its key name.
* `multi-binder-samples/kafka-multi-binder-jaas` — two JAAS configs with
  inline passwords in
  `spring.cloud.stream.binders.<name>.environment.spring.cloud.stream.kafka.binder.configuration.sasl.jaas.config`,
  and `SASL_PLAINTEXT` in the binder configuration. SCG007 only reads
  `spring.kafka.properties.sasl.jaas.config` and `spring.kafka.jaas.options`,
  and SCG014 only `spring.kafka.*`, so the file raises nothing.

The last two share one cause: SCG007 and SCG014 cover Spring Boot's
`spring.kafka.*` namespace, not the Spring Cloud Stream Kafka binder's. All
three are tracked in [`BACKLOG.md`](BACKLOG.md) for the rule-by-rule review.

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
`on-profile: prod` document) + `application-prod.yml` (profile) + a
residual `application.properties` (just `spring.application.name`)
exercise 6 `ProfileMerger`/`ConfigFileGrouper` behaviors: scalar override,
list replacement, relaxed binding across base/profile (kebab-case base
key, camelCase profile key), explicit-null override,
placeholder-with-default resolution, and — the same profile (`prod`)
sourced from both a named file and an on-profile block inside the base
file — the two merging together, with the named file winning a key
conflict.

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

**Result:** all 6 assertions match the real Spring Boot 4.1.1 output.

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
