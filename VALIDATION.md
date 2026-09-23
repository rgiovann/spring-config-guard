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
  list was diffed against SCG's actual per-file findings.

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
  is a deliberately deferred candidate (see `BACKLOG.md`, "Pós-1.0"), not an
  oversight.
* **`spring-boot`** (SCG001 wildcard, SCG002, SCG006 — 55 of 66 findings;
  SCG007/009/013/014/017 not independently re-checked this round): **zero
  false negatives** — every file the independent grep flagged was already
  in SCG's own list. Two files SCG caught that the naive grep missed turned
  out to be a wildcard expressed as a YAML list (`include:` / `- "*"` on
  separate lines, which a single-line grep pattern can't see but SCG's YAML
  parser does); four files SCG caught for SCG006 that the grep missed were
  `client-secret: ${APP-CLIENT-SECRET}` — a placeholder **without** a
  default, which SCG correctly treats as unresolved/risky per its
  documented placeholder policy. The naive grep had (wrongly) treated any
  `${...}` as automatically safe and excluded it — a limitation of the
  independent check, not of SCG.
* **`spring-boot-admin`** (SCG001 wildcard, SCG006 — 55 of 85 findings;
  SCG013 not independently re-checked this round, though its relaxed-binding
  matching was already verified separately — see the README's
  ["Why not a generic YAML/IaC scanner"](README.md#why-not-a-generic-yamliac-scanner-checkov-semgrep)
  section): **zero false negatives**. 20 of the 29 SCG001 files the naive
  grep missed are profile files (`application-dev.yml`,
  `application-secure.yml`, etc.) that never mention `exposure` at all —
  confirmed by inspection that they inherit the wildcard from the sibling
  `application.yml` in the same module. This is the exact cross-file
  inheritance behavior the tool exists to catch, caught here in a real
  repository, not just the README's own constructed example.

**Honest scope boundary:** this is not exhaustive coverage of all 17 rules
across all 4 repositories — it's the highest-volume rules per repository,
which is where a false positive/negative would have the largest practical
impact. SCG007, SCG009, SCG010, SCG013 (in `spring-boot`), SCG014, and
SCG017 were not independently re-derived this round; their occurrence
counts in the tables below are as reported by SCG itself, not
cross-checked against a second, independent method.

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

All 66 findings resolve to files under `smoke-test/`/`integration-test/`
module directories — code that exists specifically to exercise one feature
(Actuator, H2 console, OAuth2, Kafka, etc.) with the simplest config that
does it, never to simulate production. A hardcoded
`spring.security.user.password` in a smoke test is expected, not a leak.
Zero findings outside those directories, across the entire repository.

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
