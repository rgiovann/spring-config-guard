# Validated against real-world code

What SCG reports, checked against what Spring actually does. Three kinds of
evidence, each reproducible from this repository:

* **Reference projects**: five public repositories, pinned to a commit,
  scanned with the documented command; every finding was checked against
  the files (below).
* **The pipeline**: `ProfileMerger`'s effective configuration compared with
  what a running Spring Boot app resolves through `/actuator/env`
  ("ProfileMerger correctness benchmark").
* **Each rule**: its scenarios run against a real Spring Boot 4.1.1 app, a
  client on the wire or the library's own source, one configuration at a
  time, with the scripts in `spring-env-benchmark/` (its
  [README](spring-env-benchmark/README.md) lists them and what each needs).

Every number and every **SCG** column in this document is the result of
**SCG v1.17.0**. Most scenario rows are pinned by a test named after
them, so a change in behavior fails the build before it can make this
document wrong. The rest, mostly in the sections of SCG001, SCG003,
SCG007–SCG009, SCG011 and SCG012, are covered by tests that don't name
each row; every one of them was checked against the v1.16.0 jar, one
fixture per row. What changed between releases, and why, is in `CHANGELOG.md` and
the git history, not here.

SCG has no notion of "this is just a demo or test profile": a rule
triggers on the effective properties of base and named profiles alike
(CLAUDE.md, "Profiles"). What it skips is a *location*: `src/test/` source
sets and Maven/Gradle build output, which never ship with the application
([ADR-006](ARCHITECTURE.md#adr-006-test-source-sets-and-build-output-excluded-from-the-scan)).

**Read finding counts as occurrences, not independent problems.** One
property in a shared or inherited file multiplies into one finding per
profile and per service that inherits it: 48 findings in
`spring-petclinic-microservices-config` trace back to three properties in
its Global file. The sample suites, by contrast, come close to one finding
per independently written file.

## Reference projects

| Repository | Commit | Mode | Files with findings | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|---|---|---|
| `spring-petclinic/spring-petclinic-microservices-config` | `323993c` | `--config-server` | 8 services | 40 | — | 8 | 48 |
| `spring-projects/spring-boot` | `adbbf04` | regular | 42 | 49 | 7 | 20 | 76 |
| `codecentric/spring-boot-admin` | `8699ebd` | regular | 29 | 55 | 31 | 1 | 87 |
| `spring-projects/spring-petclinic` | `818c413` | regular | 3 | 5 | — | — | 5 |
| `spring-cloud/spring-cloud-stream-samples` | `2ff1168` | regular | 30 | 13 | 28 | 6 | 47 |

`spring-petclinic-microservices-config` is a real Spring Cloud Config
Server backing repository, scanned the way it is consumed; it is the case
that motivated [Config Server Mode](README.md#config-server-mode), since
none of its service files match the `application*` naming the regular
mode looks for. The other four are sample, test and teaching code: they
stress-test precision on real-world configuration, and are not a security
assessment of those projects.

## spring-petclinic/spring-petclinic-microservices-config

Run with `--config-server` (9 files: one Global `application.yml` and 8
services):

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 32 | — | — | 32 |
| SCG006 | 8 | — | — | 8 |
| SCG012 | — | — | 8 | 8 |
| **Total** | **40** | **—** | **8** | **48** |

Every finding traces back to the Global `application.yml`, inherited by
all 8 services, none of which override it: `exposure.include: "*"` in its
base section (SCG001), and its `mysql` profile's `password: petclinic`
(SCG006) and `jdbc:mysql://localhost:3306/petclinic?...useSSL=false`
(SCG012, INFO since the host is a loopback address; HIGH on a remote host,
"Loopback addresses in the transport rules"). SCG001 counts 32: four
configurations per service (the base, `chaos-monkey`, `docker` and
`mysql`), each inheriting the Global base. 5 services
(`customers-service`, `genai-service`, `tracing-server`, `vets-service`,
`visits-service`) also write an `on-profile: default` document, which
Spring applies when no profile is active: part of their base, not a
profile of its own ("Profile expressions in `on-profile`", P8). The
8 services match the repository's file listing one to one, and
`application.yml` never appears as a `sourceFile`: it is folded into every
service as the Global layer. `eureka.client.serviceUrl.defaultZone:
http://discovery-server:8761/eureka/` is not reported: service discovery
addresses are deferred (`BACKLOG.md`).

```bash
git clone https://github.com/spring-petclinic/spring-petclinic-microservices-config.git
git -C spring-petclinic-microservices-config checkout 323993ce2519c6d02df63e08bf4458d123d3b611
java -jar target/spring-config-guard.jar spring-petclinic-microservices-config --config-server --json --fail-on=NONE
```

## spring-projects/spring-boot

Run against Spring Boot's own source (84 `application.{yml,yaml,properties}`
files outside `src/test/`):

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 21 | — | — | 21 |
| SCG002 | 3 | — | — | 3 |
| SCG006 | 23 | — | 13 | 36 |
| SCG007 | 2 | — | — | 2 |
| SCG009 | — | 1 | 5 | 6 |
| SCG013 | — | 6 | — | 6 |
| SCG014 | — | — | 1 | 1 |
| SCG017 | — | — | 1 | 1 |
| **Total** | **49** | **7** | **20** | **76** |

Every finding is in a `smoke-test/` (69), `integration-test/` (6) or
`system-test/` (1) module: code that exercises one feature (Actuator, H2
console, OAuth2, Kafka, ...) with the simplest configuration that does
it, never production. A hardcoded `spring.security.user.password` in a
smoke test is expected there. The SCG014 and SCG017 findings are on
`localhost` (`bootstrap-servers=localhost:9092`,
`jwk-set-uri: http://localhost:8080/oauth2/jwks`), hence INFO.

```bash
git clone https://github.com/spring-projects/spring-boot.git
git -C spring-boot checkout adbbf047320013ee42284d6957293aaf75a56ad7
java -jar target/spring-config-guard.jar spring-boot --json --fail-on=NONE
```

## codecentric/spring-boot-admin

Run against Spring Boot Admin's sample suite (29 `application*.yml` files
with findings, across 9 `spring-boot-admin-samples` modules: consul,
eureka, hazelcast, mcp, reactive, servlet, servlet-graalvm, war,
zookeeper):

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 31 | — | — | 31 |
| SCG006 | 24 | — | — | 24 |
| SCG009 | — | 1 | 1 | 2 |
| SCG013 | — | 30 | — | 30 |
| **Total** | **55** | **31** | **1** | **87** |

Every finding is under `spring-boot-admin-samples/`, whose modules each
show one integration with the most minimal configuration that works,
`secure` and `insecure` profiles included on purpose. In
`spring-boot-admin-sample-zookeeper/application.yml`, the `insecure`
profile only activates itself, with no properties of its own, and SCG still
reports the SCG001, SCG006 and SCG013 findings it inherits, since they are
in that profile's effective configuration.

```bash
git clone https://github.com/codecentric/spring-boot-admin.git
git -C spring-boot-admin checkout 8699ebdfd3afa96f0fd2318addc7508f4be14def
java -jar target/spring-config-guard.jar spring-boot-admin --json --fail-on=NONE
```

## spring-projects/spring-petclinic

Run against PetClinic (3 `application*.properties` files):

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 3 | — | — | 3 |
| SCG006 | 2 | — | — | 2 |
| **Total** | **5** | **—** | **—** | **5** |

PetClinic is a whole application, kept as a reference and teaching app.
`management.endpoints.web.exposure.include=*` in the base file is reported
in the base and in the `mysql` and `postgres` profiles that inherit it,
although the file's own comment says "Don't do this in production", and
`spring.datasource.password=${MYSQL_PASS:petclinic}` (and `POSTGRES_PASS`)
resolves to its plaintext default. SCG012 stays silent: neither JDBC URL
has a query string, so there is no explicit `useSSL=false` or
`sslmode=disable` to report.

```bash
git clone https://github.com/spring-projects/spring-petclinic.git
git -C spring-petclinic checkout 818c4136ea971c21674525f9053de0d9c7ad8cfe
java -jar target/spring-config-guard.jar spring-petclinic --json --fail-on=NONE
```

## spring-cloud/spring-cloud-stream-samples

Run against Spring Cloud Stream's samples (58
`application*.{yml,yaml,properties}` files outside `src/test/`), the
corpus's real Kafka security surface: hardcoded keystore passwords,
`SASL_PLAINTEXT` and JAAS credentials configured through the Spring Cloud
Stream Kafka binder rather than `spring.kafka.*`.

| Rule | HIGH | MEDIUM | INFO | Total |
|---|---|---|---|---|
| SCG001 | 1 | — | — | 1 |
| SCG006 | 8 | — | — | 8 |
| SCG007 | 2 | — | — | 2 |
| SCG009 | — | — | 1 | 1 |
| SCG013 | — | 1 | — | 1 |
| SCG014 | 2 | 27 | 5 | 34 |
| **Total** | **13** | **28** | **6** | **47** |

31 of the 34 SCG014 findings report a protocol that isn't set, where
Kafka's default is `PLAINTEXT` ([ADR-010](ARCHITECTURE.md#adr-010-a-finding-based-on-an-absent-key-is-reported-one-level-below-a-written-value)):
2 modules using `spring.kafka.*` and 29 binders in use (samples that
configure Kafka only through the binder, [ADR-009](ARCHITECTURE.md)). 27
are MEDIUM; 4 are INFO, since the brokers they write are all on
`localhost`. The other 16 findings are on explicit values: literal
passwords (`spring.datasource.password` twice,
`spring.security.user.password`, `jaas.options.password` in the Kafka and
Kafka Streams binders, the three numeric SSL passwords in
`kafka-ssl-demo`), the 2 JAAS passwords in
`kafka-multi-binder-jaas` (SCG007), the 3 `SASL_PLAINTEXT` values written
in a binder (one INFO, on `localhost` brokers), `exposure.include=*`,
`show-details: ALWAYS` and one logger at a debug level.

This repository uses no bracketed map keys, so it doesn't exercise
ADR-007.

```bash
git clone https://github.com/spring-cloud/spring-cloud-stream-samples.git
git -C spring-cloud-stream-samples checkout 2ff1168833cfcab14d2251219dad15a8919c1672
java -jar target/spring-config-guard.jar spring-cloud-stream-samples --json --fail-on=NONE
```

## Independent precision check (false positive / false negative review)

Whether each finding above is correct, and whether a risk was missed,
checked without SCG's own code.

| Repository | Findings | How it was checked | False negative found |
|---|---|---|---|
| `spring-petclinic` | 5 | Every file read; expected count derived by hand | No |
| `spring-petclinic-microservices-config` | 48 | Every file read; expected count derived by hand | No |
| `spring-boot` | 76 | Independent greps, file by file, for the 8 rules that fired | No |
| `spring-boot-admin` | 87 | Independent greps, file by file, for the 4 rules that fired | No |
| `spring-cloud-stream-samples` | 47 | Every file with a password, secret or `security.protocol` read by hand | No |

**The small repositories** were read in full, with the expected findings
derived against every rule before comparing with SCG's output: 3 SCG001 +
2 SCG006 = 5 in `spring-petclinic`; 32 SCG001 + 8 SCG006 + 8 SCG012 = 48
in `spring-petclinic-microservices-config`, as explained in their
sections.

**The large repositories** were checked with plain `grep` (no shared logic
with SCG) for the raw textual pattern behind each rule that fired, and the
file list compared with the `sourceFile`s of SCG's `--json` output for
that rule. No file the greps found was missing from SCG's output. Every
file SCG reported beyond the greps was read, and is one of:

* a wildcard written as a YAML list (`include:` / `- "*"` on separate
  lines), which a single-line grep can't see (2 SCG001 files in
  `spring-boot`);
* a profile file that inherits the risky property from its module's base
  file, which is the inheritance SCG exists to catch (20 SCG001, 20
  SCG013 and 2 SCG006 files in `spring-boot-admin`);
* a value the grep treats as safe or doesn't look for: a placeholder
  without a default (`client-secret: ${APP-CLIENT-SECRET}`), which SCG
  reports as INFO since it can't be known statically, a key naming secret
  material (`private-key`, `signing.credentials`), or a secret pattern
  the grep doesn't list (7 SCG006 files in `spring-boot`);
* a logger other than the root set to `DEBUG` or `TRACE` (5 SCG009 files
  in `spring-boot`, 1 in `spring-boot-admin`), outside the grep's
  `debug`/`trace`/root pattern.

The greps, run from the directory holding the cloned repository:

```bash
# SCG001 (wildcard exposure.include), raw text match, not YAML-aware:
grep -rlE "exposure\.include\s*[:=]\s*[\"']?\*|include:\s*[\"']?\*" \
  <repo-dir> --include="application*.yml" --include="application*.yaml" \
  --include="application*.properties"

# SCG002 (H2 console enabled):
grep -rlEi "h2[._-]?console[._-]?enabled\s*[:=]\s*true" \
  <repo-dir> --include="application*"

# SCG006 (hardcoded password/secret/credential, deliberately naive: it
# excludes ${...} placeholders, which SCG doesn't treat as safe):
grep -rlEi "(password|secret|credential)\s*[:=]\s*['\"]?[A-Za-z0-9_!@#\$%^&*]+['\"]?\s*\$" \
  <repo-dir> --include="application*" | grep -viE '\$\{'

# SCG007 (credential embedded in a connection URI, e.g. user:pass@host):
grep -rlE "://[^:/[:space:]]+:[^@/[:space:]]+@" \
  <repo-dir> --include="application*"

# SCG009 (debug/trace=true, or logging.level.root at DEBUG/TRACE):
grep -rlEi "^\s*(debug|trace)\s*[:=]\s*true|logging\.level\.root\s*[:=]\s*(DEBUG|TRACE)" \
  <repo-dir> --include="application*"

# SCG013 (health show-details at always/when-authorized):
grep -rlEi "show[._-]?details\s*[:=]\s*[\"']?(always|when-?authorized|when_authorized)" \
  <repo-dir> --include="application*"

# SCG014 (Kafka configured, but security.protocol never set): the files of
# the first command, minus those of the second:
grep -rlE "spring\.kafka" <repo-dir> --include="application*"
grep -rlE "spring\.kafka(\.[a-z]+)?\.security\.protocol" <repo-dir> --include="application*"

# SCG017 (resource server URIs over http://):
grep -rlEi "(issuer-uri|jwk-set-uri|public-key-location|introspection-uri)\s*[:=]\s*[\"']?http://" \
  <repo-dir> --include="application*"
```

**`spring-cloud-stream-samples`** was checked by reading every file that
declares a password, secret or `security.protocol`. The 31 SCG014 findings
on an absent protocol follow from the absence of a key, so they were
counted, not read one by one.

**Rules with nothing to check here:** SCG003, SCG004, SCG005, SCG008,
SCG010, SCG011, SCG015 and SCG016 fire in none of these repositories, which
don't use those properties. Their evidence is their own scenarios, below,
and the `demo-project`/`demo-project-clean` fixtures.

## ProfileMerger correctness benchmark (`/actuator/env` comparison)

The reference projects check rule precision against real-world config.
This benchmark checks a lower-level claim instead: that `ProfileMerger`'s
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
`application.properties` + `application.yaml` exercise 7
`ProfileMerger`/`ConfigFileGrouper` behaviors: scalar override, list
replacement, relaxed binding across base/profile (kebab-case base key,
camelCase profile key), explicit-null override (and a null in the base file
no profile redefines, `debug:` and `~`: Spring loads both as an empty
string, and so does SCG), placeholder-with-default resolution, the same
profile (`prod`) sourced from both a named file and an on-profile block
inside the base file — the two merging together, with the named file
winning a key conflict — and, with the same key in `application.yml` and
`application.yaml`, `.yml` winning (case 35).

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
indexed base list; a YAML null in a profile over a base list (case 38),
which replaces it as `[]` does; and, as a control, a profile that doesn't
mention the key keeping the base's list.

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
ignored shape comes from the profile. A YAML null in the profile over a
base map or object (cases 36 and 37) is the same: the base's sub-keys stay
and bind, in SCG as in Spring.

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
benchmark tests). Each set fails when the behavior it pins is removed:
with bracketed keys kept as they are written (before ADR-007), the
bracketed map test fails on its first case, the base's `[com.acme-core]`
entry lost once the profile adds one of its own; with the purge that
treats `a` and `a[n]` as one list disabled, the list test fails on its
first case (SCG sees `[*, health, info]`, both spellings surviving); with
a quoted `"[0]"` YAML key joined with a dot (`quoted-index.[0].url`, before
ADR-008), the profile's element isn't recognized as part of the list and
the base's whole list survives; with the merge changed to purge a base
map when the profile sets a scalar, the shapes test fails on that case.

SCG keeps both shapes of a scalar-vs-map key, like Spring's property
sources, and a rule reads the shape of the property it checks. What
remains is a limitation, not a divergence: SCG doesn't know types, so a
rule reading a key in the shape Spring ignores would see a value Spring
doesn't bind. No rule does so for a realistic configuration, and no
reference project writes one key in both shapes.

One difference in representation remains, harmless for every current rule:
for `[]` in a profile, SCG purges the base list and keeps no key, where
Spring keeps an empty string. Rules reading a list see the same empty list
either way; it would only matter to a rule treating an absent key as an
insecure default.

SCG reports 6 findings on the benchmark app itself: 4 SCG001, for `env`
and `configprops` exposed with `show-values`, in the base and in `prod`;
and 2 SCG006, for the two literal passwords of the `partial-override` base
list, on the base only, since the `prod` profile replaces that list and
Spring drops them (ADR-008).

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

## Profile expressions in `on-profile` (running Spring Boot 4.1.1 app)

Which documents Spring Boot applies for a `spring.config.activate.on-profile`
value, by active profiles, next to the configurations SCG builds for the
same files, reproducible with
`spring-env-benchmark/profile-expression-scenarios.sh` and the fixtures in
`spring-env-benchmark/profile-expressions/`. Each fixture sets
`spring.h2.console.enabled` in a base document and in conditioned documents
or other files; the app runs with that directory as its only config
location, and the value comes from `/actuator/env`. SCG's side is whether
the configuration it builds for those active profiles has the console on,
which is when it reports SCG002.

Each cell is Spring / SCG: `on` or `off`; `—` when SCG builds no
configuration for that set of active profiles: several profiles active
together are evaluated only when a profile group activates them ("Profile
groups"), and a profile no file or expression names
(`c` in P1) gets the base's configuration in Spring. Unless the row says
otherwise, the base document has the console off and the conditioned
document turns it on. `ProfileExpressionScenariosTest` pins every SCG cell.

| # | Files | none | `a` | `b` | `a,b` | `c` | SCG's configurations |
|---|---|---|---|---|---|---|---|
| P1 | `on-profile: '!a'` | on / on | off / off | on / — | off / — | on / — | base (on), `a` (off) |
| P2 | `'a,b'` | off / off | on / on | on / on | on / — | off / — | base (off), `a`, `b` (on) |
| P14 | `' a ,  b '` | off / off | on / on | on / on | | | base (off), `a`, `b` (on) |
| P3 | `[a, b]` (YAML list); base **on**, the list's document off | on / on | off / off | off / off | off / — | on / — | base (on), `a`, `b` (off) |
| P4 | `'a & b'` | off / off | off / off | off / off | on / — | off / — | base, `a`, `b` (off); the document is counted as not evaluated |
| P5 | `'a \| b'` | off / off | on / on | on / on | on / — | off / — | base (off), `a`, `b` (on) |
| P6 | `'(a & !b) \| c'` | off / off | on / on | off / off | off / — | on / on | base (off), `a` (on), `b` (off), `c` (on) |
| P7 | `'!a, b'` | on / on | off / off | on / on | on / — | on / — | base (on), `a` (off), `b` (on) |
| P8 | `on-profile: default` | on / on | off / — | | | | base (on) |
| P9 | `application-default.yml` | on / on | off / — | | | | base (on) |
| P10 | base off, `on-profile: a` on, then another base document off | off / off | off / off | | | | base, `a` (off) |
| P11 | `application.yml`: base off, `on-profile: a` on; `application.properties`: off | off / off | off / off | | | | base, `a` (off) |
| P12 | `application-x.yml` with `on-profile: '!b'`, on (columns: none, `x`, `x,b`) | off / off | on / on | | off / — | | base (off), `x` (on), `b` (off) |
| P13 | `'a & b \| c'` (columns: none, `c`) | app did not start / input error | | | | app did not start / input error | none: exit code 2 |

Spring reads the value as a list of profile expressions: a comma, or a
YAML list (P3), means "any of", and spaces around the items are ignored
(P14); each item can use `!`, `&`, `|` and parentheses (P1, P4–P7); `&` and
`|` mixed without parentheses is malformed, and the application doesn't
start (P13: `Malformed profile expression [a & b | c]`). With no profile
active, the `default` profile is: `!a` and `on-profile: default` apply, and
so does `application-default.yml` (P1, P8, P9). Documents apply in source
order, so a later base document overrides an earlier conditioned one (P10),
and `application.properties` overrides a conditioned document in
`application.yml` (P11). `on-profile` inside a profile-specific file is an
extra condition (P12); Spring Boot 4.1.1 rejects only
`spring.profiles.active` and `spring.profiles.default` there.

SCG evaluates the base with `default` active and one configuration per
profile any file name or expression refers to, `default` excepted
([ADR-012](ARCHITECTURE.md#adr-012-on-profile-evaluated-as-spring-boot-does-one-ordered-fold-per-set-of-active-profiles)),
so every cell where it builds a configuration matches Spring's.

A Config Server repository's order (P15), measured as the Spring Cloud
Config reference says the server resolves it, with
`spring.config.name=application,svc`. Each key is set in several of
`application.yml` (base, then a `dev` block), `svc.yml` (base, then a `dev`
block) and `application-dev.yml`:

| # | Active | `k1` | `k2` | `k3` | `k4` |
|---|---|---|---|---|---|
| P15 | none | `svc-base` | `app-base` | `svc-base` | `svc-base` |
| P15 | `dev` | `svc-base` | `app-block` | `app-dev-file` | `app-dev-file` |

Every document of `svc.yml`, its base included, overrides `application.yml`'s
`dev` block (`k1`), and `application-dev.yml` overrides `svc.yml`'s `dev`
block (`k4`). `ConfigServerAssembler` uses that order, pinned by
`ConfigServerAssemblerTest` with the same files.

The grammar's edge cases, measured with one document per value (the last
part of the script). Each cell says whether Spring applied the document;
the columns are the active profiles.

| # | `on-profile` | none | `a` | `b` | `c` | `a,b` | `b,c` |
|---|---|---|---|---|---|---|---|
| E1 | `'!default'` | no | yes | yes | yes | yes | yes |
| E2 | `'a b'` | no | no | no | no | no | no |
| E3 | `'a)'`, `'(a'`, `'&a'`, `'a&'` | no | yes | no | no | yes | no |
| E4 | `'!!a'`, `'(a)'` | no | yes | no | no | yes | no |
| E5 | `'a & (b \| c)'` | no | no | no | no | yes | no |
| E6 | `'!(a \| b)'`, `'!a & !b'` | yes | no | no | yes | no | no |
| E9 | `'Prod'` (columns: none, `prod`, `Prod`) | no | no | yes | | | |
| E10 | `on-profile:` with no value, `~`, `""`, `[]`, or `on-profile=` in `.properties` (columns: none, `a`) | yes | yes | | | | |
| E11 | a map: `on-profile: {x: prod}`, or `on-profile.x=prod` in `.properties` (columns: none, `prod`, `x`) | yes | yes | yes | | | |

With `a b` active, the application didn't start: Spring Boot rejects the
profile name (`Profile 'a b' must contain a letter, digit or allowed
char`), so E2's document never applies. The application didn't start for E7 (`'!'`,
`'a | !b & c'`: `Malformed profile expression`) and E8 (`'a,,b'`, `',a'`,
`'a,'`, `' '`, and the YAML list `[a, ""]`: `Invalid profile expression
[]: must contain text`). E10: a null, empty or empty-list value is no
condition at all, so the document always applies. E11: a map under
`on-profile` isn't a condition either; the bracketed form
`on-profile[prod]=x` in `.properties` stops the application (`The elements
[spring.config.activate.on-profile[prod]] were left unbound`).

This is Spring Framework's `ProfilesParser`: a space doesn't separate
names, so `'a b'` is one profile named `a b`, which can't be activated
(E2); a stray parenthesis or
a dangling operator is tolerated (E3); an operator with nothing to apply
to, `&` and `|` mixed without parentheses, or an empty list item stops the
application (E7, E8), including a blank value; and names are
case-sensitive (E9). SCG's `ProfileExpression` follows the same steps,
pinned by `ProfileExpressionTest`; `ConfigLoader` reads E7 and E8 as an
input error (exit code 2) and E10 as no condition, pinned by
`ConfigLoaderTest`. SCG still builds a configuration for `a b` (E2), which
Spring can't run, and reads both E11 forms as no condition: the map form as
Spring does, the bracketed one where Spring refuses to start, which has no
effect on findings since the document then applies to every configuration.

**In the reference projects** (application files at the pinned commits,
counted on 2026-10-06):

* `spring-petclinic-microservices-config`: five services start with an
  `on-profile: default` document (P8), part of each service's base: SCG
  builds no `default` configuration for them.
* `spring-boot`: one expression, `goodbye | dev`, in a smoke test with no
  findings.
* `spring-cloud-stream-samples`: two documents use the legacy
  `spring.profiles` key, which SCG doesn't read as an activation (they are
  folded into the base); not measured here.
* `codecentric/spring-boot-admin` and `spring-petclinic`: plain profile
  names only.
* Of the candidate reference projects (`BACKLOG.md`), `jhipster-sample-app`
  writes `on-profile: '!api-docs'` (P1) and two `on-profile` documents
  (`dev`, `prod`) inside `application-secret-samples.yml` (P12), which
  apply only when `secret-samples` and that profile are both active, and
  declares `group.dev: [secret-samples, api-docs]` ("Profile groups"). The
  `'!api-docs'` block, which turns SpringDoc off, reaches the
  base and the `prod`, `secret-samples` and `tls` profiles but not `dev`,
  whose group activates `api-docs`: SCG008 is reported for `dev` and
  `api-docs` only. The `dev` document of `application-secret-samples.yml`
  applies to `dev`, where its blank `spring.datasource.password` is an
  SCG006 INFO; the `prod` one, which only `prod` and `secret-samples`
  together activate, is counted in the stderr warning. `dev` also reports
  the H2 console of `application-dev.yml` (SCG002), which the null
  `spring:` at the top of `application-secret-samples.yml` leaves on, in
  Spring as in SCG ("ProfileMerger correctness benchmark", case 36). 23
  findings in all.

## Profile groups (running Spring Boot 4.1.1 app)

Which profiles `spring.profiles.group` activates, and in which order their
files apply, measured with the last part of
`spring-env-benchmark/profile-expression-scenarios.sh`. Each row prints the
active profiles `/actuator/env` reports and, for `k1`–`k4`, the value of the
highest-precedence source; `—` when no source sets it.
`ProfileGroupScenariosTest` pins each row on SCG's side, as the
configuration of the activated profile (the base for "none").

| # | Files | Active | Spring's active profiles | `k1` | `k2` | `k3` | `k4` |
|---|---|---|---|---|---|---|---|
| G1 | `group.dev: [a, b]`; `application-dev` sets k1–k3, `-a` k1–k2, `-b` k1; blocks `on-profile: b`, then `a`, set k4 | `dev` | `dev,a,b` | `b` | `a` | `dev` | `a-block` |
| G1 | the same | none | none | `base` | `base` | `base` | `base` |
| G1 | the same | `a` | `a` | `a` | `a` | `base` | `a-block` |
| G2 | `group.dev: [a]`, `group.a: [b]`; `application-b` sets k1 | `dev` | `dev,a,b` | `b` | — | — | — |
| G3 | `group.dev: [a]` inside `application-dev.yml`; `application-a` sets k2 | `dev` | `dev` | `dev` | — | — | — |
| G4 | `group.dev: [a]` inside an `on-profile: dev` document; `application-a` sets k2 | `dev` | `dev,a` | `dev` | `a` | — | — |
| G5 | `spring.profiles.include: [x]`; `application-x` sets k1, `-dev` k2, `-default` k3 | none | `x` | `x` | — | — | — |
| G5 | the same | `dev` | `x,dev` | `x` | `dev` | — | — |
| G6 | `group.dev=a,b` in `.properties`; `application-a` sets k1, `-b` k2 | `dev` | `dev,a,b` | `a` | `b` | — | — |
| G7 | `group.default: [a]`; `application-a` sets k1 | none | none listed | `a` | — | — | — |

A group's profiles are activated after the profile that names them, depth
first (G2), and profile-specific files apply in that activation order, the
last one winning (G1: `b` over `a` over `dev`), while `on-profile` blocks
keep their order in the file (G1: the `a` block, written last, wins). A
group declared in a profile-specific file is ignored (G3); one inside an
`on-profile` document applies (G4). The `default` profile's group applies
when no profile is active, though `/actuator/env` lists none (G7).
`spring.profiles.include` adds its profiles always, and `default` is then no
longer active: `application-default.yml` doesn't apply (G5).

SCG matches every row but G5
([ADR-013](ARCHITECTURE.md#adr-013-profile-groups-evaluated-with-the-profile-that-activates-them)):
`spring.profiles.include` is not evaluated, so its base keeps `k1=base` and
applies `application-default.yml`. No reference project uses it.

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

SCG001 resolves each endpoint as Spring does, not from `exposure.include`
and the endpoint's own `access`/`enabled` alone: for every scenario but S16
it reports exactly the endpoints listed above, which
`ActuatorExposureRuleTest` asserts. In S16, where Spring refuses to start,
SCG001 reports the endpoints of S1: it doesn't check that an endpoint's
`access` and `enabled` exclude each other (a test pins this). `restart`
isn't in the app (it needs Spring Cloud Context); its `defaultAccess = NONE`
was read in `spring-cloud-commons`' source, so it follows `heapdump`.

None of the reference projects uses these keys with a web
`exposure.include`.

Split across config locations (ADR-005), checked with fixtures, each with
the multi-location coverage warning: `exposure.include=env` in
`src/main/resources` and `env.show-values=always` in `config/` (Spring:
`env` exposed with values) loses the `show-values` finding, which the same
two keys in one file report, a false negative; `exposure.include=*` in
`src/main/resources` and `access.default=none` in `config/` (Spring: no
endpoint reachable) is still HIGH, a false positive.

```bash
cd spring-env-benchmark
mvn -q package -DskipTests
./actuator-exposure-scenarios.sh
```

## SCG002 H2 console scenarios (running Spring Boot 4.1.1 app)

Which values turn the H2 console on, and from where it answers, was checked
in an app with Spring MVC and Spring Boot's H2 console module, reproducible
with `spring-env-benchmark/h2-console-scenarios.sh`, run twice with the
same results. Each scenario requests the console from loopback, from the
machine's non-loopback address (a remote client to H2), and through
`loopback-proxy.py`, a reverse proxy on that address forwarding to
localhost as a proxy or sidecar on the same machine does. "blocked" is H2's
"remote connections are disabled" page.

|  # | Configuration | Loopback / remote / proxied | SCG |
|---|---|---|---|
|  H0 | defaults | 404 / 404 / 404 | silent  |
|  H1, H2 | `enabled=true`, `TRUE` | console / blocked / console | HIGH  |
|  H3–H5 | `enabled=yes`, `on`, `1` | 404 / 404 / 404 | silent  |
|  P1 | `enabled=true ` (trailing space, `.properties`) | 404 / 404 / 404 | silent  |
|  H6–H9 | `enabled=false`, `off`, empty, `banana` | 404 / 404 / 404 | silent  |
|  H10 | `enabled=${H2_ENABLED}`, unset | app did not start | INFO  |
|  H11 | `enabled=${H2_ENABLED:true}` | console / blocked / console | HIGH  |
|  Y1 | YAML `enabled: on`, unquoted | console / blocked / console | HIGH  |
|  A1, A2 | `enabled=true`, `web-allow-others=true` or `yes` | console / console / console | HIGH, aggravating  |
|  A5 | `enabled=true`, `web-allow-others=${UNSET:true}` | console / console / console | HIGH, aggravating  |
|  A3 | `web-allow-others=true` alone | 404 / 404 / 404 | silent  |
|  A4 | A1 with a plain `web-admin-password` | 500 / 500 / 500 | HIGH, aggravating  |
|  T1 | `enabled=true`, `path=/db` | console / blocked / console | HIGH  |

Spring Boot turns the console on with `@ConditionalOnBooleanProperty`,
which took only `true`, in any case (H1, H2): `yes`, `on`, `1` and a
trailing space left it off (H3–H5, P1).
`web-allow-others` is bound through the Binder and took `yes` too (A2).
Without it, H2 served only loopback clients, but through the same-host
proxy, which sends no `X-Forwarded-For`, a remote client reached the
console (H1, proxied); a proxy that sends that header, to an app that
trusts it, was not measured. So the console stays HIGH either way and
the message names `web-allow-others` when it is set. A placeholder without
a default is INFO (H10); for `web-allow-others` (not in the table) the
message says the console may accept remote clients rather than that it
does. H2 rejects a `web-admin-password` that isn't in its encoded form, so
A4's console answered 500.

## SCG003 CORS scenarios (running Spring Boot 4.1.1 apps)

How Spring answers a credentialed cross-origin request was checked in two
running Spring Boot 4.1.1 apps: Actuator's CORS in this benchmark app
(`/actuator/env`, reproducible with
`spring-env-benchmark/cors-scenarios.sh`), and Spring for GraphQL's in a
minimal app with `spring-boot-starter-graphql` (`/graphql`, reproducible
with `spring-env-benchmark/graphql-cors-scenarios.sh`). Spring Boot 4.1.1's
configuration metadata binds CORS from properties for these two only, with
the same keys.

|  # | With `allow-credentials=true` unless noted | Spring 4.1.1 | SCG |
|---|---|---|---|
|  C1 | Actuator `allowed-origins=*` | app doesn't start ("allowedOrigins cannot contain the special value *") | LOW  |
|  G2 | GraphQL `allowed-origins=*` | 500 on every CORS request | LOW  |
|  C2 | Actuator `allowed-origin-patterns=*` | foreign origin echoed with credentials | HIGH  |
|  G1 | GraphQL `allowed-origin-patterns=*` | foreign origin echoed with credentials | HIGH  |
|  C6 | Actuator `allowed-origin-patterns=https://*` | foreign origin echoed with credentials | HIGH  |
|  C3 | Actuator `allowed-origins=https://*.example.com` | 403: compared literally | silent  |
|  G3 | GraphQL `allowed-origins=https://*.example.com` | 403: compared literally | silent  |
|  C4 | Actuator `allowed-origin-patterns=https://*.example.com` | subdomain gets credentials | MEDIUM  |
|  G4 | GraphQL `allowed-origin-patterns=https://*.example.com` | subdomain gets credentials | MEDIUM  |
|  C5 | Actuator `allowed-origins=*`, no credentials | `Access-Control-Allow-Origin: *` without credentials | silent  |
|  C8 | `allowed-origin-patterns=${CORS_ORIGINS}` | decided at runtime | INFO  |

SCG003 reads both prefixes and each origin key as Spring does: a wildcard
is only a pattern in `allowed-origin-patterns`; `*` in `allowed-origins`
with credentials is rejected by Spring, so it is LOW (present but
ineffective) rather than an exploitable HIGH; an unresolved placeholder,
in an origin key or in `allow-credentials`, is INFO.

Spring anchors the end of a pattern, so SCG003 looks at what follows the
last `*`: unless it fixes a domain of at least two labels, the pattern is
HIGH. In the running app each of these echoed an attacker's origin with
credentials: `https://*.com` (`https://evil.com`), `https://*example.com`
(`https://evilexample.com`) and `https://app.*` (`https://app.evil.com`).
`https://*.example.com` and `https://*-staging.example.com` are MEDIUM (the
app refused `https://a.example.com.evil.com` and
`https://x-staging.example.com.evil.com`), and so is a public suffix of two
labels or more, such as `*.co.uk` or a hosting platform's `*.vercel.app`,
which SCG can't tell from a company's domain. Spring Cloud Gateway's CORS
properties are left open (BACKLOG.md).

Wildcards in the scheme, the host or the port, and the `null` origin, were
run with `cors-scenarios.sh`, `graphql-cors-scenarios.sh` and
`null-origin-browser-probe.sh`, each twice with the same results (A6–A13
are SCG004's rows, "SCG004 insecure origin scenarios"):

|  # | With `allow-credentials=true` unless noted | Spring 4.1.1 | SCG |
|---|---|---|---|
|  A6 | `allowed-origin-patterns=*://app.example.com` | only `app.example.com`, in any scheme | silent  |
|  A7 | `allowed-origin-patterns=http*://app.example.com` | only `app.example.com` | silent  |
|  A8 | `allowed-origin-patterns=http://localhost:*` | loopback only (`http://localhost.evil.com`: 403) | silent  |
|  A10 | `allowed-origin-patterns=http://localhost:[*]` | loopback only | silent  |
|  A11 | `allowed-origin-patterns=http://*.localhost` | `localhost` subdomains only | silent  |
|  A13 | `allowed-origin-patterns=http://localhost*` | `http://localhost.evil.com` allowed with credentials | HIGH  |
|  N1 | `allowed-origins=null` | `Origin: null` allowed with credentials | HIGH  |
|  N2 | `allowed-origins=NULL` | the same: compared ignoring case | HIGH  |
|  N3 | `allowed-origin-patterns=null` | the same | HIGH  |
|  N4 | `allowed-origins=null`, no credentials | allowed, without credentials | silent  |
|  N5 | `allowed-origins: null` unquoted in YAML | no CORS headers: YAML null is no value | silent  |
|  G5 | GraphQL `allowed-origins=null` | allowed with credentials | HIGH  |

SCG003 takes the host as SCG004 does (`CorsOrigins`): a wildcard only in
the scheme or the port lets one host in, and a host whose matches are all
`localhost` names is no attacker's origin; both are silent, and SCG004
reports the plain-HTTP remote hosts among them. `null` is the origin a
browser sends from a sandboxed iframe, which any page can embed: in
Chromium, a page's sandboxed iframe read `/actuator/env` with credentials
when `allowed-origins=null`, and was blocked with another origin. It is
HIGH with credentials, INFO with credentials from an unresolved
placeholder, and silent without them, like `*` (C5).

## SCG004 insecure origin scenarios (running Spring Boot 4.1.1 apps)

How Spring answers a cross-origin request from a plain-HTTP origin was
checked in the same two apps as SCG003: Actuator's CORS in this benchmark
app (`/actuator/env`) and Spring for GraphQL's in the `graphql-cors` app
(`/graphql`), both reproducible with
`spring-env-benchmark/cors-insecure-origin-scenarios.sh`, run twice with
the same results. How an origin is
read comes from `CorsConfiguration` in spring-web 7.0.9: `allowed-origins`
is compared ignoring case; in a pattern, `*` matches any sequence, matching
is case-sensitive and anchored, and a trailing `:[*]` or `:[8080,8081]` is
a port list whose comma doesn't separate origins.

|  # | With `allow-credentials=true` unless noted | Spring 4.1.1 | SCG |
|---|---|---|---|
|  A1 | `allowed-origins=http://partner.example` | allowed with credentials | MEDIUM  |
|  A2 | the same, no credentials | allowed, without credentials | LOW  |
|  A3 | `allowed-origins=HTTP://PARTNER.EXAMPLE` | allowed with credentials | MEDIUM  |
|  A4 | `allowed-origin-patterns=HTTP://partner.example` | 403: patterns are case-sensitive | MEDIUM  |
|  A5 | `allowed-origin-patterns=*.example.com` | `http://a.example.com` allowed with credentials | MEDIUM  |
|  A6 | `allowed-origin-patterns=*://app.example.com` | `http://app.example.com` allowed with credentials | MEDIUM  |
|  A7 | `allowed-origin-patterns=http*://app.example.com` | `http://app.example.com` allowed with credentials | MEDIUM  |
|  A8 | `allowed-origin-patterns=http://localhost:*` | loopback only (`http://localhost.evil.com`: 403) | silent  |
|  A9 | `allowed-origin-patterns=http://localhost:[8080,8082]`, a scalar | 403: Spring Boot splits the value on its comma | silent  |
|  A9b | the same, as a YAML list item | ports 8080 and 8082 allowed, 9000: 403 | silent  |
|  A10 | `allowed-origin-patterns=http://localhost:[*]` | loopback only (`http://localhost.evil.com`: 403) | silent  |
|  A11 | `allowed-origin-patterns=http://*.localhost` | `http://a.localhost` allowed, `http://a.localhost.evil.com`: 403 | silent  |
|  A13 | `allowed-origin-patterns=http://localhost*` | `http://localhost.evil.com` allowed with credentials | MEDIUM  |
|  G1 | GraphQL `allowed-origins=http://partner.example` | allowed with credentials | MEDIUM  |
|  G2 | GraphQL `allowed-origin-patterns=http://*.example.com`, no credentials | allowed, without credentials | LOW  |
|  P1 | `allowed-origins=http://${PARTNER_HOST}` | decided at runtime | INFO  |
|  P2 | `allowed-origins=${APP_ORIGIN},http://partner.example`, no credentials | `http://partner.example` allowed | LOW and INFO  |

SCG004 reads both prefixes, splits a value as `CorsConfiguration` does, and
reports a pattern whose scheme is missing or a wildcard (A5–A7). A loopback
host is silent with any port, port wildcard or port list, and so are
subdomains of `localhost` (A8–A11). Severity follows `allow-credentials`:
MEDIUM when it is true; LOW otherwise, since an injected script then only
reads responses to anonymous requests (SCG003 reports nothing for
`allowed-origins=*` without credentials, its C5, which lets every origin
in). A literal origin next to a placeholder is reported at its own severity
(P2); an origin is INFO only where the placeholder decides it. A4 is kept as
a finding: the pattern matches nothing, but it is a broken configuration
meant to allow plain HTTP. The pattern `*` is left to SCG003.

Leaving loopback origins unreported (A8–A11) assumes the browser resolves
`localhost` names itself: if it asked DNS, an attacker on the network could
answer `a.localhost` with their own address, serve a page from it, and pass
the CORS check. `spring-env-benchmark/localhost-browser-probe.sh` serves a
page on 127.0.0.1 and loads it by name, run twice with the same results:
Chromium 141 loaded it from `localhost`, `a.localhost` and
`deep.a.localhost`, though the system resolver had no answer for the last
two, and didn't load it from `example.test`, which the resolver didn't
answer either. Firefox and Safari were not measured.

## SCG005 methods and headers scenarios (running Spring Boot 4.1.1 app and Chromium)

What `allowed-methods` and `exposed-headers` change for a script on a
permitted origin was checked in this benchmark app (Actuator, with `env`
and `loggers` exposed) and in Chromium, reproducible with
`spring-env-benchmark/cors-methods-headers-scenarios.sh`, run twice with the
same results. Spring Boot 4.1.1 builds Actuator's and GraphQL's CORS
configuration only when `allowed-origins` or `allowed-origin-patterns`
binds to a non-empty list (`toCorsConfiguration()` returns null
otherwise); unset methods default to GET and HEAD. Which response headers
a script reads is decided by the browser, so it was checked against a
minimal server.

|  # | Configuration (`allowed-origins` set unless noted) | Spring 4.1.1 / Chromium | SCG |
|---|---|---|---|
|  M1 | `allowed-methods=*`, no origin key | no CORS headers at all | silent  |
|  M2 | `allowed-methods=*`, credentials | POST preflight allowed with credentials | MEDIUM  |
|  M4 | `allowed-methods=GET,DELETE`, credentials | DELETE preflight allowed with credentials | silent  |
|  M7 | `allowed-methods=*`, no credentials | allowed, without credentials | LOW  |
|  M5 | `allowed-methods=*`, a JSON POST | preflight 403: `Content-Type` not allowed | —  |
|  B1 | `allowed-methods=*` and `allowed-headers=*`, credentials | a JSON POST set the ROOT logger to TRACE (204) | —  |
|  H1 | `exposed-headers=*`, credentials | `Access-Control-Expose-Headers: *`; Chromium exposed no header | LOW (ineffective)  |
|  H3 | `exposed-headers=*`, no origin key | no CORS headers at all | silent  |
|  E1 | `allowed-origins=${SCG_ORIGINS:}`, `allowed-methods=*`, credentials | no CORS headers at all | silent  |
|  H4 | `exposed-headers=X-Auth-Token`, credentials | Chromium exposed it to the script | MEDIUM  |
|  H5 | `exposed-headers=X-Auth-Token`, no credentials | exposed on anonymous responses | LOW  |
|  H6 | `exposed-headers=Set-Cookie, Cookie` | Chromium never exposed `Set-Cookie` | LOW, INFO  |
|  T1 | `exposed-headers=X-Access-Token`, credentials | `Access-Control-Expose-Headers: X-Access-Token` | INFO  |
|  G1 | GraphQL `allowed-methods=*`, `exposed-headers=X-Auth-Token`, credentials | GraphQL binds the same keys | MEDIUM, MEDIUM  |

M5 and B1 show that a JSON write needs both `allowed-methods` and
`allowed-headers`; `allowed-methods=*` alone still lets DELETE and a POST
without a non-safelisted header through, so it stays the finding, and its
message names the dependency. `allowed-headers=*` alone allowed no write
(Chromium blocked the POST), so it isn't reported. Severity follows
`allow-credentials`, as in SCG004: the permitted origins are trusted by
configuration, and the risk is what a compromised one does with the user's
session. `exposed-headers=*` in Chromium exposed `X-Auth-Token` only to a
request without credentials, so it is LOW with or without them.

E1: an origin whose placeholder resolves empty allows no origin (the app
sent no CORS headers), so SCG005 resolves the origin keys first and counts
the origins they yield; a value of only blanks or commas is silent too; a
placeholder without a default still counts as an origin, since it may be set
at runtime. M4: an explicit list of methods lets DELETE through with
credentials, but it is not reported: listing the methods clients need is the
fix the `*` finding asks for. T1: Spring sends any header listed in
`exposed-headers` in `Access-Control-Expose-Headers`, the same mechanism by
which Chromium exposed `X-Auth-Token` (H4; Chromium was not run with
`X-Access-Token`); a header whose name suggests a token or a session
(`authorization`, `token`, `jwt`, `session`, `secret`, `apikey`, ignoring
`-` and `_`) is INFO, since whether it carries one depends on the
application. M5 and B1 have no SCG result: they measure Spring, not a
configuration SCG tells apart. The only files among the reference projects
that set these keys are three `src/test` resources in `spring-boot`, which
SCG doesn't scan (ADR-006).

## SCG006 key matching (Spring Boot 4.1.1 metadata)

Which keys SCG006 treats as secrets is checked against the configuration
metadata of Spring Boot 4.1.1's 97 modules (2650 properties in 96 of them,
plus `spring-boot-webflux`'s 24, none of which names a secret), plus a
hand-built set of 30 keys: 20 non-secrets, native and third-party, 6
secrets as controls, and 4 secrets whose key doesn't end in the word.

A pattern (`password`, `secret`, `token`, `credential`, ...) found
anywhere in a key isn't enough: a namespace, a map key, a nested object or
a package name can contain the word. The 20 non-secrets are such keys,
native properties among them:

* `spring.security.oauth2.authorizationserver.client.<id>.token.*`
  (`access-token-time-to-live=5m`, `id-token-signature-algorithm=RS256`, and
  three more), `spring.security.oauth2.resourceserver.opaquetoken.client-id`,
  `spring.datasource.hikari.credentials-provider-class-name`,
  `spring.ldap.embedded.credential.username`;
* `logging.level.org.springframework.security.oauth2.server.authorization.token=DEBUG`;
* `spring.cloud.kubernetes.secrets.namespace`,
  `spring.cloud.gcp.secretmanager.project-id`, a Spring Cloud Stream binding
  named `tokenEvents`, `app.jwt.token-prefix=Bearer`.

A custom key is HIGH only when it ends in a pattern, and
`logging.level`/`logging.group` are skipped. A key that only contains a
pattern is INFO, which never fails a build on its own (checked: exit 0 with
`--fail-on=LOW`): it may still name a secret, so it stays visible instead of
being silenced.

|  | SCG |
|---|---|
|  20 non-secrets | 1 HIGH, 15 INFO, 4 silent  |
|  6 secrets (controls) | 6 HIGH  |
|  4 secrets named with the word before another one, in the plural, or behind a placeholder default (`app.secret-key-base`, `app.password-hash`, `app.api-keys`, `app.token-value`) | 4 INFO  |

The one HIGH is `server.ssl.certificate-private-key=/etc/tls/server.key` (a
plain path; accepted, see the rule's Javadoc); the 4 silent ones are the 2
`logging.level` keys, a boolean and a number. Against the metadata, 4
native properties are INFO, none of them a secret (`api-token-type`,
`credentials-provider-class-name`, `embedded.credential.username`,
`opaquetoken.client-id`), and so are the 6 non-boolean fields of
`spring.security.oauth2.authorizationserver.client.<id>.token`, which the
metadata doesn't list since they sit inside a map; every native secret is
HIGH. In the reference projects, the 65 HIGH SCG006 findings are all on
keys ending in a pattern, and no key there only contains one with a value
that could be a secret.

Where SCG006 stays silent was reviewed case by case (CLAUDE.md,
"Findings"):

* A key containing a pattern but ending in `-uri`/`-url`/`-endpoint`
  (`token-uri`) has its URL checked: a password in the user-info is HIGH
  (reported by SCG007, ADR-011), a query string INFO, a plain URL or path
  silent. A secret in the path itself (a webhook URL) stays silent, an
  accepted limitation.
* A `classpath:` value in a key naming secret material is INFO: the
  material is packaged inside the jar, usually committed. `file:` is
  silent. A certificate or its location is silent too
  (`public-material-suffixes`), since a certificate is public: without
  that, SAML's `...credentials[0].certificate-location` would give 4 INFO
  in `spring-boot`.
* A boolean written as `true`, `false`, `on`, `yes`, `off` or `no` in a key
  ending in a pattern (`management.endpoints.web.cors.allow-credentials:
  on`) is a switch, since Spring's `StringToBooleanConverter` reads all of
  them, and is silent. `1` and `0`, which Spring also reads as booleans,
  are reported in such a key, as a numeric secret.

On 6 more hand-built keys, `https://svc:s3cr3t@...` in
`app.security.token-url` is HIGH, a `?token=` query and
`classpath:certs/server.key` in a `private-key` are INFO, and a webhook
URL, a GitHub `token-uri` and a SAML `certificate-location` are silent. Of
the 13 INFO SCG006 findings in `spring-boot`, 6 are private keys packaged
with an application: the `spring.ssl.bundle.pem.*.keystore.private-key` of
the two SNI integration test apps (4) and the SAML smoke test's
`private-key-location` (2); the other 7 are OAuth2 client secrets from a
placeholder without a default.

Native secrets no pattern matches were searched for: every metadata
property with no SCG006 finding whose name contains `pass`, `pwd`,
`secret`, `token`, `cred`, `key`, `auth`, `cert`, `private`, `jaas`,
`sasl`, `license`, `ticket`, `headers` or `signature` was read (146 names,
most of them types, aliases, locations, URIs or timeouts). Eight are
secrets: `spring.kafka.ssl.key-store-key` and its `admin`, `consumer`,
`producer` and `streams` variants (a PEM private key, by the metadata's own
description), `spring.neo4j.authentication.kerberos-ticket`,
`spring.liquibase.license-key` and
`management.datadog.metrics.export.application-key`. They are
`high-risk-keys`, a list holding only keys that exist in Spring Boot
4.1.1: HIGH for a written value, INFO for a blank value, a `classpath:`
value or an unresolved placeholder. `HardcodedSecretsRuleTest` pins these
cases.

Left open (`BACKLOG.md`): the OTLP `headers` maps
(`management.otlp.metrics.export.headers`,
`management.opentelemetry.tracing.export.otlp.headers` and
`management.opentelemetry.logging.export.otlp.headers`) can hold a
credential. An entry named after a pattern (`headers.api-key`) is HIGH, but
`headers.Authorization` and vendor headers such as `X-Honeycomb-Team` are
silent.

## SCG007 credential forms (JDBC drivers and kafka-clients)

Which credential forms a connection string or JAAS configuration can carry
was checked against the clients that read them, in the versions Spring
Boot 4.1.1's dependency management resolves: each JDBC driver's own URL
parser (or, for H2, a database created with the URL's password, which then
rejected any other), and kafka-clients 4.2.1's `JaasConfig`.

| # | Value | Read by | SCG |
|---|---|---|---|
| c01 | `jdbc:mysql://app:s3cr3t@db/app` | MySQL | HIGH |
| c02 | `jdbc:postgresql://db/app?user=app&password=s3cr3t` | PostgreSQL (rejects the user-info form) | HIGH |
| c03 | `jdbc:mysql://db/app?user=app&password=s3cr3t` | MySQL, MariaDB | HIGH |
| c04 | `jdbc:sqlserver://db;user=sa;password=s3cr3t` | SQL Server | HIGH |
| c05 | `jdbc:h2:mem:app;USER=sa;PASSWORD=s3cr3t` | H2 | HIGH |
| c06 | `jdbc:oracle:thin:scott/s3cr3t@db:1521/orcl` | Oracle | HIGH |
| c07 | `jdbc:mysql://db:3306/app?serverTimezone=UTC` | no credential | silent |
| c08 | `jdbc:postgresql://db:5432/app?ApplicationName=a@b` | no credential | silent |
| c09 | `spring.data.redis.url=redis://user:s3cr3t@...` | Spring Boot 4 name | HIGH |
| c10 | `spring.mongodb.uri=mongodb://app:s3cr3t@...` | Spring Boot 4 name | HIGH |
| c11 | `spring.flyway.url` with user-info | JDBC | HIGH |
| c12 | `spring.datasource.hikari.jdbc-url` with user-info | JDBC | HIGH |
| c13 | `spring.elasticsearch.uris`, credential in the 2nd node |  | HIGH |
| c14 | JAAS `password=s3cr3t`, unquoted | Kafka | HIGH |
| c15 | JAAS OAuthBearer `clientSecret="s3cr3t"` | Kafka (deprecated option, still read) | HIGH |
| c16 | `spring.kafka.consumer.properties.sasl.jaas.config` | Kafka per-client map | HIGH |
| c17 | `spring.kafka.jaas.options.password` | a map entry | SCG006 HIGH |

SCG007 detects these forms in every property by the value's shape
(ADR-011); `HardcodedSecretsRuleTest` and
`EmbeddedConnectionCredentialsRuleTest` pin them, plus `spring.cloud.config.uri`
and Eureka's `defaultZone` with user-info. The client versions checked
were MySQL Connector/J 9.7.0, PostgreSQL 42.7.13, MariaDB 3.5.10, SQL
Server 13.4.0, H2 2.4.240, Oracle 23.26 and kafka-clients 4.2.1.

Connector/J also reads a password from a MySQL host specification, after
`(` or `,` (`jdbc:mysql://(host=db,user=app,password=s3cr3t)/app`,
`jdbc:mysql://address=(host=db)(password=s3cr3t)/app`, in any `jdbc:mysql`
sub-protocol, the key in any case): HIGH. These forms, not checked against
their clients, are reported HIGH too: Redis with a password and no user
(`redis://:s3cr3t@`) and `rediss://`, `mongodb+srv://`, R2DBC, RabbitMQ
`amqp://`/`amqps://` (also in a list), SQL Server `password={...}`, Oracle
`@//host`, `?PASSWORD=` in upper case, MariaDB user-info and a SCRAM JAAS
configuration; kafka-clients' replacement for `clientSecret`,
`sasl.oauthbearer.client.credentials.client.secret`, is HIGH through
SCG006.

## SCG008 SpringDoc scenarios (running Spring Boot 4.1.1 app)

What each SpringDoc flag turns off was checked in a running app. Method, to
reproduce: a minimal Spring Boot 4.1.1 app with
`spring-boot-starter-webmvc`, `springdoc-openapi-starter-webmvc-ui` 3.1.1
(the line for Spring Boot 4) and one `@RestController` (`GET
/api/orders/{id}`); each scenario starts it with the flags as command-line
arguments, waits until the previous run has released the port and the new
one has logged `Started`, and requests `/v3/api-docs` (checking that it
lists `/api/orders/{id}`), `/swagger-ui/index.html` and `/swagger-ui.html`
(reproducible with `spring-env-benchmark/springdoc-scenarios.sh`).

| # | Flags | `/v3/api-docs` | Swagger UI | SCG |
|---|---|---|---|---|
| S1 | none (defaults) | 200, lists the API | 200 | silent |
| S2 | `api-docs.enabled=false` | 404 | 404 | silent |
| S9 | `api-docs.enabled=FALSE` | 404 | 404 | silent |
| S11 | `api-docs.enabled=false`, `swagger-ui.enabled=true` | 404 | 404 | silent |
| S3 | `swagger-ui.enabled=false` | 200, lists the API | 404 | MEDIUM |
| S4 | both `false` | 404 | 404 | silent |
| S5–S7 | `api-docs.enabled=off`, `no`, `0` | 200, lists the API | 200 | MEDIUM |
| S8 | `swagger-ui.path=/docs` | 200, lists the API | 200 (at `/docs`) | MEDIUM |
| P1 | `api-docs.enabled=false`, `swagger-ui.enabled=${X}` | (off, as S2) |  | silent |
| P2 | `api-docs.enabled=${X}` | decided at runtime |  | INFO |
| P3 | `swagger-ui.enabled=${X}` | 200 (only the UI depends on `X`) |  | MEDIUM |

`springdoc.api-docs.enabled=false` turns SpringDoc off entirely, the UI
included even when it is explicitly enabled; only `false`, in any case,
disables (SpringDoc reads the flags through `@ConditionalOnProperty`, so
`off`, `no` and `0` don't). P1–P3 follow from that and weren't run
separately: once `api-docs` is off nothing is served, and while it is on
the spec is served whatever `swagger-ui` says.

Split across config locations (ADR-005), checked with fixtures: the UI
path in `src/main/resources` and `api-docs.enabled=false` in `config/`
(Spring: all off) leaves one MEDIUM in `src/main/resources`, a false
positive the multi-location coverage warning surfaces; `api-docs.enabled=false`
in `src/main/resources` overridden by `true` in `config/` (Spring: on)
leaves one MEDIUM in `config/`, correct. SCG008 can't miss a split risk:
re-enabling SpringDoc takes a `springdoc.*` key, which triggers the rule in
that location.

## SCG009 verbose logging scenarios (running Spring Boot 4.1.1 app)

What each logging setting writes to the application log was checked in an
app with Spring MVC, JdbcTemplate and JPA on H2, and a RestClient on Apache
HttpClient 5. It receives one request with a secret in each place a log can
pick up, reproducible with `spring-env-benchmark/verbose-logging-scenarios.sh`,
run twice with the same results. Q = query string, H = inbound
Authorization header, B = inbound body, S = JdbcTemplate bound parameter,
J = JPA bound parameter, O = outbound Authorization header, D = outbound
body. Values are command-line arguments unless noted.

|  # | Configuration | Secrets in the log | SCG |
|---|---|---|---|
|  L0 | defaults | none | silent  |
|  L1 | `debug=true` | Q B D | MEDIUM  |
|  L2, P4 | `debug=false`, `debug=${UNSET_VAR:false}` | none | silent  |
|  L3–L7 | `debug=FALSE`, `off`, `no`, `0`, empty | Q B D | MEDIUM  |
|  P2 | `debug=false ` (trailing space, `.properties`) | Q B D | MEDIUM  |
|  P3 | `debug=${UNSET_VAR:}` | Q B D | MEDIUM  |
|  L8, L9 | `trace=true`, `trace=off` | Q B S D | MEDIUM  |
|  Y1, Y2 | YAML `debug: off`, `debug: no`, unquoted | none | silent  |
|  Y3 | YAML `debug: "off"`, quoted | Q B D | MEDIUM  |
|  Y4, Y5 | YAML `debug:` and `debug: ~` (null) in a base file | Q B D | MEDIUM  |
|  P1 | `DEBUG=true` in a `.properties` file | Q B D | MEDIUM  |
|  R1, R3 | `logging.level.root=DEBUG` (or `debug`) | Q B O D | MEDIUM  |
|  R2 | `logging.level.root=TRACE` | Q H B S J O D | MEDIUM  |
|  R4 | `logging.level.root=INFO` | none | silent  |
|  R5, R6 | `logging.level.root=ALL`, `true` | app did not start | silent  |
|  N1, N7, N8 | `web`, `org.springframework.web`, `org.springframework` at `debug` | Q B D | MEDIUM  |
|  N9 | `org=debug` | Q B O D | MEDIUM  |
|  N3 | `org.springframework=trace` | Q B S D | MEDIUM  |
|  N10, N11 | `sql`, `org.springframework.jdbc.core` at `trace` | S | MEDIUM  |
|  N4, N12 | `org.hibernate.orm.jdbc.bind`, `org.hibernate` at `trace` | J | MEDIUM  |
|  N5, N13 | `org.apache.hc.client5.http.wire`, `org.apache.hc` at `debug` | O D | MEDIUM  |
|  N2 | `sql=debug` | none (SQL without its parameters) | INFO  |
|  N14 | `org.apache.hc=info` | none | silent  |
|  N6 | `spring.mvc.log-request-details=true`, `web=debug` | Q B D | MEDIUM  |
|  N15 | `org.springframework.web.servlet.DispatcherServlet=debug` | Q | MEDIUM  |
|  N16 | `...mvc.method.annotation.RequestResponseBodyMethodProcessor=debug` | B D | MEDIUM  |
|  N17 | `org.springframework.web.client.DefaultRestClient=debug` | D | MEDIUM  |
|  N18 | `org.springframework.web.method.HandlerMethod=trace` | Q B D | MEDIUM  |
|  N19 | `org.springframework.jdbc.core.StatementCreatorUtils=trace` | S | MEDIUM  |
|  N20 | `org.hibernate.orm.resource.registry=trace` | J | MEDIUM  |
|  N21 | `org.apache.hc.client5.http.headers=debug` | O | MEDIUM  |
|  N22, N24 | `org.apache.coyote.http11.Http11InputBuffer`, `org.apache.tomcat.util.http.Parameters` at `debug` | none | INFO  |
|  N23 | `org.apache.coyote.http11.Http11InputBuffer=trace` | Q H B O D (the raw requests) | MEDIUM  |
|  N25 | `org=debug`, with `org.springframework.web` and `org.apache.hc` at `info` | none | INFO  |
|  N26 | `ORG.SPRINGFRAMEWORK.WEB=debug` | none: logger names are case-sensitive | INFO  |

Spring Boot's `LoggingApplicationListener` reads `debug` and `trace` as raw
strings and turns them on for any value except exactly `false`, so every
other spelling of "off" turns debug logging on (L3–L7, P2, P3, Y3).
Unquoted YAML `off` and `no` are YAML booleans and stay off. A YAML null is
read as an empty value and turns it on too (Y4, Y5): Spring Boot's YAML
loader turns a null into an empty string, so the key is present, and
`ProfileMerger` keeps it as an empty string, in the base and in a profile
that overrides a key with null (checked through `/actuator/env`,
"ProfileMerger correctness benchmark", case 4).

The secrets were written by the loggers of N15–N21 and N23, each turned on
alone, and by their ancestors (N1, N3–N5, N7–N13); a more specific logger
with its own level decides for its descendants (N25), and logger names are
matched as written (N26). The rule reports at MEDIUM one of those loggers,
an ancestor of one, or Spring Boot's `web` or `sql` group containing one,
when its level reaches it and no more specific configured logger stands in
between, and any other logger at `DEBUG`/`TRACE` as INFO, since what it
writes can't be known statically (N2, N22, N24 wrote none of the secrets).
Severity stays MEDIUM: the secrets reach whoever reads the log.

In the reference projects: `spring-boot`'s `debug=true` is MEDIUM, and 5
loggers are INFO (`org.hibernate.SQL`, `org.springframework.security`,
`org.springframework.integration.file`, Spring Boot's `AuditListener` and
`org.thymeleaf` at `DEBUG`/`TRACE`); `spring-boot-admin` has 1 MEDIUM
(`org.springframework.web=debug`) and 1 INFO (`de.codecentric=trace`);
`spring-cloud-stream-samples` has 1 INFO
(`org.springframework.kafka.config=debug`).

## SCG010 error response scenarios (running Spring Boot 4.1.1 and 3.5.16 apps)

What each error property adds to an HTTP error response was checked in
three small apps with an endpoint that throws an exception and one that
fails binding a request parameter: Spring MVC and WebFlux on Spring Boot
4.1.1, and Spring MVC on Spring Boot 3.5.16. It is reproducible with
`spring-env-benchmark/error-response-scenarios.sh`, run twice with the same
results. T = stack trace, E = exception class name, M = the exception's
message, B = binding errors; with `on-param`, what a request adding the
`trace`, `message` or `errors` parameter gets. Unless noted, keys are
`spring.web.error.*` on Spring MVC 4.1.1.

|  # | Configuration | Spring Boot | SCG |
|---|---|---|---|
|  D0, F0, T0 | defaults (no key) | nothing | silent  |
|  S1, S6 | `include-stacktrace=always` (or `ALWAYS`) | T on every error | MEDIUM  |
|  S2–S5 | `include-stacktrace=on-param` (or `onParam`, `ON_PARAM`, `on.param`) | T with `?trace`, any value but `false` (in any case) | MEDIUM  |
|  S7, S8 | `include-stacktrace=never`, or empty | nothing | silent  |
|  S9–S11 | `include-stacktrace=true`, `on`, `sometimes` | app did not start | silent  |
|  X1–X4 | `include-exception=true`, `on`, `YES`, `1` | E on every error | MEDIUM  |
|  X5 | `include-exception=false` | nothing | silent  |
|  X6, X7 | `include-exception=always`, or empty | app did not start | silent  |
|  M1, M2 | `include-message=always`, `on-param` | M (with `?message`) | MEDIUM  |
|  B1, B2 | `include-binding-errors=always`, `on-param` | B (with `?errors`) | MEDIUM  |
|  Y1 | YAML `include-exception: on`, unquoted | E (YAML reads `on` as true) | MEDIUM  |
|  Y2 | YAML `include-stacktrace: on`, unquoted | app did not start | silent  |
|  F1–F3 | WebFlux, the same keys | the same as Spring MVC | as Spring MVC  |
|  O1, O2, F4 | `server.error.*` on 4.1.1: `include-stacktrace=always`; all four set | nothing: no longer bound | MEDIUM; MEDIUM ×4  |
|  T1, T2 | `server.error.*` on 3.5.16: all four set; `include-stacktrace=on-param` | T, E, M, B; T with `?trace` | MEDIUM ×4; MEDIUM  |
|  T3 | `spring.web.error.*`, all four set, on 3.5.16 | nothing: not bound yet | MEDIUM ×4  |

Each prefix is read by one side of Spring Boot 4.0 only: 4.1.1's
configuration metadata marks every `server.error.*` key deprecated at level
`error` since 4.0.0 (no longer bound), and O1, O2, F4 and T3 show each
prefix ignored by the other version. SCG doesn't know the version a project
targets, so both prefixes are reported at the same severity, and every
message says which version reads which prefix and that removing the key is
the fix where it is inert; reporting both as INFO would hide the key that
takes effect. `include-stacktrace` is MEDIUM, not HIGH: a stack trace
carries the exception's message and its cause chain (S1), so it discloses
more of what `include-message` does, which is information disclosure
without compromise (MEDIUM), not a different risk. A value Spring Boot
can't bind stops the application from starting (S9–S11, X6, X7, Y2), so
the rule's silence on it is proven. None of the reference projects sets
these keys.

## SCG011 transport scenarios (running Spring Boot 4.1.1 apps)

What each server transport key does was checked in running apps. Method, to
reproduce: a minimal Spring Boot 4.1.1 app with
`spring-boot-starter-webmvc`, `spring-boot-starter-actuator` and one
endpoint that creates a session, built three times: on Tomcat (the default),
on Jetty, and on Tomcat with Spring Session (`spring-boot-session`,
`@EnableSpringHttpSession` with an in-memory `MapSessionRepository`); plus a
WebFlux app (`spring-boot-starter-webflux`, Netty) whose endpoint touches
the `WebSession`. A self-signed PKCS#12 key-store and the same key as PEM
files serve as TLS material. Each scenario starts one app with the
properties as command-line arguments on port 9443 (a separate management
port, when set, is 9444), waits until the previous run has released both
ports and the new one has logged Spring Boot's `Started ... in` line (or
failed), then requests the session endpoint and `/actuator/health` over
HTTPS, falling back to HTTP, and records the scheme each port answers on and
the session cookie's attributes (reproducible with
`spring-env-benchmark/server-transport-scenarios.sh`, which generates the
TLS material on its first run).

Server and management SSL (Tomcat):

|  # | Properties | Spring 4.1.1 | SCG |
|---|---|---|---|
|  T1–T5 | `key-store`, `enabled=false` / `off` / `no` / `0` / `FALSE` | HTTP | HIGH  |
|  T6 | `key-store`, `enabled=disabled` | does not start | silent  |
|  T7 | `key-store`, `enabled=` or `${X:}` | does not start (`Failed to bind properties under 'server.ssl.enabled' to boolean`) | silent  |
|  T8 | PEM `certificate` + `certificate-private-key`, `enabled=false` | HTTP | HIGH  |
|  T9 | PEM `certificate` + `certificate-private-key` | HTTPS | silent  |
|  T10 | `bundle` (a JKS SSL bundle), `enabled=false` | HTTP | HIGH  |
|  T11 | `bundle` | HTTPS | silent  |
|  T12 | `enabled=false`, no TLS material | HTTP | silent  |
|  M1 | `server.ssl.key-store`, `management.server.port=9444` | management HTTPS (inherits `server.ssl`) | silent  |
|  M2 | M1 + `management.server.ssl.enabled=false` | main HTTPS, management HTTP | HIGH  |
|  M3 | `management.server.port=9444`, `management.server.ssl.key-store`, `management.server.ssl.enabled=false` | management HTTP | HIGH  |
|  M4 | `management.server.port=9444`, `management.server.ssl.key-store` | management HTTPS | silent  |
|  M5 | M3 with `management.server.port=-1` | management server off | silent  |
|  M6 | `server.ssl.key-store`, `management.server.port=9443` (= `server.port`), `management.server.ssl.key-store`, `management.server.ssl.enabled=false` | one HTTPS connector, `management.server.ssl.*` ignored | silent  |

M5 and M6 follow `ManagementPortType.get()`: a negative management port
disables the management server, and a port equal to `server.port` (or to
8080 when `server.port` is not set) shares the main connector. A management
connector of its own takes `management.server.ssl.*` when that is set
(`ManagementWebServerFactoryCustomizer`), so M2's `enabled=false` without a
management key-store turns TLS off on it. The falsy values that disable SSL
(`false`, `off`, `no`, `0`, any case) are the ones the rule matches.

Session cookie, servlet keys (`server.servlet.session.cookie.*`); the cookie
attributes each app set:

|  # | Properties | Tomcat | Jetty | Spring Session | SCG |
|---|---|---|---|---|---|
|  K0 | TLS, defaults | `Secure; HttpOnly` | `Secure` | `Secure; HttpOnly; SameSite=Lax` | silent  |
|  K1/K2 | TLS, `secure=false` / `off` | `Secure; HttpOnly` | `Secure` | `HttpOnly; SameSite=Lax` | MEDIUM  |
|  K3 | HTTP, `http-only=false` | (none) | (none) | `SameSite=Lax` | MEDIUM  |
|  K4/K5 | HTTP, `same-site=None` / `none` | `HttpOnly; SameSite=None` | `SameSite=None` | `HttpOnly; SameSite=None` | MEDIUM  |
|  K6 | HTTP, defaults | `HttpOnly` | (none) | `HttpOnly; SameSite=Lax` | silent  |
|  K7 | TLS, `same-site=None`, `secure=false` | `Secure; HttpOnly; SameSite=None` | `Secure; SameSite=None` | `HttpOnly; SameSite=None` | MEDIUM + MEDIUM  |

Tomcat and Jetty mark their session cookie `Secure` on every HTTPS request,
whatever `secure` says; only Spring Session drops it. Jetty's session cookie
carries no `HttpOnly` even by default, so K3 changes nothing there. The
script waits for Spring Boot's `Started ... in` line, not any `Started `
line: Jetty logs its own before its connector is up, and Jetty rows waited
for that one failed at random.

Session cookie, WebFlux (`server.reactive.session.cookie.*`):

|  # | Properties | WebFlux (Netty) | SCG |
|---|---|---|---|
|  R0 | TLS, defaults | `Secure; HttpOnly` | silent  |
|  R1 | TLS, `secure=false` | `HttpOnly` | MEDIUM  |
|  R2 | HTTP, `http-only=false` | (none) | MEDIUM  |
|  R3 | HTTP, `same-site=None` | `HttpOnly; SameSite=None` | MEDIUM  |
|  R4 | TLS, `server.servlet.session.cookie.secure=false` and `http-only=false` | `Secure; HttpOnly` (no effect) | MEDIUM ×2  |

The cookie checks are MEDIUM: none exposes the cookie's value without a
second weakness (a plain HTTP request, an XSS, a cross-site request). K1/K2
on Tomcat or Jetty and R4 are findings for a key without effect: SCG doesn't
see the classpath, so it can't tell them from Spring Session's K1/K2 or a
servlet app's R4 keys, and the message of the servlet `secure` finding says
the key only takes effect with Spring Session.

Split across config locations (ADR-005), checked with fixtures, each with the
coverage warning on stderr:

|  # | `src/main/resources` | `config/` | Spring | SCG |
|---|---|---|---|---|
|  L1 | `server.ssl.key-store` | `application-prod.yml`: `enabled: false` | HTTP in `prod` | silent (false negative)  |
|  L1b | `server.ssl.key-store` | `application.yml`: `enabled: false` | HTTP | silent (false negative)  |
|  L2 | `key-store`, `enabled: false` | `application-prod.yml`: `enabled: true` | HTTP, HTTPS in `prod` | HIGH in the base profile (correct)  |
|  L2b | `key-store`, `enabled: false` | `application.yml`: `enabled: true` | HTTPS | HIGH (false positive)  |
|  L3 | `management.server.port: 9444` | `application-prod.yml`: management `key-store`, `enabled: false` | management HTTP in `prod` | silent (false negative)  |
|  L4 | management port, `key-store`, `enabled: false` | `application-prod.yml`: `port: -1` | management HTTP, off in `prod` | HIGH in the base profile (correct)  |

None of the reference projects has an SCG011 finding. Left open
(BACKLOG.md): weak TLS protocols
(`server.ssl.enabled-protocols`, `server.ssl.protocol`) and
`server.servlet.session.tracking-modes=url`, silent today.

## SCG012 driver modes (JDBC drivers and Spring Boot's Redis configuration)

Which values turn TLS off, or keep it on without checking the server's
certificate, was read from the drivers Spring Boot 4.1.1's dependency
management resolves: pgjdbc 42.7.13 (`SslMode.requireEncryption()` and
`verifyCertificate()` for each mode), MySQL Connector/J 9.7 (the `sslMode`
property description), mssql-jdbc 13.4 (`EncryptOption.valueOfString`) and
MariaDB Connector/J 3.5 (`SslMode.from`).

* No encryption: PostgreSQL `sslmode=disable`/`allow` (and the default
  `prefer` doesn't require it), MySQL `sslMode=DISABLED`, SQL Server
  `encrypt=false`, `no` and `optional`, MariaDB `sslMode=disable`, `false`
  and `0`; MySQL's legacy `useSSL=false`, still accepted and translated to
  `sslMode=DISABLED`; R2DBC `sslMode=disable`.
* Encryption without certificate validation: PostgreSQL `sslmode=require`,
  MySQL `sslMode=REQUIRED`, MariaDB `sslMode=trust` (its TLS plugin then
  installs `MariaDbX509TrustingManager`, whose `checkServerTrusted` accepts
  any certificate), pgjdbc's
  `sslfactory=org.postgresql.ssl.NonValidatingFactory` (whose trust
  manager's `checkServerTrusted` is empty, too); only
  `verify-ca`/`verify-full` (MySQL `VERIFY_CA`/`VERIFY_IDENTITY`) check it.
* Redis: Spring Boot 4.1.1's Lettuce and Jedis configurations enable TLS
  when `spring.data.redis.ssl.enabled` is true or the URL is `rediss://`,
  so a `redis://` URL alone doesn't prove plaintext.

|  # | Value | SCG |
|---|---|---|
|  t01 | `spring.datasource.url` `?sslmode=disable` | HIGH  |
|  t02 | `spring.mongodb.uri` `?tls=false` | HIGH  |
|  t03 | `spring.data.redis.url=redis://...` | silent  |
|  t04 | `spring.flyway.url` `?sslmode=disable` | HIGH  |
|  t05 | `spring.datasource.hikari.jdbc-url` `?sslMode=DISABLED` | HIGH  |
|  t06 | `spring.artemis.broker-url=tcp://...` | silent  |
|  t07 | SQL Server `encrypt=optional` | HIGH  |
|  t08 | SQL Server `encrypt=no` | HIGH  |
|  t09 | MariaDB `sslMode=false` | HIGH  |
|  t10 | MariaDB `sslMode=trust` | MEDIUM  |
|  t11 | PostgreSQL `sslmode=require` | MEDIUM  |
|  t12 | MySQL `sslMode=REQUIRED` | MEDIUM  |
|  t13 | `spring.elasticsearch.uris=https://es1,http://es2` | HIGH  |
|  t14 | PostgreSQL `sslmode=verify-full` | silent  |

The query parameters are looked for in every property whose value starts
with `jdbc:`, `r2dbc:`, `mongodb:` or `mongodb+srv:`, which covers t02, t04
and t05 whatever the key; the scheme check (`http://`, `tcp://`,
`amqp://`, `ldap://`) is limited to the known connection keys, with Spring
Boot 4.1.1's names, and checks every node of a list (t13). No encryption
is HIGH. Encryption without certificate validation is MEDIUM, including
`verifyServerCertificate=false` and the other parameters listed above: the
traffic is encrypted and reading it takes an active man in the middle.
Left open (BACKLOG.md): t03, t06, the default modes, an explicit
`sslmode=prefer` (silent), MySQL `requireSSL=false` (translated to
`PREFERRED`, yet HIGH), and the transports SCG012 doesn't look at (Neo4j,
Cassandra, Pulsar, Couchbase).

## SCG013 health details scenarios (running Spring Boot 4.1.1 apps)

What `/actuator/health` returns for each health setting was checked in two
apps with Spring MVC, Actuator and an H2 datasource, one without Spring
Security and one with it (every request permitted, one HTTP Basic user with
role USER), reproducible with
`spring-env-benchmark/health-details-scenarios.sh`, run twice with the same
results. "details" is every component with its details (the database vendor,
diskSpace's absolute path and free space, the SSL chains), "components"
their names and status only, "status" the overall status only. Keys are
under `management.endpoint.health`; the group is `group.custom`, including
`db`.

|  # | Configuration | Response | SCG |
|---|---|---|---|
|  D0, D5 | defaults, `show-details=never` | status | silent  |
|  S0, S1 | Spring Security: defaults, `show-details=always` | anonymous and user: status, details | silent, MEDIUM  |
|  D1, D7 | `show-details=always` (or `ALWAYS`) | details | MEDIUM  |
|  D2–D4 | `show-details=when-authorized` (or `WHEN_AUTHORIZED`, `whenAuthorized`), no Spring Security | status | INFO  |
|  S2 | `show-details=when-authorized`, Spring Security | anonymous: status; user: details | INFO  |
|  S3 | S2 with `roles=ADMIN` | anonymous and user: status | INFO  |
|  D6 | `show-details=true` | app did not start | silent  |
|  C1 | `show-components=always` | components | INFO  |
|  S4 | `show-components=when-authorized`, Spring Security | anonymous: status; user: components | INFO  |
|  C2 | `show-components=never`, `show-details=always` | status | silent  |
|  G1, G2 | group `show-details=always`: the group, the endpoint | details, status | MEDIUM  |
|  G3 | group `show-components=always` | components | INFO  |
|  G4 | G1 with `additional-path=server:/healthz` | `/healthz`: details | MEDIUM  |
|  G5 | `show-details=always`, the group without its own | details | MEDIUM (endpoint)  |
|  G7 | `show-details=always`, group `show-details=` (empty) | details | MEDIUM (endpoint)  |
|  G6 | `show-details=always`, group `show-components=never` | group: status | MEDIUM (endpoint)  |
|  S5 | group `show-details=when-authorized`, Spring Security | anonymous: status; user: details | INFO  |
|  X1, X2 | `show-details=always` with `access=none`, or health excluded from exposure | 404 | MEDIUM  |

`when-authorized` returned nothing extra to an anonymous caller, with or
without Spring Security; only an authenticated user got the details, and
`roles` narrowed that further (D2, S2, S3), so it is INFO, as is
`show-components` alone, which returned names and status without details
(C1, S4). `show-components` defaults to `show-details`, and at `never` it
hid the details too (C2), so the lower of the two decides. A health group
has its own keys, falls back to the endpoint's for those it doesn't set or
sets to an empty value (G5–G7), and is served at `/actuator/health/<name>`
and at its `additional-path`, which can be on the main server port
(G1–G4); a group is reported when it sets one of the keys itself, as the
`comp` group of `spring-boot`'s Actuator smoke test
(`group.comp.show-details=always`, MEDIUM) does. X1 and X2 are the rule's
documented scope decision: health details are reported even where the
endpoint isn't reachable.

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

SCG014 resolves the protocol per client in that order, so an insecure
value overridden by a secure one isn't reported:

|  Scenario | Spring's result | SCG |
|---|---|---|
|  P1 common typed `PLAINTEXT`, common map `SSL` | `SSL` everywhere | none  |
|  P2 common typed `SSL`, common map `PLAINTEXT` | `PLAINTEXT` everywhere | HIGH (map)  |
|  P3 consumer `SSL`, common map `PLAINTEXT` | `PLAINTEXT` for the other clients | HIGH (map)  |
|  P4 consumer typed `PLAINTEXT`, consumer map `SSL` | consumer `SSL`, others unset | MEDIUM  |
|  P5 common `PLAINTEXT`, every client `SSL` | `SSL` everywhere | none  |
|  P6 consumer `SSL` only | others unset | MEDIUM  |
|  P7 consumer, producer, admin `SSL` | streams unset | MEDIUM, naming streams  |

It reports only the keys a client actually uses, once each; inside a named
binder's environment too. An unresolved placeholder overrides what is below it,
since it resolves at runtime or the application doesn't start. The "not
set" finding names the clients left without a protocol, and the streams
client counts even without a `spring.kafka.streams.*` key: a Kafka Streams
application can take its application id from `spring.application.name`.

The program is kept in the repository
(`spring-env-benchmark/kafka-precedence`). Two more scenarios check the
steps of P4 and P3 the other way round, with the insecure value on top: X1
(consumer map `PLAINTEXT` over consumer typed `SSL`) and X2 (consumer typed
`PLAINTEXT` over common map `SSL`) both leave the consumer on `PLAINTEXT`.

```bash
cd spring-env-benchmark
./kafka-precedence-scenarios.sh
```

## SCG015 RabbitMQ transport scenarios (Spring Boot 4.1.1 client, on the wire)

Whether a Spring Boot RabbitMQ client speaks plain AMQP or TLS was checked
on the wire, without a broker: `listener.py` listens on 127.0.0.1:5672 and
5671 and records whether a connection starts with the AMQP protocol header
or a TLS handshake, and an app with `spring-boot-starter-amqp` opens one
connection at startup. Reproducible with
`spring-env-benchmark/rabbit-transport-scenarios.sh`, run twice with the
same results. Keys are under `spring.rabbitmq`; `host` is `127.0.0.1`
unless `addresses` is set. The SCG column is for the same configuration
on a remote host: on the scenario's own
loopback address, a finding there is INFO (see "Loopback addresses in the
transport rules").

|  # | Configuration | On the wire | SCG |
|---|---|---|---|
|  H0 | `host` only | AMQP (5672) | MEDIUM  |
|  H1, H3, H4 | `ssl.enabled=true`, `yes`, `TRUE` | TLS (5671) | silent  |
|  H2 | `ssl.enabled=false` | AMQP (5672) | HIGH  |
|  H5 | `port=5671`, no `ssl.enabled` | AMQP (5671) | MEDIUM  |
|  B1 | `ssl.bundle` set | TLS (5672) | silent  |
|  B2 | `ssl.bundle=${SCG_BUNDLE:}` (resolves empty) | AMQP (5672) | MEDIUM  |
|  B2u | `ssl.bundle=${SCG_BUNDLE}` (no default) | decided at runtime | INFO  |
|  V1 | `ssl.enabled=true`, `ssl.validate-server-certificate=false` | TLS (5671) | silent  |
|  A1 | `addresses=127.0.0.1:5672` | AMQP | MEDIUM  |
|  A2 | `addresses=amqps://...` | TLS | silent  |
|  A3 | `addresses=amqp://...`, `ssl.enabled=true` | AMQP | HIGH (SCG012)  |
|  A4 | `addresses=AMQPS://...` | app did not start | silent  |
|  A5 | `addresses=127.0.0.1:5672`, `ssl.enabled=true` | TLS | silent  |
|  A6 | `addresses=127.0.0.1:5672,amqps://...` | AMQP | MEDIUM  |
|  A7 | `addresses=amqps://...,127.0.0.1:5672` | TLS | silent  |
|  Y1 | YAML `addresses` as a list, `[127.0.0.1:5672]` | AMQP | MEDIUM  |

Spring Boot's `RabbitProperties.Ssl.determineEnabled()` turns TLS on for
`ssl.enabled` true (bound through the Binder, so `yes` too) or an
`ssl.bundle`, and the scheme of the first address, when it has one,
overrides both (A2, A3, A6, A7). An address list written in YAML reaches
the client like a single value (Y1), so the rule reads the list's first
entry. The RabbitMQ Java client
(amqp-client 5.30.0) authenticates with SASL `PLAIN` by default, which sends
the user name and password as they are, so a plain connection carries the
credentials in the clear. V1 is TLS without checking the broker's
certificate, which SCG015 doesn't cover (`BACKLOG.md`, "TLS without
verifying the server").

`determineEnabled()` tests the bundle with `StringUtils.hasText`, so a
placeholder that resolves empty leaves TLS off and the client speaks plain
AMQP (B2). The rule resolves the bundle first: one that resolves empty
counts as unset, and one without a default is INFO unless `ssl.enabled` is
true, since the bundle may be set at runtime. No reference project sets
`spring.rabbitmq.host` or `addresses`.

## SCG016 Vault transport scenarios (Spring Cloud Vault 5.0.2 client, on the wire)

Whether a Spring Cloud Vault client speaks plain HTTP or TLS was checked on
the wire, without a Vault server: `listener.py` listens on 127.0.0.1:8200
and records whether a connection starts with a TLS handshake or a plain
HTTP request, and whether that request carries the Vault token. The app
imports configuration from Vault at startup
(`spring.config.import=optional:vault://`, token authentication). It uses
Spring Cloud 2025.1.3, the latest GA release train, which pins Spring Boot
4.0.8 and Spring Cloud Vault 5.0.2; the train for Spring Boot 4.1 is not
GA yet. Reproducible with `spring-env-benchmark/vault-transport-scenarios.sh`,
run twice with the same results. Keys are under `spring.cloud.vault`. The
SCG column is for the same configuration on a remote host: on the scenario's own
loopback address, a finding there is INFO (see "Loopback addresses in the
transport rules").

|  # | Configuration | On the wire | SCG |
|---|---|---|---|
|  D0 | defaults (`host=127.0.0.1`) | TLS | silent  |
|  S1 | `scheme=http` | HTTP, token in the clear | HIGH  |
|  S2 | `scheme=HTTP` | app did not start | silent  |
|  S3 | `scheme=https` | TLS | silent  |
|  S4 | `scheme=` (empty) | app did not start | silent  |
|  U1 | `uri=http://...` | HTTP, token in the clear | HIGH  |
|  U2 | `uri=https://...` | TLS | silent  |
|  U3 | `uri=https://...`, `scheme=http` | TLS | silent  |
|  U4 | `uri=http://...`, `scheme=https` | HTTP, token in the clear | HIGH  |
|  U5 | `uri=HTTP://...` | app did not start | silent  |
|  U6 | `uri=` (empty), `scheme=http` | HTTP, token in the clear | HIGH  |
|  E1–E5 | `scheme=http`, `enabled=false` (or `FALSE`, `off`, `no`, `0`) | no connection | silent  |

`uri` overrides `scheme` (U3, U4), and an empty `uri` leaves it to `scheme`
(U6). Spring Cloud Vault compares the scheme case-sensitively: `HTTP`,
`HTTP://` and an empty `scheme` stopped the application from starting
("Scheme must be http or https"), so SCG016 is silent on them. `enabled`
set to any false literal turned the client off. No reference project
configures `spring.cloud.vault.*`.

## SCG017 resource server transport scenarios (Spring Boot 4.1.1, on the wire)

Whether a Spring Boot OAuth2 resource server fetches its keys, its OIDC
discovery document and its token introspection over plain HTTP or TLS was
checked on the wire, without an authorization server: `listener.py`
listens on 127.0.0.1:8300 and records whether a connection starts with a
TLS handshake or a plain HTTP request, and whether that request carries the
introspection client secret. The app (Spring Boot 4.1.1, Spring MVC and
`spring-boot-starter-oauth2-resource-server`) receives one request with a
bearer token; the listener serves a generated public key for `.pub` paths.
The response was 401 in every row: the test token is never valid, and
forging one was not attempted. Reproducible with
`spring-env-benchmark/jwt-transport-scenarios.sh`, run twice with the same
results. Keys are under `spring.security.oauth2.resourceserver`. The SCG
column is for the same configuration on a remote host: on the scenario's own
loopback address, a finding there is INFO (see "Loopback addresses in the
transport rules").

|  # | Configuration | On the wire | SCG |
|---|---|---|---|
|  J1 | `jwt.jwk-set-uri=http://...` | HTTP | HIGH  |
|  J2 | `jwt.jwk-set-uri=https://...` | TLS | silent  |
|  J3 | `jwt.jwk-set-uri=HTTP://...` | HTTP | HIGH  |
|  I1 | `jwt.issuer-uri=http://...` | HTTP | HIGH  |
|  I2 | `jwt.issuer-uri=https://...` | TLS | silent  |
|  I3 | `jwt.issuer-uri=HTTP://...` | HTTP | HIGH  |
|  B1 | `jwt.issuer-uri=https://...`, `jwt.jwk-set-uri=http://...` | HTTP | HIGH  |
|  B2 | `jwt.issuer-uri=http://...`, `jwt.jwk-set-uri=https://...` | TLS | silent  |
|  K1 | `jwt.public-key-location=http://...` | HTTP | HIGH  |
|  B3 | `jwt.issuer-uri=http://...`, `jwt.public-key-location=file:...` | HTTP | HIGH  |
|  B4 | `jwt.jwk-set-uri=https://...`, `jwt.public-key-location=http://...` | TLS | silent  |
|  B5 | `jwt.issuer-uri=https://...`, `jwt.public-key-location=http://...` | TLS | silent  |
|  O1 | `opaquetoken.introspection-uri=http://...`, client id and secret | HTTP, secret in the clear | HIGH  |
|  O2 | `opaquetoken.introspection-uri=https://...`, client id and secret | TLS | silent  |

The keys come from the first of `jwk-set-uri`, `issuer-uri` and
`public-key-location` that is set, as Spring Boot's `IssuerUriCondition`
and `KeyValueCondition` state: next to a `jwk-set-uri`, neither
`issuer-uri` (B2) nor `public-key-location` (B4) was fetched; next to an
`issuer-uri`, `public-key-location` wasn't (B5), and `issuer-uri` was
(B3). The rule reports only the key in use. When a key before it is an
unresolved placeholder, which may resolve empty at runtime, an `http://`
value after it is reported as INFO. The application reads
`public-key-location` at startup and started with the key it fetched in
plain HTTP (K1), and `introspection-uri` sent the client secret in the
clear (O1). The scheme is matched in any case (J3, I3). In O1 and O2,
SCG006 also reports the client secret written in the file.

No reference project sets `public-key-location` or `introspection-uri`,
and none sets more than one of the three key sources (checked with a grep
for the four keys, in any of their relaxed forms, whatever their value).
The one SCG017 finding, in `spring-boot`, is `jwk-set-uri:
http://localhost:8080/oauth2/jwks`: INFO, on a loopback address
("Loopback addresses in the transport rules", L13).

## Loopback addresses in the transport rules

Traffic to a loopback address doesn't leave the host, so nobody on the
network can read or alter it. SCG012, SCG014, SCG015, SCG016 and SCG017
report a connection whose hosts are **all** loopback (`localhost`,
127.0.0.0/8, `::1`) as INFO instead of HIGH or MEDIUM, with the reason in
the message. It stays INFO, not silent: a local forwarder (a proxy or
sidecar on the same machine or pod) may relay the traffic in plaintext,
and a client that discovers other nodes from the first one (Kafka's
advertised listeners, a MongoDB replica set) may then connect elsewhere.
`*.localhost` doesn't count: unlike a browser, a server-side client asks
the system resolver, which had no answer for `a.localhost` and so would
ask DNS (`localhost-browser-probe.sh`, "SCG004 insecure origin
scenarios"). A host that isn't written doesn't count either, though
Spring's defaults are `localhost` (Kafka's `localhost:9092`, Vault's
`host`): in deployments it is usually set outside the files. For the same
reason, only a host written literally counts: one from a placeholder, even
with a loopback default (`${RABBIT_HOST:localhost}`), keeps its severity,
since the deployment usually replaces the host and not the insecure
setting next to it (L15). A value is left as it was when its hosts can't
all be read (Oracle's `@host:port:SID` and `@//host` forms, a TNS
descriptor) or don't decide where the client connects: an SRV scheme
(`mongodb+srv://`), looked up in DNS, or a parameter that overrides the
host or routes elsewhere, such as PostgreSQL's `?host=` and SQL Server's
`;serverName=` (both checked in pgjdbc 42.7.4 and mssql-jdbc 12.8.1), a
SOCKS proxy or a failover partner (L14). SCG016 keeps its severity when
Vault is located through service discovery (L16), and SCG017 when the
URI is `issuer-uri`, whose metadata may name keys on another host (L17).

|  # | Rule | Configuration | SCG |
|---|---|---|---|
|  L1 | SCG012 | `spring.datasource.url=jdbc:mysql://localhost:3306/app?useSSL=false` | INFO  |
|  L2 | SCG012 | `jdbc:mysql://localhost,db.internal/app?useSSL=false` | HIGH  |
|  L3 | SCG012 | `jdbc:sqlserver://127.0.0.1;encrypt=false` | INFO  |
|  L4 | SCG012 | `spring.elasticsearch.uris=http://es.localhost:9200` | HIGH  |
|  L5 | SCG014 | `spring.kafka.bootstrap-servers=localhost:9092`, no protocol | INFO  |
|  L6 | SCG014 | L5 plus `spring.kafka.consumer.bootstrap-servers=kafka.internal:9092` | MEDIUM  |
|  L7 | SCG014 | binder `brokers=localhost:9092`, `configuration.security.protocol=SASL_PLAINTEXT` | INFO  |
|  L8 | SCG014 | no broker written, no protocol | MEDIUM  |
|  L9 | SCG015 | `spring.rabbitmq.host=localhost` | INFO  |
|  L10 | SCG015 | `addresses=localhost:5672,rabbit.internal:5672` | MEDIUM  |
|  L11 | SCG016 | `spring.cloud.vault.uri=http://127.0.0.1:8200` | INFO  |
|  L12 | SCG016 | `scheme=http`, `host=localhost` (HIGH without `host`) | INFO  |
|  L13 | SCG017 | `jwk-set-uri=http://localhost:8080/oauth2/jwks` | INFO  |
|  L14 | SCG012 | `jdbc:postgresql://localhost/db?host=prod-db.internal&sslmode=disable` | HIGH  |
|  L15 | SCG015 | `spring.rabbitmq.host=${RABBIT_HOST:localhost}` | MEDIUM  |
|  L16 | SCG016 | L12 plus `discovery.enabled=true` | HIGH  |
|  L17 | SCG017 | `issuer-uri=http://localhost:9000` | HIGH  |

SCG014 counts the brokers across the whole file (`bootstrap-servers`, a
`bootstrap.servers` map entry, a binder's `brokers`, in every context): one
remote address anywhere keeps every finding (L6). SCG015 counts every
entry of `addresses` when it is set, since the client fails over to them,
else `host`.

In the reference projects, 15 findings are INFO for a written loopback
host, from 8 properties: in `spring-petclinic-microservices-config`,
SCG012's `jdbc:mysql://localhost:3306/petclinic?...useSSL=false`, inherited
by its 8 services (HIGH on a remote host); in `spring-boot`, SCG017's
`jwk-set-uri: http://localhost:8080/oauth2/jwks` (HIGH) and one SCG014 on
`bootstrap-servers=localhost:9092` (MEDIUM); in
`spring-cloud-stream-samples`, five SCG014 on binder `brokers` or
`bootstrap-servers` at `localhost` (one HIGH for `SASL_PLAINTEXT`, four
MEDIUM). The demo fixtures that showcase a HIGH use a remote host
(`localstack.dev.internal`, `customers-db`).
