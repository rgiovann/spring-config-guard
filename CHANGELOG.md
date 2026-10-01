# Changelog

Release notes for every version, newest first. Versioning rules, the release
checklist and the notes template are in
[CONTRIBUTING.md](CONTRIBUTING.md#releases).

Each section heading must be exactly `## vX.Y.Z`, matching the tag: the
release workflow publishes that section's body as the GitHub release notes,
and refuses to publish a tag without one.

## v1.7.0

**Added**
- SCG006 checks the URL in a key that contains a secret pattern but ends in
  `-uri`/`-url`/`-endpoint` (`app.security.token-url`), which used to be
  skipped whatever its value: a password in the URL's user-info
  (`https://user:secret@host`) is HIGH, a query string (`?token=...`) is
  INFO. A plain URL or path stays silent; a secret in the path itself (a
  webhook URL) is not detected.
- SCG006 reports a `classpath:` value in a key naming secret material
  (`private-key: classpath:server.key`) as INFO: the material is packaged
  inside the application. It used to be skipped as a mere reference.
  `file:` values are still skipped, and so is a certificate or its location
  (public material).

**Fixed**
- SCG006 matched a secret pattern (`password`, `secret`, `token`,
  `credential`, ...) anywhere in a key, so a namespace, a map key or a
  package name containing the word was reported as HIGH, including Spring
  Boot's own properties: `spring.security.oauth2.authorizationserver.client.<id>.token.access-token-time-to-live=5m`,
  `spring.security.oauth2.resourceserver.opaquetoken.client-id`,
  `logging.level.<package>.token=DEBUG`, `spring.cloud.kubernetes.secrets.namespace`.
  A key is now HIGH only when it ends in a pattern; a key that only
  contains one is INFO, since it may still name a secret
  (`app.secret-key-base`); `logging.level` and `logging.group` are skipped.
  Three `high-risk-keys` absent from Spring Boot 4.1.1 were replaced and 11
  current ones added.
- SCG014 evaluated every `security.protocol` key on its own, so an insecure
  value overridden by a secure one was still reported as HIGH (e.g.
  `spring.kafka.security.protocol=PLAINTEXT` with
  `spring.kafka.properties.security.protocol=SSL`). It now resolves the
  protocol each Kafka client gets as Spring Boot does (client properties
  map, client key, common properties map, common key) and reports only the
  keys a client uses. The "not set" finding names the clients left without
  a protocol, and is no longer raised when every client has its own key.

**Detection changes**
- **Fewer HIGH findings**: SCG006 keys that only contain a secret pattern
  move from HIGH to INFO, and SCG014 no longer reports overridden values.
  With `--fail-on=HIGH`, some builds that failed only on these now pass.
- **New findings**: SCG006 reports a password in a URL's user-info as HIGH,
  and a query string or a `classpath:` secret as INFO, in keys it used to
  skip.
- Measured on 30 hand-built keys and Spring Boot 4.1.1's configuration
  metadata (`VALIDATION.md`, "SCG006 key matching") and on Spring Boot's
  own `KafkaProperties` (`VALIDATION.md`, "SCG014 protocol precedence").
- On the reference corpus, against `v1.6.0`: 6 SCG006 INFO added in
  `spring-boot`, all private keys packaged with an application (the SNI
  integration tests' PEM bundles and the SAML smoke test's
  `private-key-location`); the 3 SCG014 "not set" findings keep their rule,
  severity, file and profile, with new wording. Every other finding and
  coverage warning is identical.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.6.0...v1.7.0`.

## v1.6.0

**Fixed**
- SCG001 now resolves which Actuator endpoints are exposed over HTTP as
  Spring Boot does, checked against a running Spring Boot 4.1.1 app in 18
  configurations (`VALIDATION.md`, "SCG001 exposure scenarios"). It used to
  read only `exposure.include` and each endpoint's own `access`/`enabled`;
  it now also applies `exposure.exclude`, `management.server.port=-1`,
  `management.endpoints.access.max-permitted`, the global
  `management.endpoints.access.default` and the legacy
  `management.endpoints.enabled-by-default`, and `read-only` access leaves
  write-only endpoints (`shutdown`, `restart`) unreachable.

**Detection changes**
- **SCG001 no longer reports endpoints Spring doesn't expose** (six false
  positives in the scenarios above): those listed in `exposure.exclude`
  (or all of them with `exclude=*`), and every endpoint under
  `access.default=none`, `max-permitted=none`, `enabled-by-default=false`
  or `management.server.port=-1`. The finding disappears when no sensitive
  endpoint is left exposed; otherwise the excluded ones drop out of its
  message.
- **SCG001 now reports `heapdump` and `shutdown`** where a global default
  opens them, though they are restricted by default:
  `access.default=unrestricted` or `enabled-by-default=true` open both, and
  `access.default=read-only` opens `heapdump` (three false negatives). With
  `exposure.include=*` the finding already existed, and these endpoints are
  now listed in its message; a new finding appears only when no other
  sensitive endpoint was exposed (e.g. `include=heapdump`).
- **Lower severity for findings based on an absent key** (ADR-010): when the
  only evidence is a key that isn't set and whose default is insecure, the
  finding is MEDIUM instead of HIGH, since the key may be set outside the
  scanned files, e.g. by an environment variable. Applies to SCG014 (Kafka,
  or a Spring Cloud Stream Kafka binder, with no `security.protocol`) and
  SCG015 (RabbitMQ with `ssl.enabled` absent or an empty placeholder
  default); each message says why it is MEDIUM. An insecure value written
  in the files (`PLAINTEXT`, `SASL_PLAINTEXT`, `ssl.enabled=false`) stays
  HIGH. With the default `--fail-on=HIGH`, these findings alone no longer
  fail the build; `--fail-on=MEDIUM` still fails on them.
- On the reference corpus, against `v1.5.0`: 31 SCG014 findings in
  `spring-cloud-stream-samples` and 1 in `spring-boot` go from HIGH to
  MEDIUM, with the same rule, file and profile. Every other finding and
  coverage warning is identical; the SCG001 fix changes no finding there.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.5.0...v1.6.0`.

## v1.5.0

**Added**
- SCG007 and SCG014 now cover the Spring Cloud Stream Kafka and Kafka
  Streams binders, which configure Kafka clients through their own
  properties instead of `spring.kafka.*`. The binders are evaluated as
  Spring Cloud Stream resolves them: each client builds on `spring.kafka.*`,
  overridden by the binder's `configuration` map, overridden by its
  `consumer-properties`/`producer-properties`; a named binder's
  `spring.cloud.stream.binders.<name>.environment` is a context of its own,
  on top of the main one it inherits (unless `inherit-environment` is
  false). See ADR-009.
  - SCG007 reports a plaintext JAAS password in `sasl.jaas.config` in the
    binders' client maps, and inside a binder's environment.
  - SCG014 reports `PLAINTEXT`/`SASL_PLAINTEXT` written in the binders'
    client maps, and in `spring.kafka.*` inside a binder's environment. A
    top-level value inherited by several binders is reported once.
  - SCG014 reports a binder in use with no protocol covering all its
    clients (the binder's `configuration` map or `spring.kafka.security.protocol`;
    a consumer-only or producer-only value leaves the other clients on
    Kafka's `PLAINTEXT` default), the check it already applied to
    `spring.kafka.*`. It isn't repeated where that check already reports the
    same gap.
- Messages name the key as written, including a binder's environment
  prefix, and the binder a finding is about.

**Detection changes**
- **More findings**, all in the new binder checks above. On the reference
  corpus, 34 findings added, all in `spring-cloud-stream-samples`: 2 SCG007
  and 3 SCG014 on values written in the binder (the two false negatives
  recorded in `VALIDATION.md`), and 29 SCG014 for samples that configure
  Kafka only through the binder with no protocol set.
- Every other reference project reports the same findings and coverage
  warnings as `v1.4.0`.
- Known limitations: a protocol set only through an environment variable
  is invisible, so such a binder is reported as unset (as for
  `spring.kafka.*`); a project using the binder with no binder key at all is
  not recognized as using it.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.4.0...v1.5.0`.

## v1.4.0

**Added**
- SCG006 now reports a numeric secret when the key ends in a secret
  pattern (`...password`, `...secret`, `...api-key`, ...), since such a key
  names the secret itself: `ssl.keystore.password: 123456` was skipped by
  the heuristic that treats numeric values as metrics, not secrets. Numeric
  values in other keys (`token-validity-in-seconds: 86400`,
  `password-min-length: 8`) and booleans in any key
  (`require-password: true`) are still skipped.

**Fixed**
- A list index written as a quoted YAML key (`"[0]":`) was joined with a
  dot (`x.[0]`) instead of Spring's `x[0]`, so it wasn't recognized as a
  list item. With the jar of v1.3.1, `exposure.include: {"[0]": "*"}`
  raised no SCG001, and a profile writing `"[0]": {url: ...}` over a base
  list kept the base's whole list, so SCG006 reported a base password
  Spring drops in that profile. YAML keys starting with `[` now join their
  parent without a dot, as in Spring's YAML loader. See ADR-008.

**Detection changes**
- **More findings**: SCG006 on numeric values in keys ending in a secret
  pattern. On the reference corpus, 3 findings added in
  `spring-cloud-stream-samples`: the three numeric SSL passwords in
  `kafka-ssl-demo`, a false negative recorded in `VALIDATION.md`.
- **More findings**: SCG001 and any rule reading a list now see items
  written as quoted YAML index keys.
- **Fewer findings**: a profile replacing a base list through a quoted
  index key no longer inherits the base's items, so findings on them (e.g.
  SCG006 on a base password) no longer appear in that profile.
- Every other reference project reports the same findings and coverage
  warnings as `v1.3.1`; none of them uses quoted index keys.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Documentation: the `/actuator` benchmark now compares lists written in two
formats, lists of objects partially overridden, and a scalar and a map on
the same key against `/actuator/configprops` (6 benchmark tests); only the
quoted index case needed a fix. `VALIDATION.md` and `CLAUDE.md` record the
results, including that SCG keeps both shapes of a key written as a scalar
and as a map, as Spring does.

Full diff: `v1.3.1...v1.4.0`.

## v1.3.1

**Fixed**
- Bracketed map keys (`spring.kafka.properties[sasl.jaas.config]`,
  `logging.level[com.example]`, or `"[security.protocol]"` in YAML) were
  treated as list indices. Rules look properties up by their dotted name, so
  they never matched the bracketed spelling: SCG007 missed a plaintext JAAS
  password written that way, and SCG014 reported Kafka as `PLAINTEXT` even
  when `spring.kafka.properties[security.protocol]=SASL_SSL` was set. In
  profiles, an entry added by the profile discarded every entry the base
  defined in that map. SCG now rewrites bracketed map keys into dotted form
  when loading `.yml` and `.properties` files, keeping numeric list indices,
  as Spring Boot's binder does. See ADR-007.
- The same input could produce a different report on each run: SCG001
  listed endpoints in an order that changed from one JVM run to the next,
  and findings one rule reported in the same file and profile could swap
  places. Output is now byte-identical on every run, in JSON and console:
  SCG001 lists endpoints in a fixed order (`env, threaddump, configprops,
  beans, loggers`; `env, configprops`), and findings tied on severity, file
  and profile are ordered by rule ID and then message.

**Detection changes**
- **More findings** where a sensitive property is written with brackets:
  SCG007 now reports a plaintext JAAS password in
  `spring.kafka.properties[sasl.jaas.config]`, in both formats.
- **Fewer findings**: SCG014 no longer reports Kafka as unencrypted when the
  secure protocol is set through `spring.kafka.properties[security.protocol]`.
- **More findings in profiles**: a profile adding one entry to a map
  written with brackets keeps the base's entries, as Spring does, so
  findings on those entries now appear in that profile too. For example, a
  hardcoded `spring.kafka.properties[ssl.keystore.password]` in the base
  was reported by SCG006 only on the base when a profile added its own
  `spring.kafka.properties[...]` entry; it is now reported on the profile
  as well.
- **Finding messages** name the dotted key
  (`spring.kafka.properties.sasl.jaas.config`), not the bracketed spelling
  written in the file.
- **Known limitation**: brackets keep characters relaxed binding ignores,
  so `[com.foo-bar]` and `[com.foobar]` are two entries in Spring but one
  key in SCG, the later overriding the earlier (ADR-007).
- The same findings and coverage warnings as `v1.3.0` on every reference
  project (demo fixtures, `spring-env-benchmark`, and the `VALIDATION.md`
  repositories): none of them uses bracketed keys. Only the order of the
  endpoint lists in SCG001 messages differs, now fixed.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Documentation: `VALIDATION.md` adds `spring-cloud-stream-samples`, with
three false negatives recorded for the rule-by-rule review, and the
`/actuator` benchmark now checks bracketed map keys against
`/actuator/configprops`.

Full diff: `v1.3.0...v1.3.1`.

## v1.3.0

**Added**
- `--version` flag: prints `spring-config-guard <version>` and exits 0,
  before validating any other argument (like `--help`, which still wins
  when both are given). The version comes from the `pom.properties` Maven
  writes into the jar; outside a packaged jar it is reported as unknown
  rather than guessed.
- The release workflow now fails unless the built jar's `--version` reports
  exactly the version being released, so a published jar always identifies
  itself correctly.

**Detection changes**
- None. Findings and coverage warnings are identical to `v1.2.0` on every
  reference project (demo fixtures, `spring-env-benchmark`, and the four
  `VALIDATION.md` repositories).

**Breaking changes**
- None. `--version` is a new flag; report formats, existing flags, exit
  codes and the Policy file schema are unchanged.

Documentation: README now explains what a finding's `sourceFile`
identifies, and CONTRIBUTING.md classifies a new optional JSON field as a
MINOR change.

Full diff: `v1.2.0...v1.3.0`.

## v1.2.0

**Added**
- New coverage warning for configuration split across Spring config
  locations. When one module has `application*` files in more than one of
  `src/main/resources`, `src/main/resources/config` and `config/`, SCG
  prints to stderr: `spring-config-guard: N application(s) have config
  files in more than one Spring config location, evaluated independently --
  risks split across locations are not detected.` Spring merges those
  locations at runtime; SCG evaluates each directory on its own, so a risky
  combination split across them (e.g. `allowed-origins: "*"` in one and
  `allow-credentials: true` in the other) produces no finding. The warning
  makes that gap visible. Like the `spring.config.import` warning, it is not
  a `Finding` and doesn't affect `--fail-on`. See ADR-005.
- Release jars are now built, tested and published by GitHub Actions from
  the exact commit of the release tag, with notes taken from `CHANGELOG.md`.

**Fixed**
- When `application.yml` and `application.properties` coexisted in the same
  directory (or two files for the same profile, in both formats), every
  property of one of the two files was silently dropped and never analyzed.
  Both are now merged, with `.properties` winning a key conflict, as Spring
  Boot does. See ADR-003.
- A named profile file (`application-prod.yml`) and a
  `spring.config.activate.on-profile: prod` document inside a base file are
  now merged into a single `prod` configuration, the named file winning a
  key conflict (confirmed against a running Spring Boot app). They were
  previously evaluated as two separate `prod` configurations. Also fixes a
  `NullPointerException` when that merge involved an explicit `null`
  override.

**Detection changes**
- **More findings** in projects affected by the first fix: the file that
  used to be dropped is now analyzed, so its findings appear for the first
  time.
- **Fewer findings**: `src/test/` and Maven/Gradle build output (`target/`
  or `build/` next to a `pom.xml`/`build.gradle`/`build.gradle.kts`) are no
  longer scanned, since neither ships with the application. Running SCG
  after a build no longer duplicates every finding from `target/classes`,
  and test-only config no longer fails the gate. On the `spring-boot`
  validation run, 66 findings become 64 (both removed ones came from
  `src/test/resources`). Passing one of those directories directly as
  `<project-path>` still scans it. See ADR-006.
- **Profiles defined both by a named file and by an on-profile block**
  (second fix), where the two used to be evaluated separately:
  - more findings when a risky combination is split between them (e.g.
    `allowed-origins: "*"` in the block, `allow-credentials: true` in the
    file now raises SCG003; it raised nothing before);
  - fewer findings when the file overrides the block with a safe value
    (a value the block enabled and the file disables is no longer flagged);
  - one finding instead of two when both define the same risky value.
- **Source file of base findings** when both formats are present: findings
  on the merged base configuration now always name the highest-precedence
  file (`application.properties`) as `sourceFile`, even when the property
  itself is defined in `application.yml`.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.1.0...v1.2.0`.

## v1.2.0-rc.1

Pre-release published to validate the automated release workflow
(`.github/workflows/release.yml`) end to end — manual trigger, version
and tag checks, build and tests, tag creation, notes from this changelog,
jar attached. Not intended for use: pin `v1.1.0` or wait for `v1.2.0`, whose
notes will list the changes since `v1.1.0`.

**Detection changes**
- Same as the current `main`; they will be listed in `v1.2.0`.

**Breaking changes**
- None.

Full diff: `v1.1.0...v1.2.0-rc.1`.

## v1.1.0

**Added**
- New coverage warning: SCG now prints an unconditional line to stderr
  (`spring-config-guard: N file(s) import external configuration via
  spring.config.import that was not scanned.`) whenever a scanned file
  declares `spring.config.import` — that imported content stays
  invisible to every rule, and previously nothing in the report
  indicated it had been skipped. Deliberately not a `Finding`: kept
  outside the report and the `--fail-on` filter so it can't compete
  with, or hide behind, actual findings. Does not resolve or follow the
  import itself; see `Scope & Limitations` in the README for why.

No breaking changes. Full diff: `v1.0.2...v1.1.0`.

## v1.0.2

**Fixed**
- `SCG002` (H2 console enabled) no longer leaks the internal "no active
  profile" sentinel (`__spring_config_guard_base__`) into the finding's
  message text for the base/no-profile case — it now behaves like every
  other rule, relying on the separate `profileLabel` field instead of
  restating the profile inline.
- `SCG008` (Swagger/OpenAPI exposure) no longer frames its description
  and messages around "production" — the rule has always been
  profile-agnostic (Zero-Trust, no profile exemption), and the old
  wording could mislead a reader into treating a `dev`/`test` finding as
  safe to ignore.

No breaking changes. Full diff: `v1.0.1...v1.0.2`.

## v1.0.1

**Fixed**
- `SCG010` (verbose HTTP error responses) now also detects the
  `spring.web.error.include-*` property family introduced in Spring Boot
  4.0, alongside the existing `server.error.include-*` (3.x) keys. Spring
  Boot 4.0 renamed the whole `server.error.*` group to `spring.web.error.*`
  (confirmed against the official OpenRewrite migration recipe,
  `SpringBootProperties_4_0`); a project already migrated to 4.0 using the
  new property names previously went undetected by this rule.

No breaking changes. Full diff: `v1.0...v1.0.1`.

## v1.0

Static-analysis CLI that lints Spring Boot `application.{properties,yml,yaml}`
files for security misconfigurations before deployment — runs as a CI gate,
not against a live URL.

**What's in this release**
- 17 rules (`SCG001`–`SCG017`) covering Actuator exposure, hardcoded
  credentials, insecure TLS transport (DB/broker, Kafka, RabbitMQ, Vault,
  OAuth2), CORS misconfiguration, Swagger/OpenAPI exposure, verbose
  logging/errors, and server SSL/session cookie settings — see the
  [rule catalog](https://github.com/rgiovann/spring-config-guard#rules).
- `--config-server` mode for scanning Spring Cloud Config Server backing
  repositories.
- `--policy` for explicit, auditable suppression of findings by rule +
  profile.
- `--json` output and `--fail-on` severity threshold for CI gating.
- Validated against real-world repositories (Spring Boot, Spring Boot Admin,
  Spring PetClinic, and a real Spring Cloud Config Server backing repo) —
  see [Validated against real-world code](https://github.com/rgiovann/spring-config-guard#validated-against-real-world-code).

**Usage**
```
java -jar spring-config-guard.jar <project-path> [--json] [--config-server] [--fail-on=HIGH|MEDIUM|LOW|NONE] [--policy=<file>]
```

Requires Java 21+. Apache License 2.0.
