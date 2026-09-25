# Changelog

Release notes for every version, newest first. Versioning rules, the release
checklist and the notes template are in
[CONTRIBUTING.md](CONTRIBUTING.md#releases).

Each section heading must be exactly `## vX.Y.Z`, matching the tag: the
release workflow publishes that section's body as the GitHub release notes,
and refuses to publish a tag without one.

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
