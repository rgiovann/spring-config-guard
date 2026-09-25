# Changelog

Release notes for every version, newest first. Versioning rules, the release
checklist and the notes template are in
[CONTRIBUTING.md](CONTRIBUTING.md#releases).

Each section heading must be exactly `## vX.Y.Z`, matching the tag: the
release workflow publishes that section's body as the GitHub release notes,
and refuses to publish a tag without one.

## v1.2.0-rc.1

Pre-release published to validate the automated release workflow
(`.github/workflows/release.yml`) end to end — tag push, version check,
build and tests on the tagged commit, notes from this changelog, jar
attached. Not intended for use: pin `v1.1.0` or wait for `v1.2.0`, whose
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
