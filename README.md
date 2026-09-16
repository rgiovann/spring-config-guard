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

## Contributing

Each new rule is a class implementing `dev.scg.core.Rule` — see
`ActuatorExposureRule` as a reference. PRs for new rules are welcome.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
