# Contributing to spring-config-guard

Thanks for considering a contribution. This file covers the practical
mechanics of getting a change in; the deep technical conventions already
live elsewhere in the repo, and this file points to them instead of
duplicating them (duplicated docs drift out of sync — see `ARCHITECTURE.md`'s
ADR-001 for a concrete example of that trade-off already being reasoned
through in this project).

## Getting started

Requires Java 21 and Maven.

```bash
git clone https://github.com/rgiovann/spring-config-guard.git
cd spring-config-guard
mvn test
```

Run a single test class or method while iterating:

```bash
mvn test -Dtest=HardcodedSecretsRuleTest
mvn test -Dtest=HardcodedSecretsRuleTest#detectsPlaintextPassword
```

Build the runnable fat jar with `mvn package`, then try it against the
bundled fixtures — see the README's "Usage" section and the
`demo-project/`/`demo-project-clean/` showcase subdirectories for real
input/output examples, including the Policy layer's `--policy` flag.

## Project structure and conventions

`CLAUDE.md` is the primary reference for this project's conventions —
despite the name, it's plain project documentation (architecture, the
processing pipeline, relaxed binding, placeholder resolution, severity
calibration, testing conventions), not something specific to any one
tool. Read it before a non-trivial change.

`ARCHITECTURE.md` holds ADRs for project-wide decisions with real
trade-offs (not per-rule scope calls, which live in that rule's own
Javadoc). Check it before proposing something that might revisit a
decision already made deliberately.

## Adding a new rule

The mechanical checklist (interface, package, `SCGNNN` ID, ServiceLoader
registration, metadata, tests) is in `CLAUDE.md`'s "Adding a Rule"
section. The judgment calls around it — whether something is even
statically detectable, `Rule` vs `ConfigurableRule`, severity
calibration, common pitfalls that have caused real bugs here before —
are in `.claude/skills/add-security-rule/SKILL.md`. Both are plain
Markdown; you don't need any particular tool to read or follow them.

If you're reviewing or auditing an existing rule instead,
`.claude/skills/review-security-rule/SKILL.md` has the analytical
procedure this project uses for that.

The authoritative list of implemented rules is
`src/main/resources/META-INF/services/dev.scg.core.Rule`, enforced by
`RuleRegistryTest`'s exact-ID assertion — don't rely on a manually
maintained list anywhere else.

## Commit messages

* Title: `type(scope): imperative summary` (Conventional-Commits-style
  types — `feat`, `fix`, `test`, `docs`, `refactor`, etc. — scoped to
  `rules`, a specific rule ID, or the affected area).
* Body: a bullet list, not prose. Each bullet names a concrete change
  and, where it isn't obvious from the diff, *why* — a design decision,
  a bug that was fixed, a trade-off.
* Keep a commit scoped to one coherent concern. If your change spans
  unrelated things, split it into separate commits/PRs.

## Pull requests

* Keep PRs focused — one rule, one fix, or one clearly-scoped feature
  per PR. Easier to review, easier to revert if something's wrong.
* `mvn test` must pass locally before you open the PR; CI (GitHub
  Actions) re-runs it on every push and PR, and must be green before
  merge.
* New behavior needs tests. For a new rule, see the testing checklist in
  `.claude/skills/add-security-rule/SKILL.md` (placeholder states,
  Zero-Trust across profiles, relaxed binding, null-value safety, etc.).

## License

By contributing, you agree your contribution is licensed under this
project's [Apache License 2.0](LICENSE) (see the license's own Section 5,
"Submission of Contributions").
