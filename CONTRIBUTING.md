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
input/output examples, including the Policy layer's `--policy` flag and
Config Server Mode's `--config-server` flag
(`demo-project/config-server-showcase/`).

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

## Releases

Versions follow `MAJOR.MINOR.PATCH`, and tags are always `vX.Y.Z`. For a
linter, "breaking" needs a precise meaning: users gate CI on its output, so
a release can change their build result without changing any contract.

* **MAJOR**: breaks a public contract — the JSON report schema, CLI flags,
  exit codes, the Policy file schema, or a rule ID being removed or
  renumbered.
* **MINOR**: adds capability — a new rule, flag or coverage warning, or
  new detection in an existing rule (e.g. recognizing a renamed property).
* **PATCH**: fixes a bug or a message.

A detection change alone — more findings, fewer findings, a recalibrated
severity — is never a MAJOR bump: detecting things is what the tool is for.
But it is never silent either: every release lists it under **Detection
changes**, saying which way findings move (more or fewer) and why.

Between releases, `main` carries the next version as `X.Y.Z-SNAPSHOT` in
`pom.xml`.

### Release checklist

The assistant prepares the release (version, notes, `pom.xml`, README
pin); the maintainer reviews it and approves before anything is tagged or
published.

1. Decide the version from the commits since the last tag, using the rules
   above.
2. Set `pom.xml` to `X.Y.Z` (drop `-SNAPSHOT`).
3. Update the pinned version in README's CI/CD Integration example.
4. Write the release notes with the template below.
5. After approval, the assistant commits, tags `vX.Y.Z` and pushes the tag.
   The maintainer then publishes the GitHub release from that tag, pasting
   the prepared notes and attaching the jar built by `mvn -B package` at
   that tag (`target/spring-config-guard.jar`).
6. Set `pom.xml` to the next `-SNAPSHOT` version.

### Release notes template

```markdown
## spring-config-guard vX.Y.Z

**Added**
- New rules, flags, coverage warnings or detection capability.

**Fixed**
- Bugs and message fixes.

**Detection changes**
- What now produces more or fewer findings, which rules, and why.
  "None." when nothing changed.

**Breaking changes**
- Contract changes (MAJOR only). Otherwise: "None."

Full diff: `vA.B.C...vX.Y.Z`.
```

Omit **Added** or **Fixed** when empty; always keep **Detection changes**
and **Breaking changes**, so their absence is stated rather than implied.

## License

By contributing, you agree your contribution is licensed under this
project's [Apache License 2.0](LICENSE) (see the license's own Section 5,
"Submission of Contributions").
