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

Versions follow `MAJOR.MINOR.PATCH`, and tags are always `vX.Y.Z` (a
pre-release adds a suffix, e.g. `v1.2.0-rc.1`). For a
linter, "breaking" needs a precise meaning: users gate CI on its output, so
a release can change their build result without changing any contract.

* **MAJOR**: breaks a public contract — removing, renaming or retyping a
  field of the JSON report, or changing its shape (e.g. from a list of
  findings to an object); removing or changing CLI flags or exit codes; an
  incompatible change to the Policy file schema; or a rule ID being removed
  or renumbered.
* **MINOR**: adds capability — a new rule, flag or coverage warning, new
  detection in an existing rule (e.g. recognizing a renamed property), or
  a new optional field in an existing JSON object.
* **PATCH**: fixes a bug or a message.

Consumers of the JSON report should ignore fields they don't know, so an
added field never breaks them; that is what makes it MINOR.

A detection change alone — more findings, fewer findings, a recalibrated
severity — is never a MAJOR bump: detecting things is what the tool is for.
But it is never silent either: every release lists it under **Detection
changes**, saying which way findings move (more or fewer) and why.

Between releases, `main` carries the next version as `X.Y.Z-SNAPSHOT` in
`pom.xml`.

### Release checklist

The assistant prepares the release (version, notes, `pom.xml`, README
pin); the maintainer reviews it and approves before anything is tagged.
Publishing is automated by `.github/workflows/release.yml`.

1. Decide the version from the commits since the last tag, using the rules
   above.
2. Set `pom.xml` to `X.Y.Z` (drop `-SNAPSHOT`).
3. Update the pinned version in README's CI/CD Integration example (skip
   for a pre-release).
4. Add a `## vX.Y.Z` section at the top of `CHANGELOG.md`, using the
   template below.
5. After approval, the assistant commits and pushes to `main`, then runs
   the **Release** workflow manually (Actions tab → Release → Run workflow,
   or the API) from `main`, with the version as input (`X.Y.Z`, no `v`).
   The workflow:
   * fails unless the input is `X.Y.Z` or `X.Y.Z-<suffix>` and it runs on
     `main`;
   * fails if the tag `vX.Y.Z` already exists, so a published release is
     never overwritten;
   * fails unless `pom.xml`'s version equals the input;
   * fails unless `CHANGELOG.md` has a non-empty `## vX.Y.Z` section;
   * runs `mvn -B package` (full test suite) on that commit;
   * fails unless the built jar's `--version` reports exactly that version;
   * creates the tag `vX.Y.Z` on exactly that commit and publishes the
     GitHub release with the section as its notes and
     `target/spring-config-guard.jar` attached — as a pre-release when the
     version has a suffix, so `releases/latest` is never a pre-release.
6. The assistant checks the workflow run and the published release, and
   reports the link.
7. Set `pom.xml` to the next `-SNAPSHOT` version.

The workflow creates the tag itself because tags can't be pushed from the
assistant's sessions, and so the tag always points at the commit that was
built and tested. If it fails, nothing is published and no tag is created:
fix the cause and run it again.

### Release notes template

A `CHANGELOG.md` section; the heading must match the tag exactly.

```markdown
## vX.Y.Z

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
