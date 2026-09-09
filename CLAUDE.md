# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project

`spring-config-guard` (SCG) is a static-analysis CLI that lints Spring Boot
`application.{properties,yml,yaml}` files for security misconfigurations
before deployment.

It reads a project directory, builds the effective configuration per profile,
runs `Rule` implementations against each configuration, and reports findings
with an exit code suitable for CI gating.

The project uses Java 21 and Maven. It does not depend on Spring Boot itself;
it statically parses Spring Boot configuration files.

## Source of Truth

The local working tree is the primary source of truth during development.

Treat the code, configuration, tests, resources, and other files currently
present in the local repository as authoritative for the current state of the
project.

Do not assume that the remote Git repository reflects the latest state.

The developer manages Git commits, branches, and pushes through IntelliJ IDEA.
Do not create commits, push changes, or modify Git history unless explicitly
requested.

When investigating existing behavior or architecture, inspect the local
working tree before relying on assumptions about the remote repository.

## Commit Messages

When asked to draft a commit message, write it in English regardless of the
conversation language, in the style already used in this repository's git
log:

* Title: `type(scope): imperative summary` (Conventional-Commits-style
  types — `feat`, `fix`, `test`, `docs`, `refactor`, etc. — scoped to
  `rules`, a specific rule ID, or the affected area).
* Body: a bullet list, not prose paragraphs. Each bullet names a concrete
  change and, where it isn't obvious from the diff, *why* — a design
  decision, a bug that was fixed, a trade-off — not a restatement of the
  diff itself.
* Group only changes that belong to one coherent concern into a single
  message. If the pending changes span unrelated concerns (e.g. a new rule
  and unrelated tooling/doc changes), say so and offer separate messages
  rather than merging them into one.
* No `Co-Authored-By` trailer — the developer runs the actual `git commit`
  through IntelliJ IDEA, so authorship is theirs (see Source of Truth
  above).
* Present the message as text for the developer to copy; do not run `git
  commit` yourself.

## Engineering Principles

Prefer:

* Simple solutions over unnecessary abstractions.
* High cohesion and low coupling.
* Strong encapsulation and clear responsibilities.
* Immutability where appropriate.
* Explicit dependencies.
* Focused, maintainable designs.
* Modern Java and Spring features when they provide a concrete benefit.

Do not introduce patterns, abstractions, libraries, or architectural layers
without a specific justification.

Avoid speculative extensibility, premature optimization, and unnecessary
complexity.

Do not use a modern Java feature merely because it is available. Use it when
it improves readability, correctness, maintainability, performance, or
architectural fit.

## Critical Analysis

Do not automatically agree with the developer's proposed solution.

When a design or implementation is questionable:

1. Identify the actual problem being solved.
2. Identify relevant assumptions, risks, and constraints.
3. Consider simpler alternatives.
4. Explain the relevant trade-offs.
5. Recommend the most appropriate solution.

If the developer's reasoning is technically incorrect, state this explicitly
and explain why.

Do not preserve a technically weak solution merely because it was the
developer's original proposal.

Do not optimize for theoretical purity at the expense of practical
simplicity.

## Context and Assumptions

Do not invent business requirements or architectural constraints.

Use the repository as the primary source of truth when investigating existing
behavior.

Ask for clarification only when missing information materially affects the
correctness of the implementation or an important design decision.

When sufficient evidence exists in the repository, proceed without unnecessary
questions.

When an assumption is unavoidable, state it briefly.

## Repository Investigation

Before making non-trivial changes:

* Inspect the relevant code and its usages.
* Check related tests and configuration when relevant.
* Understand the existing design and conventions.
* Consider the impact of the change on related components.

Do not make architectural conclusions from an isolated code fragment when the
surrounding repository can provide relevant evidence.

Keep changes focused on the requested problem.

Do not refactor unrelated code unless it is necessary for correctness,
maintainability, or the requested change.

## Architecture

The main processing pipeline is:

```text
ConfigLoader.loadDirectory()
    -> List<ConfigFile>

ConfigFileGrouper.group()
    -> List<GroupedConfigFile>

ProfileMerger.merge()
    -> List<EffectiveConfig>

RuleRegistry.discoverRules()
    -> List<Rule>

RuleEngine.run(effectiveConfigs)
    -> List<Finding>

Reporter.report(findings)

ExitCodeResolver.resolve()
```

Each stage has a deliberately narrow responsibility. Preserve these
boundaries unless there is a concrete architectural reason to change them.

`ConfigLoader` handles YAML/properties parsing and per-file profile documents.
It does not merge base and profile configurations.

`ConfigFileGrouper` groups `application.yml` with corresponding
`application-{profile}.yml` files in the same directory.

`ProfileMerger` performs base/profile merging according to the project's
implemented Spring configuration semantics.

`RuleEngine` orchestrates rule execution and should not acquire YAML, CLI, or
Maven-specific responsibilities.

A `Rule` receives the complete `EffectiveConfig` rather than individual
parameters so that the interface does not need to change whenever contextual
information is added.

## Relaxed Binding

Spring Boot relaxed binding treats variants such as `foo-bar`, `fooBar`, and
`foo_bar` as equivalent property keys.

`RelaxedProperties.canonicalize()` is the single source of truth for this
comparison.

Rules must use:

* `RelaxedProperties.get()`
* `RelaxedProperties.valuesForKeyOrListChildren()`
* `RelaxedProperties.findActualKey()`

Do not access `EffectiveConfig.properties()` directly with `.get()` when
performing property-key lookups, as this can silently miss relaxed-binding
variants.

## Placeholder Resolution

`${VAR:default}` placeholders are resolved statically through
`EnvironmentPlaceholder.resolve()`.

A placeholder without a default is considered unknowable at lint time.
The project's security posture is to treat such cases as potentially risky
rather than silently suppressing the finding.

A placeholder with a default resolves to that default, recursively.

## Adding a Rule

To add a new rule:

1. Implement `dev.scg.core.Rule`, or `ConfigurableRule` when externalized
   configuration is required.
2. Place the implementation under `dev.scg.rules`.
3. Use the next `SCGNNN` identifier.
4. Register the rule in
   `src/main/resources/META-INF/services/dev.scg.core.Rule`.
5. For `ConfigurableRule`, add
   `src/main/resources/rules-metadata/SCGNNN.yml`.
6. Add the corresponding test under
   `src/test/java/dev/scg/rules/`.

`RuleRegistry` discovers rules through `ServiceLoader` and sorts them by ID.

`RuleEngine` validates configurable rule metadata during initialization and
fails fast when required metadata is missing, empty, or invalid.

The authoritative list of current rules is
`src/main/resources/META-INF/services/dev.scg.core.Rule`, enforced by the
exact-ID assertion in `RuleRegistryTest`. Do not maintain a manual list of
rules in this file or in a skill — it will drift the moment a rule is added
or removed.

For the judgment calls that precede and surround these mechanical steps —
whether the target behavior is statically analyzable at all, whether an
existing rule already owns the responsibility, the `Rule` vs `ConfigurableRule`
decision, severity calibration, and the testing conventions rules are expected
to follow — see `.claude/skills/add-security-rule/SKILL.md`.

Rule-specific scope decisions are often documented in comments or Javadoc
inside the rule implementation itself (e.g. why a rule does or does not
exempt certain profiles, or why it is intentionally narrower than the
underlying Spring Boot feature). Read that context before changing behavior,
because such decisions may represent deliberate architectural or security
trade-offs rather than oversights. For a structured procedure to tell the
two apart when reviewing an existing or proposed rule, see
`.claude/skills/review-security-rule/SKILL.md`.

## Findings

`Finding` contains:

* `ruleId`
* `Severity`
* `message`
* `sourceFile`
* `profileLabel`

`Severity` can be `HIGH`, `MEDIUM`, `LOW`, or `INFO`.

`INFO` represents cases where static analysis cannot determine the actual
risk. It does not independently cause `ExitCodeResolver` to fail the build.

## Build and Test

Run the full test suite with:

```bash
mvn test
```

Run a single test class with:

```bash
mvn test -Dtest=HardcodedSecretsRuleTest
```

Run a single test method with:

```bash
mvn test -Dtest=HardcodedSecretsRuleTest#detectsPlaintextPassword
```

Build the fat jar with:

```bash
mvn package
```

CLI usage and flags for running the built jar are documented in `README.md`.

`demo-project/` contains deliberately misconfigured YAML fixtures.

`demo-project-clean/` contains deliberately clean properties fixtures.

These directories can be used for manual end-to-end validation when
appropriate.

## Implementation and Validation

Prefer the smallest correct change.

After a meaningful code change, perform validation appropriate to its scope,
such as compilation, relevant tests, or static analysis.

Do not claim that something was verified if it was not.

Inspect the resulting diff before considering the task complete.

Do not create commits or push changes. Git operations are managed by the
developer through IntelliJ IDEA.

## Technical Discussions

When discussing architecture or design, distinguish between:

* Actual requirements
* Existing architectural constraints
* Useful design preferences
* Speculative future requirements
* Premature abstractions

When multiple solutions are valid, compare their relevant trade-offs rather
than presenting one approach as universally correct.

The objective is not merely to implement the requested change, but to improve
the quality of the technical decision behind it.
