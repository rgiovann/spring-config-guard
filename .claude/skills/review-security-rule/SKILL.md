---
name: review-security-rule
description: Analytical procedure for reviewing an existing or proposed spring-config-guard security rule (SCGNNN) — traces the actual trigger condition against its stated intent, audits it against documented invariants, and classifies every finding as implementation bug, deliberate scope decision, static-analysis limitation, Spring Boot behavior, design preference, or speculative requirement. Use when asked to review, audit, or validate a rule's correctness.
---

# Reviewing a spring-config-guard security rule

More analytical than `.claude/skills/add-security-rule/SKILL.md`, and it
assumes that skill's vocabulary and CLAUDE.md's invariants rather than
re-deriving them — those are the standard the rule is checked against, not
something to re-explain here.

Determine first whether you're reviewing code that already exists (rule +
test) or a proposal not yet built — registration and test-correctness
checks below only apply to the former.

## 1. Reconstruct the stated intent

Read `description()`, the class Javadoc, and the test `@DisplayName`s.
State in one sentence what misconfiguration it claims to catch and what
real Spring Boot/library default makes that claim true. This project holds
itself to a real standard here — `ActuatorExposureRule`'s Javadoc cites the
actual Spring Boot changelog and notes empirical confirmation against a
real app. A rule whose Javadoc asserts a default without that kind of
grounding is itself a finding: classify the claim as unverified, not
confirmed, until you check it.

## 2. Reconstruct the actual trigger condition

Read `check()` line by line and write out the exact boolean condition that
emits a `Finding`, in terms of canonicalized keys and resolved values — not
the prose description. Compare against step 1: exactly as broad, narrower,
or wider than claimed?

Narrower-than-stated is the harder case, because the rule still "basically
works" — e.g. SCG003/004/005 are scoped only to
`management.endpoints.web.cors.*` because Spring MVC's own CORS support has
no `application.yml` binding; they say nothing about CORS configured via
`WebMvcConfigurer`. That's a documented, deliberate static-analysis
boundary, not a bug — recognize it as such rather than praising or faulting
the rule for it.

## 3. Audit against documented invariants

For each, check the actual code, not just whether its tests pass:

* **Relaxed binding** — lookups go through `RelaxedProperties`, never raw
  map access (CLAUDE.md). Any prefix/existence check respects a
  `.`-bounded segment, not a raw `startsWith` —
  `RelaxedProperties.hasKeyWithPrefix()` had exactly this bug
  (`springdocument.path` matching prefix `springdoc`).
* **Placeholders** — `EnvironmentPlaceholder.resolve()` runs before
  evaluating any value that could carry `${...}`; unresolved is treated as
  risk (`INFO`), never silently skipped or assumed safe (see
  `add-security-rule`'s placeholder shape). Partial handling is either a
  verified intentional simplification or a gap — check which.
* **Profiles** — does the rule branch on `config.profileLabel()` to
  suppress a finding? The established pattern (H2, Actuator) fires
  regardless of profile; a rule that gates on profile needs a stated
  reason, not "it's usually only a prod problem." Watch for a docstring
  claiming narrower scope than the code enforces —
  `H2ConsoleExposedRule` says "outside dev/test/local" but its `check()`
  doesn't gate on profile at all; the code is intentionally *stricter*
  than its own wording. Don't "fix" code to match loose prose.
* **Rule vs. ConfigurableRule / metadata** — if `ConfigurableRule`: is
  every top-level YAML value actually a list (a scalar/nested map crashes
  `RuleEngine` for every rule at startup, not just this one — SCG008's
  first version hit this)? Is the parsed metadata actually consumed in
  `check()`, or validated non-empty and then ignored in favor of hardcoded
  values (SCG008's first version also did this)? Independent of bugs: do
  the values need to be externally editable, or would a plain `Rule` be
  more honest (`add-security-rule`'s decision test)?
* **Registration** — is the class in `META-INF/services/dev.scg.core.Rule`
  and its ID in `RuleRegistryTest`'s exact-ID list? A rule can compile and
  pass its own tests while never running — no error surfaces anywhere.
* **Overlap** — could this belong to an existing rule already? "SCG00X
  with different property names" should usually extend SCG00X rather than
  ship as a new ID.
* **Severity & message** — matches `add-security-rule`'s taxonomy, and the
  message states why it's a risk plus an actionable fix, not just the key
  name.

## 4. False positive / false negative analysis

Construct concrete configurations by hand — not just run the existing
tests — that should and shouldn't trigger the rule, focused on the
trigger's evidence requirement. For an opt-out-by-default feature (see
`add-security-rule`'s trigger design), ask specifically: does a
"presence of any key under this namespace" heuristic false-positive on an
unrelated library sharing a name fragment, and does it false-negative on a
project using the feature entirely via defaults with zero keys mentioned
anywhere? The latter is an inherent static-analysis limitation (no
classpath visibility) — document it as a boundary if undocumented, don't
treat it as a bug to fix.

## 5. Verify tests validate behavior, not just pass

Confirm coverage matches `add-security-rule`'s testing section. Beyond
coverage, check that each test's assertions actually match its
`@DisplayName` and the rule's real behavior. Concrete example from this
codebase: a test named "...and stay silent" that actually asserted
`hasSize(1)` with a specific severity. The rule was correct — a `null`
value falls through to the feature's default-exposed state, not silence —
the *name* was wrong; renaming it was the right fix, changing the
assertions to match an inaccurate name would not have been. Also check any
test premised on relaxed-binding scope against
`RelaxedProperties.canonicalize()`'s actual documented behavior, not an
assumption about what "relaxed binding" covers.

## Classify every finding before proposing a change

Tag each issue as one of:

* **Implementation bug** — contradicts the rule's own stated intent or a
  project invariant. Fix it.
* **Deliberate scope decision** — already justified in the rule's own
  Javadoc/comments. Preserve it; don't "simplify" it away.
* **Inherent static-analysis limitation** — can't be fixed without
  changing what the project analyzes (no classpath visibility, no
  bytecode analysis). Document if undocumented; don't treat as solvable
  within the rule.
* **Spring Boot / library behavior fact** — verify against real
  documentation or source before accepting a claim about a default or
  binding behavior; don't accept it just because a comment asserts it.
* **Design preference** — a valid alternative exists but the current
  approach isn't wrong. Note the trade-off; don't force a change.
* **Speculative or non-existent requirement** — solves a problem nothing
  in the repository or the request actually has. Reject it.

Only recommend a code change for a confirmed implementation bug or a
technically weak decision, and state the concrete failure scenario
(input/config that triggers wrong behavior) — not a theoretical preference
for a different design. If a decision is technically correct and
deliberate, say so and leave it alone, even if another approach would also
have worked.
