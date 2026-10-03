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

## 4. Inventory the input space from its sources of truth

Before testing, write down everything the rule's subject can be written as,
taken from the sources Spring and the client actually read, not from what
the rule's code already looks for. Steps 2 and 3 look at the rule from the
inside; this step looks at it from the outside, and is where the second
reviews of the reviewed rules found what the first ones missed.

* **Keys**: every property in the configuration metadata of the Spring Boot
  version measured that belongs to the rule's domain, and the maps whose
  entries can carry the value (a `properties` map, a `headers` map).
  Check each one's status (`development-workflow`, section 7, step 2).
* **Value grammar**: how the client that reads the value parses it, from
  its source or reference documentation (a driver's URL syntax, its
  options and factories; a protocol's URI schemes), not from the forms
  remembered. Example: Connector/J also reads a password from a host
  specification, `jdbc:mysql://(host=db,password=...)/app`.
* **Conversion**: how Spring converts the value (its boolean literals are
  `true`/`on`/`yes`/`1` and their opposites; enums bind relaxed).

The inventory is the list of cases the analysis below and the tests are
built from.

## 5. False positive / false negative analysis

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

Then list every place where `check()` stays silent on input that touches
the rule's subject: a `continue`, an exclusion list (ignored prefixes or
suffixes, value allowlists), a value heuristic. For each one, apply
CLAUDE.md's Findings section (false negatives weigh more than false
positives): is the silence proven, i.e. can the value never be the risk?
If not, the case is doubt and belongs in `INFO`, not in silence. Example:
SCG006 used to silence keys that only contain a secret pattern; since
`app.secret-key-base` may well be a secret, they are `INFO` now. Measure
before changing: the hand-built cases and the reference corpus (see
`VALIDATION.md`) show how much `INFO` the change adds.

Then work from the inventory (step 4): run every item the rule doesn't
report against the jar, and for each one either prove it can't be the risk
or report it. Example: the 146 metadata properties with a credential-like
name and no SCG006 finding held eight native secrets.

Then think as an attacker: for every case the rule reports, which nearby
value would they use to reach the same risk while the rule rates it lower
or stays silent (a wildcard placed elsewhere, a suffix, upper case, a
public suffix, an extra list entry)? Try each in a running app. Example:
`https://*.com` was MEDIUM, though a running app sent credentials to
`https://evil.com`.

## 6. Decide the scope boundary

List the settings next to the rule's subject that the inventory turned up
but the rule doesn't cover (another library's CORS, other transports, weak
TLS protocols). Classify each now: inside the rule's scope (a finding of
this review) or outside it (a `BACKLOG.md` item, written in this review).
A neighbor found only by a later review means this step was skipped.

## 7. Verify tests validate behavior, not just pass

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

## 8. Done criteria

The review isn't done until:

* every row of its `VALIDATION.md` table has a fixture and a test that
  pins the rule's result for it;
* every number in its text comes from a command, run again before
  committing;
* the scenario script or program it ran is in the repository
  (`spring-env-benchmark`), and was run twice with the same results: a
  harness that fails at random (a port still in use, an application
  reported started too early) looks like a Spring behavior.

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

## Report

Report the review as `development-workflow`'s analysis report (section 8):
confirmed bugs, documentation and policy, verified correct, decisions
needed, out of scope, with the classes above mapped onto those sections.
Findings in other rules go to "out of scope", never into this rule's
sections.
