---
name: add-security-rule
description: Decision procedure for designing and implementing a new spring-config-guard security rule (SCGNNN) — when to trust the detection idea, how to choose between Rule and ConfigurableRule, how to calibrate severity, and the concrete pitfalls (ServiceLoader registration, metadata shape, relaxed-binding test traps) that have already caused real bugs in this project. Use when asked to add, propose, or scaffold a new rule.
---

# Adding a security rule to spring-config-guard

This is the judgment layer around CLAUDE.md's "Adding a Rule" checklist
(interface, package, `SCGNNN` id, registration, metadata, test) — read that
for the mechanical steps; this covers the decisions that have actually gone
wrong in this project. Gate 0 and Gate 1 are hard stops: if either fails,
say so and don't implement.

## Gate 0 — Is this config-file-detectable?

Per CLAUDE.md's Project section, this tool only sees flattened
`EffectiveConfig` key/value maps — no bytecode/AST, no Spring Boot
dependency. Confirm the misconfiguration is actually expressed through a
property key before anything else.

Negative precedent: CSRF is normally disabled via `http.csrf().disable()`
in a `SecurityFilterChain` Java bean, not a property — no config-file
signal exists, so it's out of scope regardless of severity. If the target
is only ever set in Java code, stop and say so.

## Gate 1 — Does an existing rule already own this?

Grep `src/main/java/dev/scg/rules/` first. Two traps found by reading
`check()`, not by trusting a rule's name or Javadoc:

* A rule can be narrower than it sounds. `ActuatorExposureRule` (SCG001)
  only fires on a *wildcard* `exposure.include`; an explicit
  `include=env,configprops` with `show-values=always` slips past it — a
  real, open gap, not hypothetical.
* CORS is deliberately split by concern across SCG003/004/005 rather than
  one rule. A genuinely new concern on the same namespace is a new rule; a
  variant of an existing concern extends that rule instead.

## Trigger design: opt-in vs. opt-out defaults

What evidence should be required before a finding fires depends on whether
the feature defaults off or on:

* **Opt-in, default off** (H2 console, `spring.h2.console.enabled=false` by
  default): require the explicit enabling value. Absence of the key is the
  safe state.
* **Opt-out, default on once the dependency is present** (SpringDoc:
  `springdoc.*.enabled=true` once on the classpath): requiring an explicit
  `=true` would almost never fire, since the real risk is the silent
  default. Since the classpath is invisible to this tool, the workable
  signal is *presence of any key under the library's namespace* + *absence
  of an explicit disable* — see `SwaggerOpenApiExposedRule` (SCG008) and
  `RelaxedProperties.hasKeyWithPrefix()`.

`hasKeyWithPrefix` matches the prefix itself or a `.`-bounded segment,
never a raw `startsWith` — `springdocument.path` must not count as evidence
for prefix `springdoc`. Getting the opt-in/opt-out call wrong means the
rule either never fires on the real-world risk or fires on projects that
don't even use the feature.

## Zero-Trust and profiles

`H2ConsoleExposedRule` and `ActuatorExposureRule` never branch on
`config.profileLabel()` to suppress a finding — a misconfiguration under a
profile labeled `dev` is still real risk if that profile can run against
shared/staging infrastructure. Treat this as the default for a new rule;
if you deviate, document why in the rule's Javadoc, the way these two
document their own scope decisions.

## Relaxed binding trap

See CLAUDE.md's Relaxed Binding section for the API. One boundary is easy
to get wrong when writing *tests*: `RelaxedProperties.canonicalize()` does
**not** turn `_` into `.` (that's the OS-env-var rule, deliberately out of
scope — `ConfigLoader` never reads env vars). A key literally written as
`SPRINGDOC_SWAGGERUI_ENABLED` will **not** relax-bind to
`springdoc.swagger-ui.enabled`; only kebab/camel/snake_case *within the
same dotted segment* are equivalent. Don't write a test assuming
SCREAMING_SNAKE_CASE flattening works for property-file keys.

## Placeholder handling

CLAUDE.md's Placeholder Resolution section covers the semantics. What it
doesn't specify — and every existing rule implements identically — is the
severity shape:

1. No default at all → `INFO`.
2. Default present but blank (`${VAR:}`) → also `INFO`, worded distinctly
   from case 1.
3. Resolves to a concrete value → apply the rule's real logic.

Reuse this shape rather than inventing new resolution logic. (SCG007 also
distinguishes a credential that's empty *because of* a placeholder default
— INFO — from a literal, always-empty credential — silent; worth checking
if a new rule inspects a similarly optional value.)

## Rule vs. ConfigurableRule

Ask: would a consumer of this tool ever legitimately want to edit these
values without a Java change?

* Yes → `ConfigurableRule`. Precedent: SCG006's `secret-key-patterns`
  (open-ended, org-specific) and SCG007's `uri-based`/`jaas-based` key
  lists (could grow as new drivers are added).
* No, the keys are a fixed, closed fact about one library → plain `Rule`
  with `private static final String` constants. Precedent: SCG008 was
  first built as `ConfigurableRule` and had to be converted back — the
  YAML existed but `configure()` never actually read it, a sign the
  abstraction wasn't earning its keep.

If `ConfigurableRule`: `RuleEngine` loads the YAML as
`Map<String, List<String>>` via an unchecked cast — **every top-level
value must be a YAML list of strings**, never a scalar or nested map.
Violating this throws a `ClassCastException` at `RuleEngine` construction,
which fails the *entire engine* at startup (its constructor eagerly
initializes every rule), not just the new one. Check the shape against
`SCG006.yml` / `SCG007.yml`.

## Severity

Calibrate against precedent, not the enum in isolation: HIGH is
compromise-grade (RCE, credential/secret exposure — H2, hardcoded secrets,
unrestricted sensitive Actuator endpoints); MEDIUM is attack-surface
expansion or info disclosure without compromise (wildcard CORS, exposed
Swagger docs); LOW is present-but-ineffective (`Set-Cookie` via CORS
`exposed-headers`, which browsers block anyway); INFO is static-analysis
uncertainty and never fails the build on its own (see CLAUDE.md's Findings
section).

## Testing

Cover, at minimum:

* Silence with no evidence of the targeted feature/key.
* The core trigger and each aggravating factor separately (e.g.
  `web-allow-others`, `show-actuator`).
* All three placeholder states.
* Zero-Trust across profiles (parameterized: `dev`/`test`/`local`/`prod`),
  unless deviation is justified as above.
* Null-value safety.
* `ConfigurableRule`: source tested keys **dynamically from the shipped
  YAML** (see `EmbeddedConnectionCredentialsRuleTest`), not a hand-copied
  list that silently stops covering keys added later.
* Any prefix/boundary check: a negative test for an unrelated key sharing
  the prefix as a substring (`springdocument.path` vs. prefix `springdoc`).

## Before considering the task done

Follow CLAUDE.md's Implementation and Validation section. Two steps fail
silently if skipped:

* Register the rule in `META-INF/services/dev.scg.core.Rule` — forgetting
  this causes no error; the rule simply never runs.
* Update `RuleRegistryTest`'s exact-ID list — it will fail once the rule
  *is* registered; that's expected, update the list rather than treating
  it as a bug.

If the detection logic is non-trivial or you're not confident it behaves
as intended, run `.claude/skills/review-security-rule/SKILL.md` against it
before calling the task done.
