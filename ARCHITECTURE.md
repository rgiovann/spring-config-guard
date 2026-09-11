# Architecture Decision Records

This file holds ADRs for decisions that affect the project **as a whole** or
span **multiple rules/modules** — not decisions scoped to a single rule.

A rule's own scope calls (which properties it targets, why a default is or
isn't flagged, severity calibration, placeholder-handling shape) belong in
that rule's own Javadoc/comments, close to the code they explain — see
`InsecureServerTransportRule`, `ActuatorExposureRule`, etc. for the
established pattern. Don't duplicate those here.

Project-wide operating conventions (Relaxed Binding, Placeholder Resolution,
Zero-Trust profile policy, the rule-adding checklist) live in `CLAUDE.md`,
not here — this file is for point-in-time *decisions with trade-offs*, not
ongoing instructions.

Format: one ADR per section, numbered sequentially, never renumbered or
deleted once accepted (a later decision that changes course supersedes an
earlier ADR by referencing it, rather than rewriting history).

---

## ADR-001: Decoupling URI Property Catalogs Between Security Rules (SCG007 vs SCG012)

### Status
Accepted

### Context
Two rules both need the same catalog of Spring properties whose value is a
database/broker connection URI (`spring.datasource.url`, `spring.redis.url`,
`spring.data.mongodb.uri`, etc.):

* **SCG007** (`EmbeddedConnectionCredentialsRule`) inspects those URIs for
  plaintext credentials embedded in the userinfo section
  (`scheme://user:password@host`), plus JAAS configs for inline passwords.
* **SCG012** (`InsecureDatabaseTransportRule`) inspects the same URIs' query
  parameters for TLS opt-outs (`?useSSL=false`) and disabled certificate
  validation (`?trustServerCertificate=true`).

Both rules' `ConfigurableRule` metadata (`SCG007.yml`, `SCG012.yml`)
independently declare an almost identical `uri-based` list of property keys.
When SCG012 was built, this list was copied into its own YAML rather than
extracted into a shared source.

### Decision
Keep `SCG007.yml` and `SCG012.yml` independently declaring their own
`uri-based` list, accepting the duplication rather than introducing shared
metadata infrastructure for it.

This was a YAGNI call, not a deep domain-separation principle: no second,
proven need for a shared catalog has appeared yet, and the two rules never
share runtime state or execution order — the only real cost identified is
maintenance (a new URI-based property has to be added to both files).

### Consequences

**Positive**
* No new abstraction (a shared metadata source, a loader for it) had to be
  built for a two-file duplication that, so far, has been small and stable.
* Each rule's YAML stays self-contained and readable on its own — a
  contributor editing SCG012.yml doesn't need to know SCG007.yml exists.
* Each rule's test suite already loads its own YAML from the classpath
  independently (`InsecureDatabaseTransportRuleTest`,
  `EmbeddedConnectionCredentialsRuleTest`) — no cross-test coupling to
  maintain either.

**Negative / Trade-offs**
* A new URI-based Spring property (e.g., a future reactive driver) must be
  added to both YAML files by hand; nothing enforces they stay in sync.
* If the two lists drift silently, only manual review or the ID-list
  assertions in `RuleRegistryTest` would ever catch it — and that test
  doesn't compare the two YAMLs' *content* today, only registered rule IDs.

### Revisit if
A third rule needs the same `uri-based` catalog, or the two lists are
caught drifting in a way that caused a real gap (not just theoretical) —
at that point, extracting a shared source stops being speculative.
