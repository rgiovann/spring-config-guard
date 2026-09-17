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

---

## ADR-002: Config Server Mode as a Separate Assembler, Not a Branch in the Existing Pipeline

### Status
Accepted

### Context
A Spring Cloud Config Server backing repository (confirmed against a real
one, `spring-petclinic/spring-petclinic-microservices-config`) is shaped
fundamentally differently from a single Spring Boot project: config files
are named after each client service (`spring.application.name` — e.g.
`customers-service.yml`), not `application*`, and a Global `application.yml`
is merged into every one of them. Without support for this shape, every
per-service file was silently invisible to SCG — `ConfigLoader`'s file
discovery only recognizes the `application*` prefix, and `ConfigFileGrouper`
hard-assumes exactly one logical app per directory (its own Javadoc states
this scope explicitly). Confirmed on the real repo above: with the regular
pipeline, only `application.yml` itself was scanned, and it produced zero
findings for the 8 real services actually defined there.

### Decision
Introduce `ConfigServerAssembler`, a new class in `dev.scg.core`, activated
by an explicit `--config-server` CLI flag — rather than adding
`if (configServerMode)` branches inside `ConfigFileGrouper`/`ProfileMerger`.
It owns the entire Global-vs-service discovery, classification, and 4-layer
merge cascade (`Global-base < Global-profile < Service-base <
Service-profile`, confirmed against the Spring Cloud Config reference doc
before implementation, not assumed) for this mode.

It reuses only the two primitives that are genuinely mode-agnostic, both
promoted from `private` to package-visible for that reason:
`ConfigLoader.loadFile()` (single-file YAML/properties parsing, extracted
from `loadDirectory()`'s loop body) and `ProfileMerger.mergeProperties()` /
`findBaseProperties()` (the pairwise base+overlay merge semantics —
list-replacement, canonical purge — folded four times via `Stream.reduce`
instead of the regular pipeline's single base+profile call).

Two narrower calls made as part of the same decision:

* **Not recursive**, unlike `ConfigLoader.loadDirectory()`. A Config Server
  repository is conventionally one flat directory; recursing risks reading
  unrelated YAML (CI workflows, `docker-compose.yml`) as if it were Spring
  configuration.
* **No `{service}-{profile}.yml` filename convention.** Unlike the fixed
  `"application"` prefix, a service name is arbitrary and routinely
  contains hyphens itself (`customers-service`, `api-gateway`), so
  `customers-service-mysql.yml` can't be reliably split into service +
  profile without an externally supplied list of valid service names.
  Profiles for a service are read only from `spring.config.activate.on-profile`
  documents inside that service's own file.

No new field was added to `Finding`/`EffectiveConfig` for "which service."
`EffectiveConfig.sourceFile()` is always the service's own file (never
`application.yml`, which only ever appears merged in) — already sufficient
to identify the service in a report, the same way an unnamed base config
never gets reported standalone in the regular pipeline either.

### Consequences

**Positive**
* Zero risk to the existing, heavily-tested default pipeline —
  `ConfigFileGrouper`/`ProfileMerger`'s public contracts and their test
  suites are completely untouched; only two methods gained package
  visibility.
* Each pipeline stage keeps a single, narrow responsibility, consistent
  with this project's general architecture principle — Config Server
  Mode's added complexity is fully contained in one new class instead of
  being smeared across the regular pipeline's classes.
* `Finding`, the console/JSON `Reporter`s, and their schemas are completely
  unchanged — no consumer of the JSON output sees a breaking change for a
  mode they may not even use.
* Validated against the real repository that motivated the feature:
  `spring-petclinic-microservices-config` — 53 findings across 8 services,
  matching the repository's actual file listing one-to-one, console and
  JSON output cross-checked to carry identical data.

**Negative / Trade-offs**
* File discovery is not shared between modes: `ConfigServerAssembler`'s
  top-level, non-`application`-filtered scan and `ConfigLoader.loadDirectory()`'s
  recursive, `application*`-filtered walk are separate, small
  implementations rather than one configurable abstraction. Deliberate
  (the two semantics are genuinely different), but a future reader might
  expect a single shared discovery path.
* `{service}-{profile}.yml` as a separate file (a convention some real
  Config Server repos use) is unsupported. Such a repo would only be
  partially visible: the service's base file and everything inherited from
  Global would be picked up, but a profile expressed as its own dedicated
  file would be silently skipped — the exact kind of gap this feature
  exists to close, just for a case not yet handled.
* No auto-detection of "is this actually a Config Server repository."
  Pointing `--config-server` at a regular Spring Boot project's
  `src/main/resources` would treat every non-`application` file in it as
  its own "service" — garbage in, garbage out; not something the tool
  tries to validate.

### Revisit if
A real Config Server repository using the `{service}-{profile}.yml` file
convention is encountered — at that point, an explicit
`--services=<comma-separated list>` flag (resolving the filename ambiguity
without guessing) is the likely next step, not filename heuristics.
