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
Accepted. Since ADR-011, SCG007 no longer detects through a key catalog;
since the SCG012 review (`VALIDATION.md`, "SCG012 driver modes"), SCG012's
`uri-based` list only drives its scheme check, and its query parameter
checks apply to any database connection string.

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
Accepted. Since ADR-012, the assembler groups each service's documents in
source order (Global files without a profile, the service's files, Global
`application-{profile}` files) and `ProfileMerger` folds them, instead of
the four-layer cascade below; the rest of this decision holds.

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

---

## ADR-003: Folding Multiple Physical Sources of the Same Profile Label Before Merging

### Status
Superseded by ADR-012, which folds every document that applies to a set of
active profiles in source order, instead of a fold per profile label. The
precedences below still hold, as part of that order.

### Context
A `/actuator/env` benchmark against a real Spring Boot app (see
`VALIDATION.md`, "ProfileMerger correctness benchmark") exposed a silent
data-loss bug: a directory holding both `application.yml` and
`application.properties` as base files lost **every** property of one of
them. With `application.yml` containing `from.yaml: yes` and
`application.properties` containing `from.properties=yes`, SCG's base
configuration was `{from.properties=yes}` — not an override (the keys are
disjoint), a whole file dropped. `ProfileMerger.findBaseProperties()`
returns the first base document it finds (its documented contract: at most
one document per label), while `ConfigFileGrouper` concatenated documents
from every physical file without ever combining two that resolve to the
same label. Since `ConfigLoader.loadDirectory()` walks the directory
without sorting, which file "won" wasn't even deterministic across file
systems. Any project with both formats side by side (a Spring Initializr
`application.properties` plus a later `application.yml`, or a legacy
migration) was affected, and every rule was blind to the dropped file.

The same shape applies to a named profile, which can have up to three
sources in one directory: `application-prod.properties`,
`application-prod.yml`, and a `spring.config.activate.on-profile: prod`
document inside a base file.

### Decision
`ConfigFileGrouper` folds every source resolving to the same label into one
document, in ascending precedence, before `ProfileMerger` runs:

* **Base:** `.yml` < `.yaml` < `.properties`.
* **Named profile:** on-profile block in a base file (`.yml` < `.yaml` <
  `.properties`) < named profile file (`.yml` < `.yaml` < `.properties`).

Where each precedence comes from:

* `.properties` beats `.yml`/`.yaml` on a key conflict at the same level —
  documented behavior, see
  [spring-boot#25121](https://github.com/spring-projects/spring-boot/issues/25121),
  and matched by the benchmark.
* A named profile file (`application-prod.yml`) and an on-profile block
  (`on-profile: prod` inside `application.yml`) **merge** — a key present
  only in the block survives — and the named file wins a key conflict.
  Confirmed empirically against Spring Boot 4.1.1 through `/actuator/env`
  (the benchmark's 6th assertion), not assumed.
* `.yml` vs. `.yaml` between themselves isn't covered by the reference
  documentation; the order is an arbitrary but deterministic tie-break, so
  the result no longer depends on the file system.

The fold reuses `ProfileMerger`'s pairwise merge semantics (list
replacement, canonical purge, explicit-null override) rather than a second
merge algorithm — but through `ProfileMerger.mergeWithoutStrippingSentinels()`,
not `mergeProperties()`. Folding with `mergeProperties()` broke in two ways,
both found only because the benchmark had an explicit-null override
coinciding with the new fold:

* `NullPointerException`: the fold resolves a `null` override into a real
  Java `null` immediately, and `ConfigDocument` used `Map.copyOf()`, which
  rejects `null` values. `ConfigDocument` now uses
  `Collections.unmodifiableMap(new LinkedHashMap<>(...))`.
* Silent loss of an explicitly emptied list: stripping the internal
  sentinels during the fold would erase the empty-list marker before the
  real base/profile merge, so that later pass would no longer purge the
  base's list. Sentinels are stripped only by the final merge.

### Consequences

**Positive**
* No file in a directory is silently dropped anymore, and the result is
  deterministic.
* Validated against a real Spring Boot app: all 6 benchmark assertions
  match (`VALIDATION.md`), with regression cases in `ConfigFileGrouperTest`
  (disjoint keys, key conflicts, on-profile vs. named file, explicit-null
  override during the fold).
* One merge algorithm, used at two points, instead of two implementations
  that could drift.

**Negative / Trade-offs**
* `ConfigDocument.properties()` may now contain `null` values; every
  consumer of an intermediate (pre-merge) document must tolerate them.
  Since 2026-10-05 an explicit-null override resolves to an empty string,
  as Spring Boot's YAML loader turns a null into one (checked through
  `/actuator/env`), so no merge produces a `null` value anymore; the
  tolerant copy stays.
* `ProfileMerger` exposes two merge entry points that differ only in
  sentinel stripping; picking the wrong one reintroduces the silent
  list-purge bug above, with no compile-time signal.
* Folding happens **per directory**. Precedence across configuration
  locations (`classpath:/`, `classpath:/config/`, `./`, `./config/`) is not
  modeled — each directory is still evaluated as its own group (see
  ADR-005).

### Revisit if
A benchmark run on a newer Spring Boot version disagrees with any of the
precedences above, or the Spring Boot reference documentation starts
specifying the `.yml`/`.yaml` order.

Revisited on 2026-10-06 for the `.yml`/`.yaml` order, which the benchmark
now measures (`VALIDATION.md`, "ProfileMerger correctness benchmark", case
35): Spring Boot 4.1.1 gives `.yml` precedence over `.yaml`, the reverse of
the tie-break above, which let SCG report a value Spring overrides. The
order is now `.yaml` < `.yml` < `.properties`, for base and named profile
files alike; the rest of this decision is unchanged.

---

## ADR-004: `spring.config.import` Surfaced as a Coverage Warning, Not Followed

### Status
Accepted

### Context
A file can pull in other configuration through `spring.config.import`.
`ConfigLoader` never visits the imported location, so its content is
invisible to every rule and the report comes out clean as if it didn't
exist. That is a silent trust gap rather than an epistemic limit: the
imported file often exists on disk, SCG just never opens it. (Real
environment variables, system properties and CLI arguments are a different
case — they don't exist until the app runs, so no static tool can read
them; see README, "Scope & Limitations".)

### Decision
**Do not follow imports.** Resolving the import graph was evaluated against
the Spring Boot reference documentation
(["Externalized Configuration"](https://docs.spring.io/spring-boot/reference/features/external-config.html))
and rejected for five concrete reasons:

1. **`configtree:` is neither YAML nor properties.** It is a directory where
   each file is a key and its content is the value (Kubernetes Secrets and
   ConfigMaps mounted as volumes). Supporting it means a new parser, not an
   extension of `ConfigLoader`.
2. **Relative locations resolve against the importing file's directory**,
   not the scan root. That turns "a list of files in a folder" into "a graph
   of files, each with its own base directory".
3. **Imports can be recursive.** An imported file can import another, which
   requires cycle detection (`A` imports `B`, `B` imports `A`), not a
   one-step lookup.
4. **A second precedence axis.** The documentation states that later
   imports take precedence and that imported values take precedence over
   the importing file. That axis crosses the existing base < profile merge.
   Getting the combination wrong doesn't fail to compile — it produces a
   plausible but incorrect effective configuration, the worst outcome for a
   security gate: false, silent confidence.
5. **Some imports are not static at all.** `spring.config.import=configserver:`
   fetches configuration from a **running** Config Server over the network at
   startup. No amount of engineering resolves that statically without turning
   SCG into a runtime agent, which contradicts the project's premise of no
   Spring Boot dependency.

**Make the incompleteness visible instead.**
`ConfigImportCoverage.filesWithUnfollowedImport()` counts the distinct
source files (not `EffectiveConfig`s — a file with three profiles inheriting
the key counts once) that declare `spring.config.import`, and `Main` prints
unconditionally to stderr when the count is above zero:

```
spring-config-guard: N file(s) import external configuration via spring.config.import that was not scanned.
```

It deliberately sits outside the rule pipeline — no `Rule`, no `Finding`,
unaffected by `Policy` and `--fail-on`, the same pattern as the Policy
suppression count. A first proposal was a new rule (`SCG018`, `INFO`
finding), rejected for alert fatigue: "an entire file was never opened" is a
larger class of uncertainty than "this property has an ambiguous value"
(the typical `INFO`), and giving both the same severity would bury the more
important signal among the smaller ones. No existing severity fits
(`HIGH`/`MEDIUM`/`LOW` presuppose a determined risk), and a fifth severity
would be a premature generalization with no second use case.

### Consequences

**Positive**
* The gap is surfaced on every run, in console and `--json` mode alike
  (stderr is independent of the `Reporter` format), without changing the
  `Finding` model or either report schema.
* No partial import resolver that could silently compute a wrong effective
  configuration.
* Covered by `ConfigImportCoverageTest` and two `DemoProjectShowcaseTest`
  cases against `demo-project/config-import-showcase/`.

**Negative / Trade-offs**
* Imported content remains unscanned; the warning says so but can't say
  what is in it.
* The warning never affects the exit code — a CI gate with `--fail-on`
  passes even when an import went unscanned. Only someone reading stderr
  sees it.

### Revisit if
Real users need local imported files scanned. Reasons 2–4 would have to be
designed first; reason 5 (`configserver:` and other network-backed
locations) stays out of scope regardless.

---

## ADR-005: Multiple Spring Config Locations Surfaced as a Coverage Warning, Not Merged

### Status
Accepted

### Context
Spring Boot merges config files from several locations into one
`Environment` — lowest to highest precedence: `classpath:/`,
`classpath:/config/`, `file:./`, `file:./config/`. `ConfigFileGrouper`
groups by directory, so each of those becomes an independent
`EffectiveConfig` (ADR-003's fold is per directory). Merging across
locations was deferred earlier, for a reason that still holds: a heuristic
that guesses which directories belong to the same application can silently
fuse two modules of a monorepo into one incorrect `EffectiveConfig`.

Confirmed with fixtures against the built jar that this has a concrete cost
beyond "not modeled". For rules that combine two keys, a risk split across
two locations disappears: `allowed-origins: "*"` in
`src/main/resources/application.yml` plus `allow-credentials: true` in
`config/application-prod.yml` (or `src/main/resources/config/application.yml`)
is SCG003 HIGH in the real `prod` environment, but SCG reports nothing and
`--fail-on=HIGH` exits 0. Single-key rules err the safe way instead (a risky
classpath value overridden by a safe `config/` value is still flagged). The
false negative was silent: nothing in the report said the result depended
on a merge SCG never performed — the same class of trust gap as an
unfollowed `spring.config.import` (ADR-004).

Note (SCG003 review, `VALIDATION.md`, "SCG003 CORS scenarios"): the example
above doesn't hold as written. With `allow-credentials: true`, Spring
rejects `allowed-origins: "*"` (the Actuator endpoint mapping fails at
startup), so the merged `prod` environment wouldn't run. The risk is real
with `allowed-origin-patterns: "*"`, which `config-location-showcase` now
uses; the conclusion is unchanged.

### Decision
Keep evaluating directories independently, and make the gap visible.
`ConfigLocationCoverage.modulesWithMultipleLocations()` reports module
roots `R` with config files in two or more of:

* `R/src/main/resources` (`classpath:/`)
* `R/src/main/resources/config` (`classpath:/config/`)
* `R/config` (`file:./config/`, assuming the app starts from `R`)

`Main` prints unconditionally to stderr when the count is above zero:

```
spring-config-guard: N application(s) have config files in more than one Spring config location, evaluated independently -- a risk split across locations can be missed, and a finding can be one that a setting in another location already turns off.
```

Same shape as ADR-004's warning, for the same reasons: outside the rule
pipeline (no `Rule`/`Finding`), unaffected by `Policy` and `--fail-on`, no
change to either report schema.

Detection is deliberately narrow, tied to the structure of one module so a
monorepo never produces a false alarm:

* Locations are only related through a shared `R/src/main/resources`.
  Sibling modules, each with its own single location, are never counted as
  one application. A `config/` directory without a sibling
  `src/main/resources` is not evidence of a Spring module root.
* `file:./` (config files at the module root itself) is not recognized.
  Its meaning depends on the working directory the app is started from,
  which SCG can't know, and a root-level `application.yml` is rare enough
  that the added false-alarm risk isn't justified yet. `R/config` carries
  the same working-directory assumption, but a `config/` directory next to
  `src/` is a strong, conventional signal.
* `src/test/resources` is not a runtime location and is not counted.

### Consequences

**Positive**
* The silent false negative now always comes with a visible warning, in
  console and `--json` mode alike.
* No merge heuristic that could compute a wrong `EffectiveConfig`; the
  monorepo concern that deferred merging is fully respected.
* No false alarm on the fixtures and real-world repositories already
  validated (`spring-petclinic`, `spring-boot-admin`); covered by
  `ConfigLocationCoverageTest` and two `DemoProjectShowcaseTest` cases
  against `demo-project/config-location-showcase/`.

**Negative / Trade-offs**
* The risk itself is still not detected — the warning says the result is
  incomplete, not what is missing.
* Like ADR-004's warning, it never affects the exit code; a CI gate with
  `--fail-on` passes while it's printed.
* Locations outside the three recognized ones (`file:./`,
  `file:./config/*/`, `spring.config.location`/`additional-location`) stay
  invisible, with no warning.

### Revisit if
Real users need risks across locations detected, not just flagged. The
next step would be an explicit, user-declared location list (not directory
heuristics), which is the configuration surface originally planned for
non-standard project layouts.

---

## ADR-006: Test Source Sets and Build Output Excluded from the Scan

### Status
Accepted

### Context
`ConfigLoader.loadDirectory()` walks the scan root recursively and picked up
every `application*` file it found, including two kinds of directory whose
config never ships with the application:

* **Build output.** `mvn package` copies `src/main/resources/application.yml`
  to `target/classes/application.yml` (Gradle: `build/resources/main/`).
  When SCG runs after a build — common in CI, where the lint step often
  follows packaging — every finding appears twice. Worse, a stale build still
  holds a value already fixed in the source, and Maven resource filtering
  writes substituted values (`@db.password@` → the real one), so SCG would
  evaluate content that differs from what is versioned. The real-world runs
  in `VALIDATION.md` never showed this only because they used fresh clones.
* **Test source sets.** `src/test/resources` legitimately holds config that
  would be a finding in production (an H2 console on, a fixed password for
  an in-memory database). It isn't packaged. Confirmed with a fixture: H2
  disabled in `src/main/resources` but enabled in `target/classes` and
  `src/test/resources` produced two SCG002 HIGH findings — failing a
  `--fail-on=HIGH` gate on a project whose shipped config is safe.

A team can't work around the test case with a Policy: suppression is per
rule + profile, not per directory, and test config usually lands in the same
base profile as the main config, so suppressing it would also hide the same
rule for `src/main/resources`.

### Decision
Skip, during the recursive walk:

* `target/` or `build/` directly next to a `pom.xml`, `build.gradle` or
  `build.gradle.kts` — the build file is what identifies it as build output,
  so a directory that merely happens to be named `build` in a non-standard
  layout is still scanned.
* `src/test/` — test source sets, by convention in both Maven and Gradle.

Only directories strictly below the scan root are considered: passing
`src/test/resources` or `target/classes` directly as `<project-path>` still
scans it, as an explicit choice by the user.

This does not contradict the Zero-Trust convention (CLAUDE.md, "Profiles
(Zero-Trust)"). That convention is about profiles — a `dev` profile can
still run against shared infrastructure — while a test source set is never
part of the running application at all.

No stderr notice is printed for skipped files: unlike an unfollowed import
(ADR-004) or a split across config locations (ADR-005), skipping them hides
nothing that reaches production.

### Consequences

**Positive**
* No duplicated or stale findings when SCG runs after a build, and no
  findings from test-only config that no Policy could target precisely.
* On the real-world runs in `VALIDATION.md`, only `spring-boot` changed: 66
  findings in 41 files became 64 in 39, both removed findings coming from
  `src/test/resources`; no finding was added anywhere.
* Covered by `ConfigLoaderExclusionTest` (Maven and Gradle output,
  multi-module projects, directories named `test`/`target`/`build` that must
  still be scanned, explicit scan roots).

**Negative / Trade-offs**
* A project that deliberately packages a file from `src/test/` into a
  production artifact, or builds into a directory other than
  `target/`/`build/`, is not covered by this convention: the first is now
  missed, the second is still scanned.
* A `target/` or `build/` next to a build file is always skipped, even if
  a project kept hand-written config there — unlikely, since Maven and
  Gradle own and regularly wipe those directories.

### Revisit if
A real user needs `src/test/` scanned (e.g. integration-test config pointed
at shared infrastructure) — an explicit opt-in flag would be the next step,
not a change to the default.

---

## ADR-007: Bracketed Map Keys Rewritten into Dotted Form at Load Time

### Status
Accepted. Since ADR-008, YAML flattening no longer produces `x.map.[a.b]`
(the context below); the decision is unchanged.

### Context
Spring Boot's bracket notation keeps a map key intact when it contains dots
or other special characters — e.g. `spring.kafka.properties[security.protocol]`
or, in YAML, a quoted `"[security.protocol]"` key. Checked with Spring Boot
4.1.1's own `Binder` and `YamlPropertySourceLoader`:

* `x.map[a.b]=v` and `x.map.a.b=v` bind to the same entry (`a.b`) of a
  `Map<String, String>`;
* the YAML loader turns `"[a.b]"` under `x.map` into `x.map[a.b]`;
* maps are merged across property sources key by key: base `[a]`, `[b]`
  plus profile `[c]` binds `{a, b, c}`, and a profile overriding `[a]`
  replaces only `a`.

SCG handled none of this. Rules look map entries up by their dotted name, so
the bracketed spelling was invisible to them — with the jar of v1.3.0,
`spring.kafka.properties[sasl.jaas.config]` holding a plaintext password
raised no SCG007, and `[security.protocol]=SASL_SSL` raised a false SCG014
(PLAINTEXT assumed). `ProfileMerger` reads `[` as the start of a list index
and replaces lists whole, so a profile defining one bracketed map entry
dropped every base entry of that map — a silent false negative for any
rule reading them in that profile. YAML flattening also produced
`x.map.[a.b]` while `.properties` produced `x.map[a.b]`, so the same key in
the two formats was not recognized as one.

### Decision
`ConfigLoader.normalizeMapKeys()` rewrites every bracketed segment whose
content is not a numeric list index into dotted form, for both YAML and
`.properties`, before anything else sees the key:
`x.map[a.b]` and `x.map.[a.b]` become `x.map.a.b`; `x.list[0]` stays as is;
`x.list[0].map[a.b]` becomes `x.list[0].map.a.b`; empty or unclosed brackets
are left literal.

Chosen over teaching bracket semantics to `RelaxedProperties` and
`ProfileMerger` (telling a list index from a map key everywhere a key is
compared or purged): that alternative touches the merge's purge logic and
every rule lookup, for more precise messages only, while one rewrite at the
single entry point fixes rule lookups, the merge and the format mismatch at
once, with no rule changed.

### Consequences

**Positive**
* Bracketed map keys are detected under the names rules already look up,
  in both formats; SCG007/SCG014 now behave the same for either spelling.
* Maps merge key by key across profiles, as in Spring.
* Covered by `BracketedMapKeysTest` (normalization cases, merge in both
  formats, override of a single entry, cross-format key identity, SCG007
  and SCG014 end to end; the SCG014 and SCG007 cases fail on v1.3.0).
* Checked against a running Spring Boot app as well: the `/actuator`
  benchmark in `VALIDATION.md` compares SCG's merged map with the one
  `/actuator/configprops` shows bound, the collision below included, and
  fails with the `ConfigLoader` from before this decision.

**Negative / Trade-offs**
* Finding messages name the dotted key, not the bracketed spelling the
  user wrote.
* Accepted collision: brackets preserve characters that relaxed binding
  ignores, so `[com.foo-bar]` and `[com.foobar]` are two entries in Spring
  but canonicalize to one key here, the later overriding the earlier. Rare,
  and pinned by a test so the limitation stays visible. The divergence is
  specific to brackets: checked later with Spring Boot 4.1.1 through
  `/actuator/configprops`, from a `.properties` file, unbracketed
  `x.map.com.foo-bar=A` and `x.map.com.foobar=B` also bind two map keys,
  `com.foo-bar` and `com.foobar`, but both get the same value (`A` in that
  run), since the key names keep the dash while the value lookup is
  relaxed. So SCG's single key matches Spring holding one value for both
  spellings (which of the two values SCG keeps was not checked); only a
  bracketed pair gets two different values in Spring.
* None of the reference projects in `VALIDATION.md` uses bracketed keys:
  the fix is proven by fixtures, by Spring's own binder and by the
  benchmark app, not yet by a real-world project.

### Revisit if
A rule needs the original bracketed spelling (e.g. to quote it back), or
the dash/underscore collision shows up in a real project.

## ADR-008: YAML Flattening Joins Bracketed Keys Like Spring's YAML Loader

### Status
Accepted

### Context
Flattening a YAML document joined every key to its parent with a dot. A key
starting with `[` therefore came out as `x.[0]` or `x.map.[a.b]`, while
Spring Boot's YAML loader joins such a key without a dot: confirmed with
Spring Boot 4.1.1, where `/actuator/env` shows a quoted `"[0]"` key under
`quoted-index` as `quoted-index[0].url`, and (ADR-007) `"[a.b]"` under
`x.map` as `x.map[a.b]`.

ADR-007 absorbed the dot for map keys, since `normalizeMapKeys()` rewrites
`x.map.[a.b]` and `x.map[a.b]` alike. It kept numeric indices verbatim,
dot included, so a list index written as a quoted YAML key stayed `x.[0]`:
a key `ProfileMerger` doesn't recognize as part of list `x`, and that
`RelaxedProperties.valuesForKeyOrListChildren()` doesn't read as one of its
items. Measured with the jar before this decision:

* a profile writing `"[0]": {url: ...}` over a base list of objects kept
  the base's whole list (Spring binds only the profile's element), so SCG006
  reported a base password Spring had dropped: a false positive;
* `exposure.include: {"[0]": "*"}` raised no SCG001: a false negative on a
  HIGH rule.

Found by the `/actuator` benchmark's lists-of-objects cases
(`VALIDATION.md`). The spelling is rare: no reference project uses it.

### Decision
`ConfigLoader.flatten()` joins a key starting with `[` to its parent without
a dot, as Spring's YAML loader does: `x` + `"[0]"` is `x[0]`, and
`x.map` + `"[a.b]"` is `x.map[a.b]`, which `normalizeMapKeys()` still
rewrites to `x.map.a.b` (ADR-007). `.properties` keys are unchanged.

Chosen over also dropping the dot before a numeric index in
`normalizeMapKeys()`: that would repair the key after writing it wrong, and
would also rewrite a `.properties` key literally written `x.[0]`, whose
meaning in Spring was not checked. Fixing the join matches Spring's own
rule at the one place keys are built from YAML.

### Consequences

**Positive**
* A list index written as a quoted YAML key is the same key as a list item:
  the profile replaces the base's list, and rules read the item.
* The YAML and `.properties` spellings of a bracketed key match before
  normalization, not only after it.
* Covered by `BracketedMapKeysTest` (the join, the profile replacing the
  base's list without the SCG006 false positive, SCG001 on the wildcard;
  all three fail before this decision) and by the benchmark's
  lists-of-objects test, which compares with `/actuator/configprops` and
  failed on the quoted index case before this decision. Findings on every
  reference project are byte-identical to before.

**Negative / Trade-offs**
* None known. A YAML key starting with `[` that isn't meant as a bracketed
  key would now join without a dot, but Spring's loader treats it that way
  too.

### Revisit if
Spring changes how its YAML loader joins keys starting with `[`.

## ADR-009: Spring Cloud Stream Kafka Binders Evaluated as Their Own Contexts

### Status
Accepted

### Context
SCG007 and SCG014 read only Spring Boot's `spring.kafka.*` namespace. The
Spring Cloud Stream Kafka and Kafka Streams binders configure Kafka clients
through their own properties, so the same risks written there went
unreported. Found in `spring-cloud-stream-samples` (`VALIDATION.md`): a
plaintext JAAS password and `SASL_PLAINTEXT` inside
`spring.cloud.stream.binders.<name>.environment.*`, and `SASL_PLAINTEXT` in
`spring.cloud.stream.kafka.binder.configuration`, all silent.

How the binder resolves its configuration, read in Spring Cloud Stream's
source (`main`, 2026-09-25):

* `KafkaBinderConfigurationProperties` builds each consumer and producer
  configuration from Spring Boot's `spring.kafka.*` properties, then the
  binder's `configuration` map (entries valid for that client), then its
  `consumer-properties`/`producer-properties` map. The admin client does
  the same with `configuration` ("binder properties supersede boot kafka
  properties", `KafkaTopicProvisioner`). The Kafka Streams binder's
  properties extend the Kafka binder's and follow the same order on top of
  `spring.kafka.streams.*`.
* A named binder's `environment` map is added to that binder's own context
  as its highest-precedence property source, and the application's
  environment is merged below it unless `inherit-environment` is false
  (`DefaultBinderFactory`).

### Decision
Both rules read the binders as Spring Cloud Stream does. A helper
(`KafkaBinderContexts`) builds the main context and one context per named
binder: its `environment` on top of the main context, which it inherits
unless `inherit-environment` is false.

* SCG007 also inspects `sasl.jaas.config` in the `configuration`,
  `consumer-properties` and `producer-properties` maps of both binders, and
  matches a key written inside a named binder's environment without that
  prefix.
* SCG014 keeps its `spring.kafka.*` checks unchanged and adds:
  * every insecure value a context writes itself: the binder maps'
    `security.protocol`, and, inside a named binder's environment, the
    `spring.kafka.*` keys it already checks at the top level. A top-level
    value inherited by several binders is reported once;
  * a binder in use with no protocol covering all its clients: the binder's
    `configuration` map or Spring Boot's common keys, since a per-client
    map leaves the admin client and the other client type on Kafka's
    `PLAINTEXT` default. Reported per context, not in the main context when
    the existing `spring.kafka.*` check already reports the same gap, or
    when named Kafka binders exist (the main context is then only
    inherited).

"Binder in use" means a key under the binder's prefix in that context, or a
named binder whose `type` is `kafka` (or `kstream`/`ktable`/`globalktable`
for the Kafka Streams binder).

Evaluating each binder's environment as its own context was chosen over
matching environment keys as one more prefix: the environment overrides
the main context for that binder only, so an `environment` value of
`spring.kafka.security.protocol: SSL` makes that binder secure without
making the main context secure. A separate `EffectiveConfig` per binder was
rejected: it would change the pipeline, and every other rule, for two
rules.

The "binder in use but protocol unset" check was included after measuring
it: 29 findings in 24 files of `spring-cloud-stream-samples`, all samples
that configure Kafka only through the binder. It is the check SCG014
already applies to `spring.kafka.*`; leaving it out would report a project
configured through Spring Boot's properties and stay silent on the same
project configured through the binder.

### Consequences

**Positive**
* Closes the two false negatives: on the reference corpus, 2 SCG007 and 3
  SCG014 findings on values written in the binder, plus 29 SCG014 findings
  for binders without a protocol, all in `spring-cloud-stream-samples`;
  every other reference project is unchanged.
* Messages name the key as written, including the binder's environment
  prefix, and the binder a finding is about.
* Covered by `KafkaBinderRulesTest`: the binder maps, both binders, the
  precedence over `spring.kafka.*`, inheritance and `inherit-environment`,
  one finding for an inherited value, no duplicate with the existing check.

**Negative / Trade-offs**
* A protocol set only through an environment variable is invisible, as it
  already was for `spring.kafka.*`: such a binder is reported as unset.
* A project using the binder with no binder key at all (only its defaults)
  isn't recognized as using it: SCG sees configuration files, not the
  classpath.
* Other binders (RabbitMQ, Pulsar) and other rules are not binder-aware.
  SCG006 needs nothing: it matches key names anywhere, environment
  included.

### Revisit if
Spring Cloud Stream changes how its binders merge properties or build a
binder's environment, or another rule needs binder contexts (the helper is
there to reuse).


## ADR-010: A Finding Based on an Absent Key Is Reported One Level Below a Written Value

### Status
Accepted

### Context
Some rules report a risk because a key is absent and Spring's or the
client's default is insecure, not because an insecure value is written:
SCG014 when Kafka is configured but no `security.protocol` is set (Kafka's
default is `PLAINTEXT`), for `spring.kafka.*` and, since ADR-009, for the
Spring Cloud Stream Kafka binders; SCG015 when RabbitMQ is configured but
`spring.rabbitmq.ssl.enabled` is absent or resolves to an empty default
(`${RABBIT_SSL:}`). Both were HIGH, the same as an insecure value written in
the file.

The evidence is not the same. `security.protocol: PLAINTEXT` in the file is
certain. An absent key is nearly certain, but SCG sees configuration files
only: production often sets such a key through an environment variable, a
command-line argument or a Config Server, and SCG can't see any of them.
On the reference corpus, 31 of the 34 SCG014 findings in
`spring-cloud-stream-samples` and the one SCG014 finding in `spring-boot`
were of this kind (`VALIDATION.md`).

Before deciding, every rule was checked for findings based on absence.
Besides SCG014 and SCG015:

* SCG011, SCG012 and SCG016 stay silent when the key is absent;
* SCG006 already reports a blank value as INFO;
* SCG008 reports a default-on feature (SpringDoc) with no explicit disable,
  already MEDIUM;
* the other rules report written values only.

### Decision
A finding whose only evidence is an absent key with an insecure default is
reported as **MEDIUM**. The same risk with an insecure value written in the
files stays **HIGH**. INFO keeps its meaning (static analysis can't tell
whether there is a risk): an absent key is not undeterminable, Spring's
default is known and insecure, so it is reported, one level lower.

Each such finding's message ends by saying why it is MEDIUM ("... may be set
outside these files, e.g. by an environment variable"), so a reader doesn't
mistake it for a lesser risk.

Applied to SCG014 (the `spring.kafka.*` check and the binder check) and to
SCG015's "not configured" finding. Explicit `PLAINTEXT`/`SASL_PLAINTEXT` and
`ssl.enabled=false` (literal or as a placeholder's default) stay HIGH.

Alternatives rejected:

* **INFO.** It would no longer fail a CI gate at any `--fail-on` level
  (INFO never fails the build on its own), hiding a risk that is real in
  most projects that leave the key out.
* **Keeping HIGH.** It treats a key set in production through the
  environment the same as a key written insecurely, so the default gate
  fails on projects that are configured correctly, and `--policy` becomes
  the routine answer instead of the exception.
* **Exempting profiles or merging findings per file.** A profile exemption
  breaks Zero-Trust (`CLAUDE.md`), and `--policy` already suppresses
  explicitly. Merging per file doesn't reduce the count: the 31 absence
  findings in `spring-cloud-stream-samples` are in 26 files, and where a
  file has several, they are different binders.

### Consequences

**Positive**
* Severity reflects how certain the evidence is: HIGH means an insecure
  value is in the files.
* The default gate (`--fail-on=HIGH`) no longer fails on a project that sets
  the protocol or SSL through its environment. `--fail-on=MEDIUM` still
  fails on it.
* On the reference corpus, only severities change: 31 SCG014 findings in
  `spring-cloud-stream-samples` and 1 in `spring-boot` go from HIGH to
  MEDIUM; the other findings and all other runs are byte-identical to
  v1.5.0 (`VALIDATION.md`).

**Negative / Trade-offs**
* A user relying on `--fail-on=HIGH` stops failing on these findings. A
  recalibrated severity is a detection change, not a MAJOR one
  (`CONTRIBUTING.md`, "Releases"), and the release lists it under
  **Detection changes**.
* A project that really runs with the insecure default is now reported one
  level lower than before.

### Revisit if
SCG gains a way to see the environment a configuration runs with (it would
then know whether the key is set), or a new rule reports absence: it
follows this ADR, unless its Javadoc explains why not.

---

## ADR-011: SCG007 Detects Embedded Credentials by the Value's Shape, in Every Property

### Status
Accepted. Supersedes ADR-001 for SCG007, which no longer detects through a
key catalog; ADR-001 still describes SCG012.

### Context
SCG007 inspected only the keys in its `uri-based` and `jaas-based` lists,
and only one credential form per kind. Reviewed against the clients that
read these values, in the versions Spring Boot 4.1.1 manages
(`VALIDATION.md`, "SCG007 credential forms"), it reported 1 of 15 real
credential forms and one false positive:

* the list had gone stale: `spring.redis.url` and `spring.data.mongodb.uri`
  are deprecated, and Spring Boot 4's `spring.data.redis.url` and
  `spring.mongodb.uri`, whose descriptions say the URL carries the
  password, were missing, as were `spring.flyway.url`, the pool-specific
  JDBC URLs and the Kafka per-client `sasl.jaas.config`. A list never
  covered Spring Cloud (`spring.cloud.config.uri`, Eureka's `defaultZone`)
  or the application's own keys either. ADR-001's "revisit if" had
  happened: the lists drifted and left a real gap, in SCG012's list too;
* only `scheme://user:password@host` was recognized, while PostgreSQL reads
  `?password=` (and rejects the user-info form), SQL Server and H2 read
  `;password=`, Oracle reads `user/password@host`, and Kafka accepts JAAS
  values unquoted and a `clientSecret` option;
* an `@` in a URL parameter (`?ApplicationName=a@b`) was read as user-info.

### Decision
SCG007 looks for embedded credentials in every property by the shape of
the value (`EmbeddedCredentials`): user-info in any node of a
comma-separated list, a URL parameter ending in `password`, Oracle's
`user/password@`, and JAAS `password`/`clientSecret` options, quoted or
not. URL forms are looked for only in a value starting with `jdbc:` or
containing `://`, JAAS options only in a value naming a `LoginModule`. A
written credential is HIGH; placeholders are substituted first, so a
literal password next to an unresolved host is still found and a
placeholder in the credential slot is not a written credential.

`SCG007.yml`'s `connection-keys` no longer decides what is inspected: it
lists the native connection properties for which a value that can't be
verified statically (an unresolved placeholder, an empty default) is INFO.

The user-info check SCG006 had added for keys ending in
`-uri`/`-url`/`-endpoint` moves to SCG007, so one credential is reported
by one rule; SCG006 keeps its INFO for a query string, unless SCG007
already reports a credential in that URL.

A refreshed key list was rejected: it fixes today's names and drifts again
at the next rename, and it can't cover keys outside Spring Boot.

### Consequences

**Positive**
* All 15 verified forms are reported; the `@`-in-a-parameter false
  positive is gone.
* No list to keep in step with Spring Boot's renames for detection.
* Every reference project in `VALIDATION.md` reports the same findings,
  byte for byte: none of their values has one of these shapes without
  already being reported.

**Negative / Trade-offs**
* A value with one of these shapes in any property is reported, e.g. an
  example connection string kept in a property for documentation. That is
  a credential written in the file all the same.
* A credential only in a path segment or in a parameter not ending in
  `password` (`?token=`) is not SCG007's; SCG006 covers the parameter as
  INFO when the key names a secret.

### Revisit if
A client is found that reads a credential from a form `EmbeddedCredentials`
doesn't know, or a value shape turns out to match non-credentials in real
configurations.

---

## ADR-012: `on-profile` Evaluated as Spring Boot Does: One Ordered Fold per Set of Active Profiles

### Status
Accepted. Supersedes ADR-003, and ADR-002's four-layer cascade. Since
ADR-013, a profile's configuration also has its profile group active, and
profile-specific files apply in activation order.

### Context
`ConfigLoader` took the value of `spring.config.activate.on-profile` as a
literal profile name, and each profile's configuration was the base plus
the documents carrying that exact label (ADR-003). Spring Boot reads the
value as a list of profile expressions and applies every document whose
expression matches the active profiles, in source order. Measured against
Spring Boot 4.1.1 through `/actuator/env` (`VALIDATION.md`, "Profile
expressions in `on-profile`", P1–P15, E1–E10), that left five divergences:

* **Expressions** (`'!api-docs'`, `'a,b'`, `'a | b'`) became a profile
  named after the string, which applied the document to no real profile.
  jhipster's `'!api-docs'` block, which turns SpringDoc off, reached none
  of its real profiles.
* **A YAML list** (`on-profile: [a, b]`) wasn't recognized, so its
  document was folded into the base: a false negative.
* **`default`** (`on-profile: default`, `application-default.yml`) became
  a profile of its own, while Spring applies it when no profile is active.
* **Document order** was ignored: a base document after a profile document
  wins in Spring, while in SCG the profile always won.
* **File precedence** was ignored for `on-profile` blocks: an
  `on-profile: a` block in `application.yml` loses to
  `application.properties` in Spring.

Config Server Mode had its own variant of the problem: every
`application*` file was "the" Global file, so with `application.yml` and
`application-dev.yml` side by side, whichever the file system listed last
was used for every service, and the other was lost.

### Decision
One rule replaces the per-label folds, in both modes:

* `ConfigLoader` keeps every document in file order, with its
  `on-profile` parsed into a `ProfileExpression` (a YAML list is the
  comma-separated list it binds to). A null, empty or empty-list value is
  no condition; a blank value, an empty list item or a malformed
  expression is an input error (exit code 2), since Spring refuses to
  start.
* `ConfigFileGrouper` puts a directory's documents in Spring Boot's source
  order: files without a profile in their name, then
  `application-{profile}` files; `.yaml` < `.yml` < `.properties` within
  each; a file's documents as written. A document of
  `application-{profile}` applies only when that profile is active, and
  its own `on-profile`, if any, must match too. `ConfigServerAssembler`
  builds the same list per service: Global files without a profile, the
  service's files, then Global `application-{profile}` files, the order
  Spring Boot gives `spring.config.name=application,svc` (P15).
* `ProfileMerger` evaluates the base, with `{default}` active, and one
  configuration per known profile P, with `{P}` active. The known profiles
  are every name the conditions refer to, file names and expressions,
  names only negated included (`api-docs` in `!api-docs`), except
  `default`. Each configuration is the fold, in source order, of every
  document that applies, with the same pairwise merge as before
  (`mergeWithoutStrippingSentinels`, sentinels stripped at the end).
* A document only a combination of profiles activates (`a & b`, or an
  `on-profile` inside `application-x.yml` naming another profile) applies
  to no evaluated configuration; `Main` counts such documents in a stderr
  warning, as it does for `spring.config.import`.
* A configuration's source file is where it is most likely fixed: for a
  profile, the file of the last applied document whose condition names
  it; otherwise, and for the base, the file of the last applied document.
  In Config Server Mode it stays the service's file.

SCG parses expressions itself, following Spring Framework's
`ProfilesParser` step by step, instead of depending on `spring-core`; the
benchmark is the oracle.

### Consequences

**Positive**
* For every set of active profiles SCG evaluates, the console value in all
  fourteen fixtures matches Spring Boot's (`ProfileExpressionScenariosTest`
  pins each row).
* One merge path: there is no per-label fold left to get out of step with
  the final merge, and documents of one file now merge with it too: a list
  a later document redefines replaces the earlier one, where `ConfigLoader`
  used to combine same-label documents key by key (`putAll`), leaving
  indices of the earlier list behind.
* Config Server Mode reads `application-{profile}` Global files, and a
  service written in two formats keeps both files.

**Negative / Trade-offs**
* Profile labels change for projects that use expressions, lists or
  `default`: a policy entry naming `default` or an expression string stops
  matching. A profile named only in an expression is a configuration of
  its own and repeats the base's findings, as every profile does.
* Several profiles active together are still not evaluated; their
  documents are only counted in the warning, so a risk only such a
  combination sets is not reported.
* A name Spring Boot refuses to activate (`a b`, E2) still becomes a
  configuration, which can't run in Spring.

### Revisit if
A benchmark run on a newer Spring Boot version disagrees with a row of
`VALIDATION.md`, "Profile expressions in `on-profile`", or profile groups
(`spring.profiles.group`), which activate several profiles from one, are
taken up (`BACKLOG.md`).

---

## ADR-013: Profile Groups Evaluated with the Profile That Activates Them

### Status
Accepted. Since 2026-10-06, a YAML null no longer removes the sub-keys of
earlier documents (`VALIDATION.md`, "ProfileMerger correctness benchmark",
cases 36–38), so the trade-off below about a null in a group member's file
no longer holds.

### Context
ADR-012 evaluates one configuration per single active profile.
`spring.profiles.group` makes one profile activate others: jhipster
declares `group.dev: [secret-samples, api-docs]`, so with `dev` active
Spring also activates `api-docs`, its `'!api-docs'` block doesn't apply
and SpringDoc is on. SCG evaluated `dev` alone, with the block applied, and
stopped reporting SCG008 there. Measured against Spring Boot 4.1.1
(`VALIDATION.md`, "Profile groups", G1–G7):

* a group's profiles become active after the profile, depth first, nested
  groups included; profile-specific files apply in that activation order,
  while `on-profile` documents keep their place in the file (G1, G2, G6);
* a group declared in `application-x.yml` is ignored, one in an
  `on-profile` document applies (G3, G4);
* a group of `default` applies when no profile is active (G7);
* `spring.profiles.include` adds its profiles always, and then `default`
  is no longer active (G5).

### Decision
`ProfileMerger` evaluates the configuration of a profile P, and the base's
from `default`, with P and the profiles its group activates, expanded as
Spring Boot's `Profiles` does (depth first, each profile once). A group is
read from the documents of the files without a profile in their name that
apply when P alone is active; a later declaration of the same group
replaces an earlier one. Documents without a file profile apply first, in
the group's order, then each active profile's `application-{profile}`
documents in activation order. A declared group is a known profile, so a
group with no file of its own is evaluated too. The configuration keeps
P's label; its source file is P's own `application-P` file when it has
one.

`spring.profiles.include` is not evaluated: no reference project uses it,
and it changes the base's active profiles, not only a profile's.

### Consequences

**Positive**
* jhipster's `dev` reports what Spring runs with `dev` active:
  SpringDoc on, and the `on-profile: dev` documents of
  `application-secret-samples.yml`, which the combinations warning no
  longer counts.
* No new concept: a configuration was already a set of active profiles
  matched by `SourceDocument.appliesTo`.

**Negative / Trade-offs**
* A group read from a document conditioned on the profile it expands
  covers G4, but a declaration whose condition depends on a group member
  is not followed.
* With groups, documents of more files reach one configuration, which
  exposes merge behavior the single-profile model rarely hit: a YAML
  null (`spring:`) in a group member's file removes sub-keys the profile's
  own file set, which Spring keeps (`BACKLOG.md`).
* `spring.profiles.include` stays out (G5 pins the divergence).

### Revisit if
A real project uses `spring.profiles.include`, or a group declared under a
condition SCG doesn't follow.
