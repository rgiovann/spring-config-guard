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

---

## ADR-003: Folding Multiple Physical Sources of the Same Profile Label Before Merging

### Status
Accepted

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

### Decision
Keep evaluating directories independently, and make the gap visible.
`ConfigLocationCoverage.modulesWithMultipleLocations()` reports module
roots `R` with config files in two or more of:

* `R/src/main/resources` (`classpath:/`)
* `R/src/main/resources/config` (`classpath:/config/`)
* `R/config` (`file:./config/`, assuming the app starts from `R`)

`Main` prints unconditionally to stderr when the count is above zero:

```
spring-config-guard: N application(s) have config files in more than one Spring config location, evaluated independently -- risks split across locations are not detected.
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
Accepted

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

**Negative / Trade-offs**
* Finding messages name the dotted key, not the bracketed spelling the
  user wrote.
* Accepted collision: brackets preserve characters that relaxed binding
  ignores, so `[com.foo-bar]` and `[com.foobar]` are two entries in Spring
  but canonicalize to one key here, the later overriding the earlier. Rare,
  and pinned by a test so the limitation stays visible.
* None of the reference projects in `VALIDATION.md` uses bracketed keys:
  the fix is proven by fixtures and by Spring's own binder, not yet by a
  real-world project.

### Revisit if
A rule needs the original bracketed spelling (e.g. to quote it back), or
the dash/underscore collision shows up in a real project.
