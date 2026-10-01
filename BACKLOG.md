# Backlog

The planned state of the project: work that is pending, deferred on purpose,
or discarded. It is not a contract — items are expected to be added,
dropped, split or reprioritized as the project evolves.

What this file does **not** hold:

* Completed work. Once something is done, its record lives in
  `ARCHITECTURE.md` (ADRs), `VALIDATION.md` and the git history, and it is
  removed from here instead of being kept as a narrative.
* The list of implemented rules. That is
  `src/main/resources/META-INF/services/dev.scg.core.Rule`, enforced by
  `RuleRegistryTest`.

Source code and Javadoc must not reference items in this file: the backlog
changes constantly, so the reason behind a decision belongs next to the code
or in an ADR.

## Pending

### Rule-by-rule review of the 17 rules

Apply `.claude/skills/review-security-rule/SKILL.md` to each rule, in order
of how likely a wrong finding is times how many projects it reaches, not by
rule number: 12 of the 17 rules can report HIGH, so severity alone doesn't
order them. Planned order: SCG006 (heuristics on key names and values, the
rule that fires most on the reference corpus), SCG014 (recalibrated by
ADR-010), SCG007 and SCG012 (heuristics on URI and JAAS text), the rules
that combine keys (SCG003, SCG008, SCG011), then the rest, single-key rules
such as SCG002, SCG009 and SCG013 last. For SCG008 and SCG011, check a
combination split across config locations: ADR-005 confirmed it produces
no finding for SCG003, but the effect on these two was not verified.

Reviewed so far:

* SCG001, against a running Spring Boot app (`VALIDATION.md`, "SCG001
  exposure scenarios"); split across locations, its `show-values` finding is
  missed, a limitation the ADR-005 coverage warning already surfaces.
* SCG006, against Spring Boot 4.1.1's configuration metadata (`VALIDATION.md`,
  "SCG006 key matching").

The severity of a finding based on an absent key is decided for every rule
in ADR-010 (MEDIUM where a written value would be HIGH); apply it to each
rule reviewed.

How the review proceeds: stop after each rule for the maintainer's go-ahead
before starting the next one. Next: SCG014. Where a rule relies on Spring
Boot behavior, check it against a running app, as for SCG001.

### GitHub Action for the Marketplace

Publish SCG as a GitHub Action (`uses: rgiovann/spring-config-guard-action@v1`)
so a CI gate no longer needs the README's `curl` + `java -jar` step.

* **In a separate repository** (`spring-config-guard-action`), as most
  established CLI and security tools do: the action's own `action.yml` at
  the root and its own `v1`-style tags, independent of this repository's CI
  and release workflows. Confirm the Marketplace's current publishing
  requirements (public repository, one action per repository, whether
  workflow files are allowed, the developer agreement, 2FA) before creating
  it.
* **A composite action**: `actions/setup-java` (Java 21), download of a
  pinned release jar with its sha256 checked, then SCG with the flags as
  inputs (path, `fail-on`, `policy`, `config-server`, `json`). Each SCG
  release means a matching action release.
* **A CI gate first** (exit code and report). PR annotations and a SARIF
  upload for code scanning come later: they place each finding on a file,
  so they depend on "Per-property origin in findings" below.
* **Order**: review SCG014, release the SCG006 and SCG014 changes, then
  create and publish the action. False positives in a CI gate are what
  drive new users away first.

### Per-property origin in findings (waiting for a real consumer)

`sourceFile` identifies the evaluated configuration, not where the offending
property is written: every `EffectiveConfig` carries one path, and rules
copy it into each `Finding`. It points elsewhere whenever a configuration is
assembled from several files — a property inherited from the base (since
v1.0), `.yml` + `.properties` in one directory, a named profile file plus an
on-profile block (both since v1.2.0), and the Global file in Config Server
Mode (documented as intended in ADR-002). Detection is unaffected. The
semantics are documented in README, "Output Format".

Reporting the real origin would take: tracking a source file per property
through `ConfigLoader` → `ConfigFileGrouper` → `ProfileMerger`, with the
same list-replacement, explicit-null and relaxed-binding semantics as the
values; rules reporting which keys triggered a finding (all 17 rules);
a list of origins for rules that combine keys possibly written in different
files (e.g. SCG003); and a new optional JSON field, which would be a
MINOR change (CONTRIBUTING.md, "Releases").

Worth it only once something consumes the location — e.g. PR annotations
or code-scanning upload, where a wrong file would mark the wrong place. The
planned GitHub Action (above) is that consumer once it adds annotations or
SARIF.
Until then, the documented semantics are enough.

### `--config-name=<prefix>`: custom `spring.config.name`

A project started with `-Dspring.config.name=myapp` uses `myapp.yml` /
`myapp-{profile}.yml`. `ConfigLoader` only recognizes the `application`
prefix, so such a project scans clean — a silent false negative, not an
error. Intended design: a `--config-name` flag (default `application`)
parameterizing the prefix `ConfigLoader` already checks. Out of scope:
`spring.config.location` and arbitrary paths. No confirmed need yet.

### Version in the JSON report (waiting for a concrete need)

`--version` tells which jar is installed, but a saved report still doesn't
say which version produced it. A new optional field in each finding would
be a MINOR change; moving to a top-level object with the version and the
findings would change the report's shape, a MAJOR one. Worth it only once
reports are stored or compared across versions, e.g. by an external tool.

## Deferred (post-1.0)

Technically viable, deliberately postponed. **Triage criterion:** does the
property carry a credential or real data payload (a candidate rule), or only
a discovery/observability address (deferred)? The second group is usually
deployed intra-cluster or intra-mesh (Docker network, Kubernetes namespace,
a service-mesh sidecar handling TLS), where `http://` is often legitimate —
exactly the kind of false positive that erodes trust in early runs.

* **Insecure service discovery** (Eureka `eureka.client.service-url.defaultZone`,
  Consul `spring.cloud.consul.discovery.scheme`). The address points to the
  registry and doesn't prove inter-service traffic is insecure; Consul's
  scheme even defaults to `http`, so most Consul projects would trigger it
  without being exposed.
* **Insecure telemetry export** (Zipkin `management.zipkin.tracing.endpoint`,
  OTLP `management.otlp.metrics.export.url`). Collectors usually run as a
  sidecar or inside the same private cluster; lower severity (MEDIUM), since
  only request/trace metadata is carried, not application credentials.

## Discarded

Not coming back unless a new, concrete use case appears.

* **Full `spring.config.import` resolution.** Surfaced as a coverage warning
  instead; see ADR-004 for the five reasons.
* **Redis without a password.** Whether Redis requires authentication
  (`requirepass`) is a server-side decision, invisible in the client's
  config. A missing password either breaks the connection in any functional
  test or reflects a server that doesn't require one — the visible config is
  identical for legitimate isolation and accidental exposure.
* **Weak JWT algorithm in the OAuth2 resource server**
  (`spring.security.oauth2.resourceserver.jwt.jws-algorithms`). The premise
  is factually wrong: the value is converted through
  `SignatureAlgorithm.from()`, whose enum has only RS/ES/PS algorithms, and an
  unknown name fails application startup. Symmetric algorithms can't be
  configured through this property, and the `issuer-uri` path doesn't read it.
* **CSRF disabled.** Done in a `SecurityFilterChain` bean in Java, not
  through a property — no config-file signal exists.
* **Springfox** (`springfox.documentation.*`). Legacy and incompatible with
  Spring Boot 3 / Java 21, the project's target.
* **Insecure SMTP transport** (`spring.mail.properties.mail.smtp.*`). Two
  alternative secure setups (STARTTLS on 587 or implicit SSL on 465) under a
  generic nested map make it costlier than the other transport rules, with no
  confirmed need. Open to an external contributor with a concrete use case.
* **Unlimited multipart upload** (`spring.servlet.multipart.max-*`). Spring
  Boot's defaults are already bounded, the limit is usually enforced at the
  edge (gateway, load balancer), and it is closer to DoS than to the
  confidentiality/integrity scope the project prioritizes.
* **Generic `http://` scanner across all properties.** Rejected on design
  grounds: when one property has a severe impact over HTTP (e.g. a JWT
  `issuer-uri`), a dedicated rule can explain why and calibrate severity; a
  generic scanner can't tell a low-risk URL from one that enables forged
  tokens. The same reasoning kept Kafka (SCG014) and Vault (SCG016) as
  dedicated rules.
* **Targeting a real profile named `base` in a Policy file.** Decided not to
  change; see README, "Other known limitations".
