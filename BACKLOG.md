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
such as SCG002, SCG009 and SCG013 last.

Reviewed so far:

* SCG001, against a running Spring Boot app (`VALIDATION.md`, "SCG001
  exposure scenarios"); split across locations it errs both ways: its
  `show-values` finding is missed when `show-values` is in another location
  (a false negative), and `exposure.include=*` is still reported when
  `access.default=none` in another location turns every endpoint off (a
  false positive), both surfaced by the ADR-005 coverage warning.
* SCG006, against Spring Boot 4.1.1's configuration metadata (`VALIDATION.md`,
  "SCG006 key matching").
* SCG014, against Spring Boot 4.1.1's `KafkaProperties` (`VALIDATION.md`,
  "SCG014 protocol precedence").
* SCG007, against the JDBC drivers and kafka-clients (`VALIDATION.md`,
  "SCG007 credential forms"; ADR-011).
* SCG012, against the JDBC drivers and Spring Boot's Redis configuration
  (`VALIDATION.md`, "SCG012 driver modes").
* SCG003, against running Spring Boot 4.1.1 apps, Actuator and Spring for
  GraphQL (`VALIDATION.md`, "SCG003 CORS scenarios").
* SCG008, against a running Spring Boot 4.1.1 app with SpringDoc 3.1.1
  (`VALIDATION.md`, "SCG008 SpringDoc scenarios"); split across locations
  it can only err towards a false positive.
* SCG011, against running Spring Boot 4.1.1 apps, Tomcat, Jetty, Spring
  Session and WebFlux (`VALIDATION.md`, "SCG011 transport scenarios"); split
  across locations it errs both ways (false negatives when the TLS material
  and `enabled=false`, or the management port and management SSL, are in
  different locations; a false positive when `config/` re-enables SSL), all
  surfaced by the ADR-005 coverage warning.

Found while reviewing SCG003, to check in the rules concerned:
`spring.graphql.cors.*` is a second CORS binding next to Actuator's, which
SCG004 and SCG005 don't read either; and `RelaxedBoolean.isTruthy` treats an
unresolved placeholder as `true`, so a rule using it reports doubt at its
certain severity (SCG003 now resolves `allow-credentials` itself).

The severity of a finding based on an absent key is decided for every rule
in ADR-010 (MEDIUM where a written value would be HIGH); apply it to each
rule reviewed.

How the review proceeds: stop after each rule for the maintainer's go-ahead
before starting the next one, and release every 2 or 3 reviewed rules, so
each release's detection changes stay few enough to read. Next: the single-key
rules (SCG002, SCG004, SCG005, SCG009, SCG010, SCG013, SCG015, SCG016,
SCG017). Where a rule relies on Spring Boot behavior, check it
against a running app, as for SCG001.

### SCG012 cases left open (decide with measurements)

Found in the SCG012 review (`VALIDATION.md`, "SCG012 driver modes"):

* **Default modes that allow plaintext.** PostgreSQL's default
  `sslmode=prefer` and MySQL's default `sslMode=PREFERRED` fall back to an
  unencrypted connection when the server doesn't offer TLS. Reporting a
  JDBC URL without an explicit mode would reach almost every PostgreSQL and
  MySQL URL; measure on the corpus first, and decide between INFO
  (CLAUDE.md, "Findings") and leaving it to the server's configuration.
* **Redis `redis://` without `spring.data.redis.ssl.enabled`.** Plaintext
  only when both hold, so it needs the two keys together (like SCG015 for
  RabbitMQ), not a scheme alone.
* **Artemis `tcp://`.** Artemis enables TLS with an `sslEnabled=true`
  parameter on a `tcp://` URL, unlike ActiveMQ Classic's `ssl://` scheme;
  confirm in Artemis' client before treating `tcp://` without it as
  plaintext for `spring.artemis.broker-url`.

### Kafka TLS without hostname verification (candidate rule)

Found while reviewing SCG014, which covers only an unencrypted protocol: a
Kafka client on `SSL`/`SASL_SSL` with `ssl.endpoint.identification.algorithm`
set to an empty value encrypts but doesn't check that the broker's
certificate matches its host name, so a man in the middle with any trusted
certificate can intercept the traffic. A common workaround for certificate
errors. Checked so far in kafka-clients 4.2.1: the default is `https`, and
the client passes the configured value straight to
`SSLParameters.setEndpointIdentificationAlgorithm`. Still to confirm before
building it: that the JDK skips the check for an empty value (a test
against a TLS listener whose certificate doesn't match the host), and the
keys that set it (`spring.kafka.properties.ssl.endpoint.identification.algorithm`,
the per-client maps, the binder maps), with the same precedence as SCG014.
Decide then whether it extends SCG014 or is a rule of its own.

### SCG006: credentials in the OTLP headers maps

Found while re-checking SCG006 (`VALIDATION.md`, "SCG006 key matching"):
`management.otlp.metrics.export.headers`,
`management.opentelemetry.tracing.export.otlp.headers` and
`management.opentelemetry.logging.export.otlp.headers` are maps of HTTP
headers sent to the telemetry backend, which often carry its credential
(the metadata describes the two `opentelemetry` ones as "for example auth
headers"). An entry named after a secret pattern (`headers.api-key`) is
HIGH, but `headers.Authorization` (`Bearer ...`, `Basic ...`) and vendor
headers such as `X-Honeycomb-Team` are silent. To decide with measurements:
recognize the value (`Bearer `/`Basic ` prefixes) or the header names in
these maps, and at which severity.

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
* **Order**: only after every rule is reviewed and released (the
  maintainer's decision). So far SCG006 and SCG014 shipped in v1.7.0,
  SCG007 and SCG012 in v1.8.0. False positives in a CI gate are what drive
  new users away first.

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
