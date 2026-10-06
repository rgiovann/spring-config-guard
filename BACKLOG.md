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

Done in this order: the findings from the candidate reference projects,
then the GitHub Action, then the one item of new coverage with a real case.
Everything else waits in Deferred for a real case or a need.

### Findings from the candidate reference projects

Three projects proposed as new reference projects, run against the v1.16.0
jar on 2026-10-06. Each has a finding to settle before it is added to
`VALIDATION.md`, pinned at the commit below, with its precision check.

* `jhipster/jhipster-sample-app` (`6b000b5`, Spring Boot 4.1.1)
* `spring-projects/spring-authorization-server` (`4283973`, its samples)
* `spring-projects/spring-ai-examples` (`7416412`)

#### `on-profile` evaluated as Spring does (core, planned)

`ConfigLoader` takes the value of `spring.config.activate.on-profile` as a
literal profile name, and each profile's configuration is the base plus the
documents carrying that exact label. Spring reads the value as a list of
profile expressions (`!`, `&`, `|`, parentheses; a comma or a YAML list
means "any of") and applies every document whose expression matches the
active profiles, in source order: files by precedence (non-profile files,
`.properties` over YAML, then profile-specific files), documents in file
order. With no profile active, the `default` profile is active.

Measured on 2026-10-06 against Spring Boot 4.1.1 (`/actuator/env`) and the
v1.16.0 jar, five divergences, all reproduced:

* **D1, expressions**: `'!api-docs'`, `'a,b'`, `'a | b'`,
  `'(a & !b) | c'` each become a profile named after the string, and the
  document applies to no real profile. jhipster's `application.yml` turns
  SpringDoc off under `'!api-docs'`; SCG reports SpringDoc enabled
  (SCG008 MEDIUM) in the base and in `dev`, `prod`, `secret-samples` and
  `tls`, and repeats the base's SCG001 HIGH and SCG013 INFO under a
  `!api-docs` profile that doesn't exist.
* **D2, YAML list** (`on-profile: [a, b]`): the keys become
  `on-profile[0]`/`[1]`, which SCG doesn't recognize, so the document is
  folded into the base. A false negative: a base with
  `spring.h2.console.enabled: true` and an `[a, b]` block setting `false`
  reports nothing.
* **D3, `default`**: `on-profile: default` and `application-default.yml`
  apply when no profile is active, i.e. to SCG's base; SCG makes them a
  profile named `default`.
* **D4, document order**: a base document after a profile document in the
  same file wins over it in Spring; in SCG the profile always wins.
* **D5, file precedence**: an `on-profile: a` block in `application.yml`
  loses to the base of `application.properties` in Spring; in SCG the
  block wins.

Also measured: spaces around list items are ignored; `'a & b | c'` makes
the application fail to start (`Malformed profile expression`); and
`on-profile` inside `application-x.yml` is accepted as an extra condition.
Spring Boot 4.1.1 rejects only `spring.profiles.active` and
`spring.profiles.default` in a profile-specific file, so the
`ConfigFileGrouper` Javadoc, which says `on-profile` is rejected there, is
wrong.

**Decided** (the maintainer, 2026-10-06): one rule fixes D1 to D5. For
each directory SCG evaluates the base, with active profiles `{default}`,
and one configuration per known profile P, with active profiles `{P}`. The
known profiles are the names of `application-{P}.*` files and every name an
expression references, except `default`. A configuration is the ordered
fold, with `ProfileMerger`'s existing merge, of every document with no
`on-profile` or whose expression matches, in Spring's source order. This
supersedes ADR-003's separate base and per-label folds. Choices taken:

* SCG parses expressions itself (a small `ProfileExpression`), without
  depending on `spring-core`; the benchmark is the oracle.
* A document only a combination of profiles activates (`a & b`) isn't
  evaluated, and a coverage warning on stderr says so, as for
  `spring.config.import`.
* A malformed expression is an input error (exit code 2), as invalid YAML
  is, since Spring refuses to start.
* A profile named only in a negation (`api-docs` from `!api-docs`) is a
  configuration of its own.
* `default` belongs to the base; a policy entry naming `default` stops
  matching (release note).
* D4 and D5 are fixed in the same change.
* Config Server Mode applies the same selection: the Global file, then the
  service's file.

Effects to expect: profile labels change for projects using expressions,
lists or `default` (a **Detection changes** entry); profiles named only in
expressions add configurations, and so repeated findings. Predicted on
jhipster, not measured: the `!api-docs` label goes, SCG008 leaves the base
and the four real profiles, and a new `api-docs` configuration reports it.

Phases, one commit each:

1. Evidence only: count the uses in the pinned reference repositories; a
   scenario script in `spring-env-benchmark/` that runs each case against
   the app and against SCG, compared key by key; a `VALIDATION.md` section
   with the results.
2. `ProfileExpression` and its tests, not yet wired in.
3. The change: `ConfigLoader` keeps every document in file order with its
   parsed expression (and the YAML-list form); `ConfigFileGrouper` orders
   sources instead of folding by label; `ProfileMerger` computes the
   targets and folds; `ConfigServerAssembler`; the warning in `Main`. With
   ADR-012, README, `CLAUDE.md` ("Architecture"), the `ConfigFileGrouper`
   Javadoc, and the before/after on the reference corpus, the demo
   fixtures and the three candidates in `VALIDATION.md`.

Left out, each waiting for a real case: `spring.profiles.default` written
in configuration (it renames the default profile);
`spring.config.activate.on-cloud-platform`, another activation condition,
ignored today, so its documents are folded into the base; several profiles
active together.

#### SCG006: a secret pattern in a map key

`spring-authorization-server`'s samples name OAuth2 client registrations
after their grant (`messaging-client-client-credentials`,
`messaging-client-token-exchange-with-delegation`). The registration id is
a map key, so every property under it (`client-id`, `scope`, `provider`,
`authorization-grant-type`, ...) "contains a secret pattern" and is
reported as INFO: 32 INFO findings, all under
`spring.security.oauth2.client.registration.<id>.*`. Its 25 HIGH findings
look correct. Decide whether a pattern that matches only inside a map key
the user named should stay silent.

#### SCG006: a placeholder written as sample text

`spring-ai-examples` writes `spring.ai.openai.api-key=<YOUR-OPENAI-API-KEY>`
(`kotlin/rag-with-kotlin`), reported as HIGH. The value is an instruction
to the reader, not a secret, but a false positive here is arguable: the
file invites the user to paste a real key in its place. Decide whether a
value shaped like `<...>` is a hardcoded secret.

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
  so they depend on "Per-property origin in findings" (Deferred).
* **Order**: only after every rule is reviewed and released (the
  maintainer's decision), since false positives in a CI gate are what drive
  new users away first. Met with v1.15.0: every rule's review has shipped.

### TLS without verifying the server (candidate rule)

The transport rules report an unencrypted connection, not an encrypted one
that accepts any server. Found in two clients so far; decide severity and
whether it is one rule or an extension of each transport rule once, for
all of them.

RabbitMQ, found while reviewing SCG015: `spring.rabbitmq.ssl.validate-server-certificate=false`
(or `ssl.verify-hostname=false`) with `ssl.enabled=true` still started a
TLS handshake on the wire (`VALIDATION.md`, "SCG015 RabbitMQ transport
scenarios", V1), with SCG015 silent. Still to measure: that the client then
accepts a certificate that doesn't match or isn't trusted.

Kafka, found while reviewing SCG014, which covers only an unencrypted protocol: a
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
Decide then whether it extends SCG014 or is a rule of its own. A real case:
`spring-cloud-stream-samples` writes
`spring.cloud.stream.kafka.binder.configuration.ssl.endpoint.identification.algorithm:`
empty in a base file (found while fixing the YAML null in a base file).

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

### Coverage found during the rule reviews, waiting for a real case

Settings or cases that the reviews, and the fixes that followed them,
turned up, but that no reference project or demo writes with the risky
value, and no user has reported (as of 2026-10-05). Each is noted with
what it would take; it moves back to Pending when a real case appears, so
the reviews' leftovers don't grow into a queue that never empties.

#### A null in a profile purges the base's sub-keys (measure first)

Found while fixing the YAML null in a base file: `app.x: ~` in a profile
makes `ProfileMerger` remove the base's `app.x.*` keys, while Spring keeps
both sources, and each one's binding picks a shape by type (CLAUDE.md,
"Architecture"). The `/actuator/env` benchmark checks a null override of a
scalar only. Add a null over a map to it before deciding whether the purge
goes.

No profile in the reference projects or demo fixtures writes a null
(checked with SCG's loader on 2026-10-05), so the divergence has no case
yet.

#### SCG012 cases left open (decide with measurements)

Found in the SCG012 review (`VALIDATION.md`, "SCG012 driver modes"):

* **Default modes that allow plaintext.** PostgreSQL's default
  `sslmode=prefer` and MySQL's default `sslMode=PREFERRED` fall back to an
  unencrypted connection when the server doesn't offer TLS. Reporting a
  JDBC URL without an explicit mode would reach almost every PostgreSQL and
  MySQL URL; measure on the corpus first, and decide between INFO
  (CLAUDE.md, "Findings") and leaving it to the server's configuration.
  The same decision covers these modes written explicitly: `sslmode=prefer`
  (silent today) and MySQL's legacy `requireSSL=false`, which Connector/J
  translates to `sslMode=PREFERRED` but SCG012 reports as HIGH.
* **Redis `redis://` without `spring.data.redis.ssl.enabled`.** Plaintext
  only when both hold, so it needs the two keys together (like SCG015 for
  RabbitMQ), not a scheme alone.
* **Artemis `tcp://`.** Artemis enables TLS with an `sslEnabled=true`
  parameter on a `tcp://` URL, unlike ActiveMQ Classic's `ssl://` scheme;
  confirm in Artemis' client before treating `tcp://` without it as
  plaintext for `spring.artemis.broker-url`.

On 2026-10-05 the reference projects held seven PostgreSQL, MySQL or
MariaDB URLs, none with an explicit mode and all on `localhost`, now INFO
as loopback; no Redis configuration; and one Artemis project without
`broker-url`.

#### SCG003: Spring Cloud Gateway's CORS (decide with measurements)

Found in the second review of SCG003 (`VALIDATION.md`, "SCG003 CORS
scenarios"): a gateway's global CORS, set in properties
(`spring.cloud.gateway.globalcors.cors-configurations.[/**].*`, and a
`spring.cloud.gateway.server.webflux.` prefix in later releases, to
confirm), is silent, also with `allowed-origin-patterns: "*"` and
credentials. It is the other CORS commonly configured in properties, and a
gateway usually sits in front of the services. Confirm the property names per
Gateway release and the behavior in a running gateway, then decide whether
SCG003 reads them like Actuator's and GraphQL's.

No reference project sets `globalcors` (2026-10-05), not even `spring-
petclinic-microservices`, which has a gateway.

#### Transports SCG012 doesn't look at (decide scope with measurements)

Found in the second review of SCG012 (`VALIDATION.md`, "SCG012 driver
modes"): these settings, written explicitly, are silent today. What each is
noted to mean comes from its name and Spring Boot 4.1.1's metadata, not yet
from its client.

* Neo4j: `spring.neo4j.uri=neo4j+ssc://...` or `bolt+ssc://...` (TLS that
  accepts self-signed certificates),
  `spring.neo4j.security.trust-strategy=trust-all-certificates` (the
  default is `trust-system-ca-signed-certificates`) and
  `spring.neo4j.security.hostname-verification-enabled=false`.
* Cassandra: `spring.cassandra.ssl.verify-hostname=false`.
* Pulsar: `pulsar://` in `spring.pulsar.client.service-url` and `http://`
  in `spring.pulsar.admin.service-url` (plaintext; TLS is `pulsar+ssl://`,
  `https://`).
* Couchbase: `couchbase://` in `spring.couchbase.connection-string`,
  plaintext unless SSL is enabled (`spring.couchbase.env.ssl.enabled`, or
  an SSL bundle, which enables it): several keys together, like Redis in
  "SCG012 cases left open".

Confirm each behavior in its client (and how Spring Boot 4.1.1 maps the
properties) before reporting, then decide whether they extend SCG012 or
form a rule of their own.

#### SCG011: weak TLS protocols and session IDs in URLs (decide with measurements)

Found in the second review of SCG011 (`VALIDATION.md`, "SCG011 transport
scenarios"): these are silent today, and each needs a running app before
it is reported.

* `server.ssl.enabled-protocols=TLSv1,TLSv1.1` or `server.ssl.protocol=TLSv1`.
  The JDK disables TLS 1.0/1.1 by default (`jdk.tls.disabledAlgorithms`),
  so check whether these take effect, fail the handshake or fail the
  startup on Java 21 before deciding a severity.
* `server.servlet.session.tracking-modes=url`: the session ID travels in the
  URL, where logs and the `Referer` header can leak it, and a link carrying
  one can fix a victim's session. Confirm on Tomcat and Jetty that it is
  written into URLs and accepted from them.

#### RabbitMQ Streams transport (measure first)

Found while reviewing SCG015: `spring.rabbitmq.stream.host`, `stream.port`
and `stream.ssl.enabled`/`stream.ssl.bundle` configure a separate RabbitMQ
Streams connection, with its own TLS settings, that SCG015 doesn't read.
Measure on the wire, as for SCG015, what it sends without
`stream.ssl.*` before deciding whether SCG015 covers it.

#### Spring Cloud Stream Rabbit binder environment (measure first)

Found while reviewing SCG015: a Rabbit binder can carry its own connection
in `spring.cloud.stream.binders.<name>.environment.spring.rabbitmq.*`, which
SCG015 doesn't read. ADR-009 evaluates binder environments as their own
contexts for Kafka only. Measure whether the Rabbit binder applies them the
same way before extending the rule or the ADR.

#### Vault located through service discovery (measure first)

Found while reviewing SCG016: with `spring.cloud.vault.discovery.enabled=true`,
Spring Cloud Vault finds the Vault server through a discovery client instead
of `uri`/`host`, and the scheme may come from the discovered instance rather
than `spring.cloud.vault.scheme`, which is all SCG016 reads. Measure, with a
registry in the benchmark, which scheme the client uses before deciding
whether SCG016 should say anything when discovery is on.

#### OAuth2 Client provider URIs over HTTP (measure first)

Found while reviewing SCG017: an OAuth2 Client (login) reads
`spring.security.oauth2.client.provider.<name>.token-uri`, `jwk-set-uri`,
`issuer-uri` and `user-info-uri`, where `http://` would expose the client
secret, the authorization code exchange and the ID token keys. SCG017 reads
only the resource server keys. Measure on the wire, with a login flow in the
benchmark, which of these the client fetches and when, before deciding
whether SCG017 or a rule of its own covers them.

#### SCG006: credentials in the OTLP headers maps

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

#### Findings name the key as the rule spells it, not as it is written

A message quotes the key from the rule's own list, so
`spring.web.error.includeStacktrace=always` is reported as
`spring.web.error.include-stacktrace=always` (found while reviewing
SCG010). Relaxed binding makes both the same property, so detection is
unaffected, but a user searching the file for the quoted key won't find
it. `RelaxedProperties.findActualKey()` returns the spelling written; only
SCG011 uses it today. Applying it would touch every rule that quotes a key,
so it is one change across the rules, not part of any single review.

Measured on 2026-10-05: of the 245 findings on the reference projects and
demo fixtures, none quotes a key spelled differently from the file, since
they write keys in kebab-case, as the rules do. Waiting for a real case,
like the items above. If it comes, one step after `RuleEngine` that
replaces each quoted key with the spelling written in the configuration
would cover every rule at once.

### Follow-ups from the README review

Found while auditing the README against the code and the v1.16.0 jar
(2026-10-06). The README was corrected where it was wrong; these are what
the review left open.

Not confirmed:

* The rule table's descriptions were checked only for each rule's set of
  severities, not re-audited rule by rule against the code.
* Troubleshooting's `UnsupportedClassVersionError` on a JVM older than 21
  follows from the jar's class version (65) and was not reproduced.
* The CI example installs Java 21 with `actions/setup-java`, so it doesn't
  depend on the runner's default JDK, which wasn't checked.
* Checkov 3.3.24 lists `yaml` and `json` frameworks, which the old README
  said it lacked. Whether they can express a check across files wasn't
  tested; the README no longer compares SCG with Checkov. Check it before
  any such comparison comes back.

Suggested improvements, each outside a README change:

* **SCG003's message overstates the impact**: "exposes the application to
  severe Cross-Site Request Forgery (CSRF) and session data leakage" claims
  an outcome static analysis can't confirm. Audit every rule's message for
  the same kind of wording.
* **`--fail-on=INFO` is accepted** and behaves as `LOW`, since INFO never
  counts toward the exit code; `--help` lists only `HIGH`, `MEDIUM`, `LOW`
  and `NONE`. Reject it as a usage error (a CLI contract change) or
  document it.
* **The console summary calls INFO findings violations**
  (`Summary: 2 violation(s) - ... INFO: 2` on a clean fixture). The console
  format is a public contract.
* **Pin the README's "See it in action" example** as a fixture with a test,
  like `DemoProjectShowcaseTest`, so its literal output can't drift from the
  rules' messages.
* **Check the jar's sha256 in the CI example.** GitHub publishes each
  release asset's digest; the example would need it updated with the
  version pin, as a step of the release checklist.

### Waiting for a need

Features nothing asks for yet; each names the need that would bring it
back.

#### Per-property origin in findings (waiting for a real consumer)

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
planned GitHub Action (Pending) is that consumer once it adds annotations or
SARIF.
Until then, the documented semantics are enough.

#### `--config-name=<prefix>`: custom `spring.config.name`

A project started with `-Dspring.config.name=myapp` uses `myapp.yml` /
`myapp-{profile}.yml`. `ConfigLoader` only recognizes the `application`
prefix, so such a project scans clean — a silent false negative, not an
error. Intended design: a `--config-name` flag (default `application`)
parameterizing the prefix `ConfigLoader` already checks. Out of scope:
`spring.config.location` and arbitrary paths. No confirmed need yet.

#### Version in the JSON report (waiting for a concrete need)

`--version` tells which jar is installed, but a saved report still doesn't
say which version produced it. A new optional field in each finding would
be a MINOR change; moving to a top-level object with the version and the
findings would change the report's shape, a MAJOR one. Worth it only once
reports are stored or compared across versions, e.g. by an external tool.

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
