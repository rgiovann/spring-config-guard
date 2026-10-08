# Changelog

Release notes for every version, newest first. Versioning rules, the release
checklist and the notes template are in
[CONTRIBUTING.md](CONTRIBUTING.md#releases).

Each section heading must be exactly `## vX.Y.Z`, matching the tag: the
release workflow publishes that section's body as the GitHub release notes,
and refuses to publish a tag without one.

## v1.17.0

**Added**
- Profile groups: each profile is evaluated with the profiles its
  `spring.profiles.group` activates, nested groups included, as Spring
  Boot expands them (ADR-013). `spring.profiles.include` is not evaluated
  yet.
- A stderr warning counts the documents that apply only when several
  profiles are active together (`on-profile: 'a & b'`, or an `on-profile`
  inside `application-x.yml` naming another profile), which SCG doesn't
  evaluate.

**Fixed**
- `spring.config.activate.on-profile` is evaluated as Spring Boot does
  (ADR-012): a list of profile expressions (`!api-docs`, `a | b`,
  `a & b`, `a,b`), and the documents of a directory folded in Spring's
  order (files without a profile in their name, then
  `application-{profile}` files, documents as written). It used to be a
  literal profile name: an expression became a profile of its own, a YAML
  list was folded into the base (a false negative), `default` was a
  profile of its own, and a document conditioned on a profile always won
  over the documents after it.
- `application.yml` takes precedence over `application.yaml` in the same
  directory, as in Spring Boot; SCG ranked them the other way.
- Config Server Mode reads every `application*` file, in Spring's order
  (Global files, the service's files, Global `application-{profile}`
  files). It used to read only the one listed last, so a service written
  in two formats lost a file.
- A YAML null (`x: ~`, or `spring:` with nothing under it) no longer
  removes the keys under it that earlier sources set; Spring keeps and
  binds them.
- Checked against Spring Boot 4.1.1; see `VALIDATION.md`, "Profile
  expressions in `on-profile`" (P1–P15, E1–E11), "Profile groups"
  (G1–G7) and "ProfileMerger correctness benchmark" (cases 35–38).

**Detection changes**
- **Profile labels**: an expression is no longer a profile label
  (`[profile: !api-docs]` is gone; its document applies to every profile
  the expression matches), and neither is `default`, which is part of the
  base. A policy entry naming `default` or an expression no longer
  matches any finding, and an unknown profile in a policy file is not an
  error: name the profiles the findings now show, or `base`.
- **Exit code 2** for an `on-profile` Spring Boot refuses to start with:
  a blank or malformed expression (`'a & b | c'`) or an empty item
  (`[a, ""]`). Such a file used to be scanned with the value as a profile
  name.
- **More findings**: a document whose `on-profile` is a YAML list now
  applies to each profile listed, not to the base; a profile now reports
  what its group's profiles set.
- **Fewer findings**: a document under `on-profile: default` is reported
  once, under the base, no longer again under a `default` profile.
- **Either way**: a document under an expression such as `'!x'` now
  applies to the base and to each profile it matches (all but `x` and
  the profiles whose group activates `x`), where it can turn a setting on
  or off; it used to apply only to a profile named after the expression.
- On the reference corpus and the demo fixtures, against `v1.16.0`:
  `spring-petclinic-microservices-config` goes from 53 to 48 findings
  (the five SCG001 of a `default` label, already reported under the
  base); every other finding is identical. In `jhipster-sample-app`, a
  project with profile groups and a `'!api-docs'` block, 25 become 23.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged; exit code 2 keeps its meaning (usage or input error).

Full diff: `v1.16.0...v1.17.0`.

## v1.16.0

**Added**
- SCG009 reports `debug:` or `debug: ~` (a YAML null) in a base file, as
  MEDIUM: Spring Boot loads a YAML null as an empty string, and an empty
  `debug` turns debug logging on. `ProfileMerger` used to drop such a key
  before any rule saw it.

**Fixed**
- A YAML null is now an empty string in the effective configuration, as
  Spring Boot's YAML loader produces it, in a base file and in a profile
  override (it used to be dropped in a base file and a Java null in a
  profile). Checked through `/actuator/env` against a running Spring Boot
  4.1.1 app. Every rule but SCG009 reads it as unset, as before.

**Detection changes**
- **Lower severity**: SCG012, SCG014, SCG015, SCG016 and SCG017 report a
  connection whose hosts, written literally, are all loopback (`localhost`,
  127.0.0.0/8, `::1`) as INFO instead of HIGH or MEDIUM, saying why: the
  traffic doesn't leave the host, unless a local forwarder relays it or
  the client is sent on to other hosts. Not lowered: a host from a
  placeholder, an unwritten default (Kafka's `localhost:9092`), a
  `*.localhost` name, a value with a parameter that overrides the host
  (PostgreSQL's `?host=`, SQL Server's `;serverName=`) or an SRV scheme,
  Vault found through discovery, and SCG017's `issuer-uri`. With the
  default `--fail-on=HIGH`, a project that failed only on such a
  connection now passes.
- **More findings**: SCG009 for a YAML null `debug` in a base file
  (MEDIUM; with `--fail-on=MEDIUM`, such a project now fails).
- Checked against Spring Boot 4.1.1; see `VALIDATION.md`, "Loopback
  addresses in the transport rules" (L1–L17), "SCG009 verbose logging
  scenarios" (Y4, Y5) and "ProfileMerger correctness benchmark".
- On the reference corpus and the demo fixtures, against `v1.15.0`: nine
  findings on a written `localhost` become INFO (one SCG012 in
  `spring-petclinic-microservices`; one SCG017 and one SCG014 in
  `spring-boot`; five SCG014 in `spring-cloud-stream-samples`); every
  other finding is identical.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.15.0...v1.16.0`.

## v1.15.0

**Added**
- SCG005 reports, as INFO, a header in `exposed-headers` whose name
  suggests a token or a session (it contains `authorization`, `token`,
  `jwt`, `session`, `secret` or `apikey`, ignoring `-` and `_`, as in
  `X-Access-Token` or `X-Api-Key`): Spring lists it in
  `Access-Control-Expose-Headers` like any header, and only the
  application knows whether it carries one. `Authorization` and
  `X-Auth-Token` keep their MEDIUM/LOW finding.

**Fixed**
- SCG005 reported `allowed-methods=*` (and its other findings) as MEDIUM
  when the origin was a placeholder that resolves empty, such as
  `allowed-origins=${ORIGINS:}`: Spring Boot then allows no origin, and the
  app sent no CORS headers. An origin now counts only when it resolves to
  at least one origin, or is a placeholder without a default.
- SCG015 was silent with `spring.rabbitmq.ssl.bundle=${BUNDLE:}`: Spring
  Boot turns TLS on only when the bundle has text, and the client spoke
  plain AMQP. A bundle that resolves empty now counts as unset (MEDIUM, or
  HIGH with `ssl.enabled=false`), and a bundle placeholder without a
  default is INFO unless `ssl.enabled` is true.

**Detection changes**
- **Fewer findings**: SCG005 when the origins resolve to none. With
  `--fail-on=MEDIUM`, a project that failed only on it now passes.
- **More findings**: SCG015 for a bundle that resolves empty (MEDIUM, or
  HIGH with `ssl.enabled=false`; with the default `--fail-on=HIGH`, the
  latter now fails), and INFO for SCG005's token-like exposed headers and
  SCG015's unresolved bundle.
- Each change was checked against Spring Boot 4.1.1: SCG005 in a running
  app, SCG015 on the wire; see `VALIDATION.md`, "SCG005 methods and headers
  scenarios" (E1, M4, T1) and "SCG015 RabbitMQ transport scenarios" (B2,
  B2u). The scenario scripts are in `spring-env-benchmark`.
- On the reference corpus and the demo fixtures, the output is
  byte-identical to `v1.14.0`'s.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.14.0...v1.15.0`.

## v1.14.0

**Added**
- SCG017 reads `spring.security.oauth2.resourceserver.jwt.public-key-location`
  and `spring.security.oauth2.resourceserver.opaquetoken.introspection-uri`:
  with `http://`, the application started with a public key fetched in plain
  HTTP, and introspection sent the client secret in the clear, while the rule
  was silent. Both are HIGH.

**Fixed**
- SCG017 reported every `http://` key on its own. Spring Boot takes the JWT
  keys from the first of `jwk-set-uri`, `issuer-uri` and
  `public-key-location` that is set and never fetches the others, so an
  `http://` `issuer-uri` next to an `https://` `jwk-set-uri` was a HIGH false
  positive. The rule now reports only the key in use. When a key before it
  is a placeholder without a default, which may resolve empty at runtime, an
  `http://` value after it is INFO.
- SCG016 reported `spring.cloud.vault.scheme=http` (or an `http://` `uri`)
  as HIGH with `spring.cloud.vault.enabled` set to a false literal (`false`,
  `FALSE`, `off`, `no`, `0`), where the client made no connection.
- SCG016 reported `scheme=HTTP` and an `HTTP://` `uri` as HIGH. Spring Cloud
  Vault compares the scheme case-sensitively, and those values stopped the
  application from starting ("Scheme must be http or https").
- SCG017's message no longer speaks of a forged JWKS, which doesn't fit a
  public key or introspection; it says what is fetched in plain HTTP and
  what whoever can rewrite that traffic gets.

**Detection changes**
- **Lower severity**: SCG017's `http://` `issuer-uri` next to a
  `jwk-set-uri` that is a placeholder without a default goes from HIGH to
  INFO. With the default `--fail-on=HIGH`, a project that failed only on it
  now passes.
- **Fewer findings**: SCG017 for an `issuer-uri` next to a set
  `jwk-set-uri`, which Spring Boot doesn't fetch, and SCG016 for a disabled
  client or an upper-case scheme. With the default `--fail-on=HIGH`, a project that
  failed only on those now passes.
- **More findings**: SCG017 for an `http://` `public-key-location` when it
  is the key in use, and for an `http://` `introspection-uri` (HIGH; with
  the default `--fail-on=HIGH`, such a project now fails), and for an
  `http://` `public-key-location` after a placeholder without a default
  (INFO).
- Each change was checked on the wire: SCG016 against a Spring Cloud Vault
  5.0.2 client, SCG017 against a running Spring Boot 4.1.1 resource server;
  see `VALIDATION.md`, "SCG016 Vault transport scenarios" and "SCG017
  resource server transport scenarios". The scenario scripts are in
  `spring-env-benchmark`.
- On the reference corpus and the demo fixtures, against `v1.13.0`: the one
  SCG017 finding in `spring-boot` and the one in `demo-project` have the new
  message; every other finding is identical.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.13.0...v1.14.0`.

## v1.13.0

**Added**
- SCG013 reads Actuator health groups (`management.endpoint.health.group.<name>.show-details`
  and `show-components`), served at `/actuator/health/<name>` and at their
  `additional-path`, which can be on the main server port: a group with
  `show-details=always` returned its details while the rule was silent. It
  also reads `show-components`, which returns component names and status
  without details: INFO.

**Fixed**
- SCG002 reported `spring.h2.console.enabled` as HIGH for `yes`, `on`, `1`
  and a trailing space. Spring Boot turns the console on only for `true`,
  in any case; with those values it stayed off. Its message now describes
  the console as observed (a web SQL client that connects to any JDBC URL)
  and says that without `web-allow-others` it answers loopback clients
  only, which can include requests forwarded by a proxy on the same
  machine.
- SCG013 reported `show-details=always` as MEDIUM next to
  `show-components=never`, which hides the details.
- SCG015 missed `spring.rabbitmq.addresses` written as a YAML list; it now
  reads the first entry, whose scheme Spring Boot decides TLS by.
- SCG013's message said "any caller" for `when-authorized`; it now names
  the path, and the roles when they are set.

**Detection changes**
- **Lower severity**: SCG013's `show-details=when-authorized` goes from
  MEDIUM to INFO: anonymous callers got only the status, with or without
  Spring Security. SCG002's `enabled` with a placeholder without a default
  goes from HIGH to INFO, since its value can't be known statically. With
  `--fail-on=MEDIUM`, a build that failed only on `when-authorized` now
  passes.
- **Fewer findings**: SCG002 for `enabled` values other than `true` (with
  the default `--fail-on=HIGH`, such a project no longer fails), and SCG013
  next to `show-components=never`.
- **More findings**: SCG013 for health groups (MEDIUM for
  `show-details=always`) and for `show-components` (INFO), and SCG015 for
  an address list without a scheme (MEDIUM). With `--fail-on=MEDIUM`, a
  project with such a group or list now fails.
- Each change was checked in running Spring Boot 4.1.1 apps, the RabbitMQ
  one on the wire; see `VALIDATION.md`, "SCG002 H2 console scenarios",
  "SCG013 health details scenarios" and "SCG015 RabbitMQ transport
  scenarios". The scenario scripts are in `spring-env-benchmark`.
- On the reference corpus and the demo fixtures, against `v1.12.0`:
  `spring-boot` adds 1 MEDIUM (SCG013, a health group in its Actuator smoke
  test), and every SCG002 and SCG013 finding has a new message (9 in
  `spring-boot`, 30 in `spring-boot-admin`, 1 in
  `spring-cloud-stream-samples`, 4 in `demo-project`); every other finding
  is identical.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.12.0...v1.13.0`.

## v1.12.0

**Added**
- SCG009 reads `logging.level.<logger>`. A `DEBUG` or `TRACE` level on a
  logger that writes secrets to the log, on an ancestor of one, or on Spring
  Boot's `web` or `sql` group containing one is MEDIUM, unless a more
  specific logger sets its own level; any other logger at those levels is
  INFO, since what it writes can't be known statically. In a running app,
  `logging.level.org.springframework.web=debug` wrote request query strings
  and bodies, as `debug=true` does, and Apache HttpClient's loggers wrote
  outbound Authorization headers; the rule only read `debug`, `trace` and
  the root logger.

**Fixed**
- SCG009 reported `debug` and `trace` only for values Spring reads as true.
  Spring Boot turns them on for any value except exactly `false`: `FALSE`,
  `off`, `no`, `0`, an empty value, a trailing space and a quoted YAML
  `"off"` all turned debug logging on, and the rule was silent. A key that
  a profile overrides with null is reported too.
- SCG009's messages said `debug` raises security loggers and logs SQL bound
  parameters; each message now says what that setting wrote in a running
  app.
- SCG010's messages name the Spring Boot versions that read each prefix:
  Spring Boot 4.0 and later ignore `server.error.*`, and earlier versions
  ignore `spring.web.error.*`, so where a key is inert the fix is to remove
  it. Neither rule's messages say "in production" anymore.

**Detection changes**
- **Lower severity**: SCG010's `include-stacktrace` goes from HIGH to
  MEDIUM, like its other three properties: a stack trace carries the
  exception's message and cause chain, more of what `include-message`
  (MEDIUM) discloses, not a different risk. With the default
  `--fail-on=HIGH`, SCG010 no longer fails a build.
- **More findings**: SCG009 for `debug`/`trace` values other than exactly
  `false`, and for `logging.level.<logger>` at `DEBUG`/`TRACE` (MEDIUM or
  INFO, above). With `--fail-on=MEDIUM`, a project that sets one of the
  loggers that write secrets to `DEBUG`/`TRACE` now fails.
- Each change was checked in running Spring Boot apps (4.1.1, and 3.5.16 for
  SCG010's prefixes); see `VALIDATION.md`, "SCG010 error response scenarios"
  and "SCG009 verbose logging scenarios". The scenario scripts are in
  `spring-env-benchmark`.
- On the reference corpus, against `v1.11.0`: SCG009 adds 5 INFO in
  `spring-boot`, 1 MEDIUM and 1 INFO in `spring-boot-admin`, and 1 INFO in
  `spring-cloud-stream-samples`, and `spring-boot`'s `debug=true` finding
  has a new message; every other finding, and the demo fixtures, are
  identical.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.11.0...v1.12.0`.

## v1.11.0

**Added**
- SCG004 and SCG005 read Spring for GraphQL's CORS keys
  (`spring.graphql.cors.*`) next to Actuator's, as SCG003 does; a GraphQL
  origin, method or exposed header used to be silent.
- SCG004 reports origin patterns whose scheme is missing or a wildcard
  (`*.example.com`, `*://app.example.com`, `http*://app.example.com`): a
  running app sent credentials to their `http://` origins.
- SCG003 reports `null` in `allowed-origins` or `allowed-origin-patterns`
  with credentials as HIGH (INFO with credentials from an unresolved
  placeholder). Browsers send `Origin: null` from sandboxed iframes, which
  any page can embed: in Chromium such an iframe read `/actuator/env` with
  credentials.

**Fixed**
- SCG003 and SCG004 reported patterns that only match the local machine
  (`http://localhost:*`, `http://localhost:[*]`, `http://*.localhost`),
  SCG003 as HIGH and SCG004 as MEDIUM, though the app refused
  `http://localhost.evil.com`. Both are silent now. SCG003 is also silent
  for a wildcard only in the scheme or the port (`*://app.example.com`,
  `https://app.example.com:*`), which lets in one host; it was MEDIUM.
- SCG004 split a value on every comma, cutting a port list
  (`http://localhost:[8080,8082]`) in two; values are now split as
  Spring's `CorsConfiguration` splits them.
- SCG004 reported a whole value as INFO when one of its origins used an
  unresolved placeholder. Each origin is evaluated on its own now: a
  literal `http://` origin next to it is reported at its severity, and
  `https://${HOST}` or `http://localhost:${PORT}` are silent.
- SCG005 reported `allowed-methods` and `exposed-headers` with no origin
  key, where Spring Boot builds no CORS configuration; it is silent there
  now.
- SCG004's message no longer limits the risk to "non-development
  environments"; SCG005's `allowed-methods=*` message says a JSON POST
  also needs `allowed-headers`.

**Detection changes**
- **More findings**: SCG004 and SCG005 for Spring for GraphQL; SCG004 for
  patterns with a missing or wildcard scheme; SCG003 for the `null`
  origin, as HIGH, so with the default `--fail-on=HIGH` a project that
  allows `null` with credentials now fails.
- **Lower severity**: SCG004 and SCG005 follow `allow-credentials`:
  MEDIUM when it is true, LOW otherwise (they were MEDIUM), since without
  credentials an `http://` origin, `allowed-methods=*` or an exposed token
  header only reaches anonymous responses. SCG005's `exposed-headers=*`
  goes from MEDIUM to LOW: Chromium ignored it for credentialed requests.
  With `--fail-on=MEDIUM`, builds that failed only on these now pass.
- **Fewer findings**: the loopback and single-host patterns above (SCG003,
  SCG004), a loopback port list (SCG004), and SCG005 without an origin key.
- Each change was checked in running Spring Boot 4.1.1 apps and in
  Chromium; see `VALIDATION.md`, "SCG003 CORS scenarios", "SCG004 insecure
  origin scenarios" and "SCG005 methods and headers scenarios". The
  scenario scripts are in `spring-env-benchmark`.
- On the reference corpus and the demo fixtures, against `v1.10.0`: every
  finding is identical.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.10.0...v1.11.0`.

## v1.10.0

**Added**
- SCG011 reads WebFlux's session cookie keys
  (`server.reactive.session.cookie.secure`, `http-only`, `same-site`), which
  set the cookie a WebFlux application sends; it used to read only the
  servlet keys.
- SCG011 reports disabled server SSL whatever the TLS material: a PEM
  certificate (`server.ssl.certificate`), an SSL bundle (`server.ssl.bundle`)
  or server-name bundles, not only a key-store. It also reports disabled
  management SSL when the management connector inherits `server.ssl.*`
  (`management.server.ssl.enabled=false` with no management key-store).
- SCG006 reports eight native secrets that no pattern matched:
  `spring.kafka.ssl.key-store-key` and its `admin`, `consumer`, `producer`
  and `streams` variants (a PEM private key),
  `spring.neo4j.authentication.kerberos-ticket`,
  `spring.liquibase.license-key` and
  `management.datadog.metrics.export.application-key`.
- SCG007 finds a password in a MySQL host specification
  (`jdbc:mysql://(host=db,user=app,password=...)/app`,
  `jdbc:mysql://address=(host=db)(password=...)/app`), which Connector/J
  reads.
- SCG012 reports pgjdbc's `sslfactory=org.postgresql.ssl.NonValidatingFactory`,
  which accepts any server certificate, as MEDIUM.

**Fixed**
- SCG011 reported management SSL turned off as HIGH where it has no effect:
  with a negative `management.server.port` (the management server is off)
  or one equal to `server.port` (or to 8080 when that isn't set), as Spring
  Boot's `ManagementPortType` decides. It is silent there now; an unresolved
  placeholder in either port is INFO. Its SSL message no longer suggests
  removing the key-store settings, which would only hide the evidence.
- SCG006 reported a boolean written `on`, `yes`, `off` or `no` in a key
  ending in a secret pattern (`management.endpoints.web.cors.allow-credentials: on`)
  as a HIGH secret. Spring reads all of them as booleans, so they are
  switches now, like `true` and `false`.
- SCG003 classified an origin pattern only by whether a literal host follows
  the wildcard, so `https://*.com`, `https://*example.com` and
  `https://app.*` were MEDIUM, though an attacker can register a matching
  origin: a running app sent credentials to `evil.com`, `evilexample.com`
  and `app.evil.com`. They are HIGH now.
- The coverage warning for config files in more than one Spring config
  location said only that a risk split across locations is not detected; it
  now also says a finding can be one that a setting in another location
  turns off.

**Detection changes**
- **More findings**: SCG011, SCG006, SCG007 and SCG012 report the forms
  listed under Added, which they used to miss.
- **Higher severity**: SCG003's origin patterns that an attacker can match
  go from MEDIUM to HIGH.
- **Lower severity or fewer findings**: SCG011's session cookie checks
  (`secure`, `http-only`) go from HIGH to MEDIUM, like `same-site`: none
  exposes the cookie without a second weakness, and on Tomcat and Jetty
  `secure=false` has no effect, which the message now says. SCG011 is silent
  for management SSL on a disabled or shared management port, and SCG006
  for `on`/`yes`/`off`/`no`. With `--fail-on=HIGH`, builds that failed only
  on SCG011's cookie findings now pass.
- Each change was checked in running Spring Boot 4.1.1 apps (SCG003,
  SCG011), against the client that reads the value (SCG007, SCG012) or
  against Spring Boot 4.1.1's configuration metadata (SCG006); see each
  rule's section in `VALIDATION.md`. The scenario apps are now in
  `spring-env-benchmark`.
- On the reference corpus, against `v1.9.0`: every finding is identical;
  only the coverage warning's wording changes.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.9.0...v1.10.0`.

## v1.9.0

**Added**
- SCG003 also reads Spring for GraphQL's CORS properties
  (`spring.graphql.cors.*`), the other CORS configuration Spring Boot binds
  from properties, with the same keys and the same results as Actuator's:
  `allowed-origin-patterns: "*"` or `"https://*"` with credentials is HIGH,
  a domain pattern MEDIUM.

**Fixed**
- SCG003 treated both origin keys alike. Checked in running Spring Boot
  4.1.1 apps (`VALIDATION.md`, "SCG003 CORS scenarios"): in
  `allowed-origins`, a wildcard other than `*` is compared literally (Spring
  answers 403), so it is no longer reported; `*` with credentials is
  rejected by Spring (Actuator's mapping fails at startup, GraphQL answers
  every CORS request with 500), so it is LOW (present but ineffective)
  instead of HIGH. An unresolved placeholder, in an origin key or in
  `allow-credentials`, is INFO instead of HIGH.
- SCG008 reported "Swagger UI remains exposed" for
  `springdoc.api-docs.enabled=false`, which turns SpringDoc off entirely:
  checked in a running Spring Boot 4.1.1 app with SpringDoc 3.1.1, the spec
  and the UI both answer 404, even with `springdoc.swagger-ui.enabled=true`
  (`VALIDATION.md`, "SCG008 SpringDoc scenarios"). It is now silent.

**Detection changes**
- **Fewer or lower findings**: SCG003 drops literal wildcards in
  `allowed-origins`, reports `allowed-origins: "*"` with credentials as LOW
  and unresolved placeholders as INFO; SCG008 is silent once
  `springdoc.api-docs.enabled` is `false`. With `--fail-on=HIGH`, builds
  that failed only on SCG003's `allowed-origins: "*"` now pass.
- **More findings**: SCG003 reports Spring for GraphQL's CORS. SCG008
  reports a placeholder in `springdoc.swagger-ui.enabled` as MEDIUM instead
  of INFO when the spec is served: only the UI depends on it.
- On the reference corpus, against `v1.8.0`: every finding and coverage
  warning is identical. The demo projects' CORS fixtures now use
  `allowed-origin-patterns: "*"`, the form that is a real risk.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.8.0...v1.9.0`.

## v1.8.0

**Added**
- SCG007 finds an embedded credential by the shape of the value, in every
  property, instead of a list of keys: a password in a URL's user-info (in
  any node of a comma-separated list), a URL parameter ending in `password`
  (PostgreSQL and MySQL `?password=`, SQL Server and H2 `;password=`,
  `trustStorePassword=`), Oracle's `user/password@host`, and a JAAS
  `password` or OAuthBearer `clientSecret` option, quoted or not. It now
  covers Spring Boot 4's `spring.data.redis.url` and `spring.mongodb.uri`,
  `spring.flyway.url`, the pool-specific JDBC URLs, the Kafka per-client
  `sasl.jaas.config`, Spring Cloud (`spring.cloud.config.uri`, Eureka's
  `defaultZone`) and the application's own keys. A literal password next to
  an unresolved placeholder (`u:secret@${DB_HOST}`) is found too. See
  ADR-011.
- SCG012 looks for its TLS parameters in every property whose value starts
  with `jdbc:`, `r2dbc:`, `mongodb:` or `mongodb+srv:`, so
  `spring.mongodb.uri`, `spring.flyway.url` and the pool-specific JDBC URLs
  are covered whatever their key, and it checks the scheme of every node of
  a list (`spring.elasticsearch.uris=https://a,http://b`). New values: SQL
  Server `encrypt=no` and `encrypt=optional`, MariaDB `sslMode=false` and
  `sslMode=0` (TLS off, HIGH), and PostgreSQL `sslmode=require`, MySQL
  `sslMode=REQUIRED`, MariaDB `sslMode=trust`, which encrypt without
  checking the certificate (MEDIUM).

**Fixed**
- SCG007 read an `@` in a URL parameter (`?ApplicationName=a@b`) as a
  user-info password and reported HIGH.

**Detection changes**
- **More findings**: SCG007 and SCG012 report the forms above, which they
  used to miss. Each was confirmed against the client that reads it, in the
  versions Spring Boot 4.1.1 manages (`VALIDATION.md`, "SCG007 credential
  forms" and "SCG012 driver modes").
- **Lower severity**: SCG012's certificate-validation findings
  (`verifyServerCertificate=false`, `trustServerCertificate=true`,
  `tlsInsecure=true` and the others) move from HIGH to MEDIUM: the traffic is
  encrypted, and reading it takes an active man in the middle. TLS turned
  off stays HIGH. With `--fail-on=HIGH`, builds that failed only on these
  now pass.
- **Rule ID change**: a password in the user-info of a URL in a key ending
  in `-uri`/`-url`/`-endpoint` that contains a secret pattern, reported by
  SCG006 since v1.7.0, is reported by SCG007, so one credential is reported
  once. A `--policy` suppressing it by `SCG006` no longer applies to it.
- On the reference corpus, against `v1.7.0`: every finding and coverage
  warning is identical.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.7.0...v1.8.0`.

## v1.7.0

**Added**
- SCG006 checks the URL in a key that contains a secret pattern but ends in
  `-uri`/`-url`/`-endpoint` (`app.security.token-url`), which used to be
  skipped whatever its value: a password in the URL's user-info
  (`https://user:secret@host`) is HIGH, a query string (`?token=...`) is
  INFO. A plain URL or path stays silent; a secret in the path itself (a
  webhook URL) is not detected.
- SCG006 reports a `classpath:` value in a key naming secret material
  (`private-key: classpath:server.key`) as INFO: the material is packaged
  inside the application. It used to be skipped as a mere reference.
  `file:` values are still skipped, and so is a certificate or its location
  (public material).

**Fixed**
- SCG006 matched a secret pattern (`password`, `secret`, `token`,
  `credential`, ...) anywhere in a key, so a namespace, a map key or a
  package name containing the word was reported as HIGH, including Spring
  Boot's own properties: `spring.security.oauth2.authorizationserver.client.<id>.token.access-token-time-to-live=5m`,
  `spring.security.oauth2.resourceserver.opaquetoken.client-id`,
  `logging.level.<package>.token=DEBUG`, `spring.cloud.kubernetes.secrets.namespace`.
  A key is now HIGH only when it ends in a pattern; a key that only
  contains one is INFO, since it may still name a secret
  (`app.secret-key-base`); `logging.level` and `logging.group` are skipped.
  Three `high-risk-keys` absent from Spring Boot 4.1.1 were replaced and 11
  current ones added.
- SCG014 evaluated every `security.protocol` key on its own, so an insecure
  value overridden by a secure one was still reported as HIGH (e.g.
  `spring.kafka.security.protocol=PLAINTEXT` with
  `spring.kafka.properties.security.protocol=SSL`). It now resolves the
  protocol each Kafka client gets as Spring Boot does (client properties
  map, client key, common properties map, common key) and reports only the
  keys a client uses. The "not set" finding names the clients left without
  a protocol, and is no longer raised when every client has its own key.

**Detection changes**
- **Fewer HIGH findings**: SCG006 keys that only contain a secret pattern
  move from HIGH to INFO, and SCG014 no longer reports overridden values.
  With `--fail-on=HIGH`, some builds that failed only on these now pass.
- **New findings**: SCG006 reports a password in a URL's user-info as HIGH,
  and a query string or a `classpath:` secret as INFO, in keys it used to
  skip.
- Measured on 30 hand-built keys and Spring Boot 4.1.1's configuration
  metadata (`VALIDATION.md`, "SCG006 key matching") and on Spring Boot's
  own `KafkaProperties` (`VALIDATION.md`, "SCG014 protocol precedence").
- On the reference corpus, against `v1.6.0`: 6 SCG006 INFO added in
  `spring-boot`, all private keys packaged with an application (the SNI
  integration tests' PEM bundles and the SAML smoke test's
  `private-key-location`); the 3 SCG014 "not set" findings keep their rule,
  severity, file and profile, with new wording. Every other finding and
  coverage warning is identical.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.6.0...v1.7.0`.

## v1.6.0

**Fixed**
- SCG001 now resolves which Actuator endpoints are exposed over HTTP as
  Spring Boot does, checked against a running Spring Boot 4.1.1 app in 18
  configurations (`VALIDATION.md`, "SCG001 exposure scenarios"). It used to
  read only `exposure.include` and each endpoint's own `access`/`enabled`;
  it now also applies `exposure.exclude`, `management.server.port=-1`,
  `management.endpoints.access.max-permitted`, the global
  `management.endpoints.access.default` and the legacy
  `management.endpoints.enabled-by-default`, and `read-only` access leaves
  write-only endpoints (`shutdown`, `restart`) unreachable.

**Detection changes**
- **SCG001 no longer reports endpoints Spring doesn't expose** (false
  positives in nine of the scenarios above): those listed in
  `exposure.exclude` (or all of them with `exclude=*`), every endpoint under
  `access.default=none`, `max-permitted=none`, `enabled-by-default=false`
  or `management.server.port=-1` unless opted in on its own, and write-only
  endpoints under `max-permitted=read-only`. The finding disappears when no
  sensitive endpoint is left exposed; otherwise the excluded ones drop out
  of its message. (Corrected on 2026-10-02: these notes were published with
  "six false positives"; re-running the scenarios against the v1.5.0 jar
  found nine. See `VALIDATION.md`, "SCG001 exposure scenarios".)
- **SCG001 now reports `heapdump` and `shutdown`** where a global default
  opens them, though they are restricted by default:
  `access.default=unrestricted` or `enabled-by-default=true` open both, and
  `access.default=read-only` opens `heapdump` (three false negatives). With
  `exposure.include=*` the finding already existed, and these endpoints are
  now listed in its message; a new finding appears only when no other
  sensitive endpoint was exposed (e.g. `include=heapdump`).
- **Lower severity for findings based on an absent key** (ADR-010): when the
  only evidence is a key that isn't set and whose default is insecure, the
  finding is MEDIUM instead of HIGH, since the key may be set outside the
  scanned files, e.g. by an environment variable. Applies to SCG014 (Kafka,
  or a Spring Cloud Stream Kafka binder, with no `security.protocol`) and
  SCG015 (RabbitMQ with `ssl.enabled` absent or an empty placeholder
  default); each message says why it is MEDIUM. An insecure value written
  in the files (`PLAINTEXT`, `SASL_PLAINTEXT`, `ssl.enabled=false`) stays
  HIGH. With the default `--fail-on=HIGH`, these findings alone no longer
  fail the build; `--fail-on=MEDIUM` still fails on them.
- On the reference corpus, against `v1.5.0`: 31 SCG014 findings in
  `spring-cloud-stream-samples` and 1 in `spring-boot` go from HIGH to
  MEDIUM, with the same rule, file and profile. Every other finding and
  coverage warning is identical; the SCG001 fix changes no finding there.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.5.0...v1.6.0`.

## v1.5.0

**Added**
- SCG007 and SCG014 now cover the Spring Cloud Stream Kafka and Kafka
  Streams binders, which configure Kafka clients through their own
  properties instead of `spring.kafka.*`. The binders are evaluated as
  Spring Cloud Stream resolves them: each client builds on `spring.kafka.*`,
  overridden by the binder's `configuration` map, overridden by its
  `consumer-properties`/`producer-properties`; a named binder's
  `spring.cloud.stream.binders.<name>.environment` is a context of its own,
  on top of the main one it inherits (unless `inherit-environment` is
  false). See ADR-009.
  - SCG007 reports a plaintext JAAS password in `sasl.jaas.config` in the
    binders' client maps, and inside a binder's environment.
  - SCG014 reports `PLAINTEXT`/`SASL_PLAINTEXT` written in the binders'
    client maps, and in `spring.kafka.*` inside a binder's environment. A
    top-level value inherited by several binders is reported once.
  - SCG014 reports a binder in use with no protocol covering all its
    clients (the binder's `configuration` map or `spring.kafka.security.protocol`;
    a consumer-only or producer-only value leaves the other clients on
    Kafka's `PLAINTEXT` default), the check it already applied to
    `spring.kafka.*`. It isn't repeated where that check already reports the
    same gap.
- Messages name the key as written, including a binder's environment
  prefix, and the binder a finding is about.

**Detection changes**
- **More findings**, all in the new binder checks above. On the reference
  corpus, 34 findings added, all in `spring-cloud-stream-samples`: 2 SCG007
  and 3 SCG014 on values written in the binder (the two false negatives
  recorded in `VALIDATION.md`), and 29 SCG014 for samples that configure
  Kafka only through the binder with no protocol set.
- Every other reference project reports the same findings and coverage
  warnings as `v1.4.0`.
- Known limitations: a protocol set only through an environment variable
  is invisible, so such a binder is reported as unset (as for
  `spring.kafka.*`); a project using the binder with no binder key at all is
  not recognized as using it.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.4.0...v1.5.0`.

## v1.4.0

**Added**
- SCG006 now reports a numeric secret when the key ends in a secret
  pattern (`...password`, `...secret`, `...api-key`, ...), since such a key
  names the secret itself: `ssl.keystore.password: 123456` was skipped by
  the heuristic that treats numeric values as metrics, not secrets. Numeric
  values in other keys (`token-validity-in-seconds: 86400`,
  `password-min-length: 8`) and booleans in any key
  (`require-password: true`) are still skipped.

**Fixed**
- A list index written as a quoted YAML key (`"[0]":`) was joined with a
  dot (`x.[0]`) instead of Spring's `x[0]`, so it wasn't recognized as a
  list item. With the jar of v1.3.1, `exposure.include: {"[0]": "*"}`
  raised no SCG001, and a profile writing `"[0]": {url: ...}` over a base
  list kept the base's whole list, so SCG006 reported a base password
  Spring drops in that profile. YAML keys starting with `[` now join their
  parent without a dot, as in Spring's YAML loader. See ADR-008.

**Detection changes**
- **More findings**: SCG006 on numeric values in keys ending in a secret
  pattern. On the reference corpus, 3 findings added in
  `spring-cloud-stream-samples`: the three numeric SSL passwords in
  `kafka-ssl-demo`, a false negative recorded in `VALIDATION.md`.
- **More findings**: SCG001 and any rule reading a list now see items
  written as quoted YAML index keys.
- **Fewer findings**: a profile replacing a base list through a quoted
  index key no longer inherits the base's items, so findings on them (e.g.
  SCG006 on a base password) no longer appear in that profile.
- Every other reference project reports the same findings and coverage
  warnings as `v1.3.1`; none of them uses quoted index keys.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Documentation: the `/actuator` benchmark now compares lists written in two
formats, lists of objects partially overridden, and a scalar and a map on
the same key against `/actuator/configprops` (6 benchmark tests); only the
quoted index case needed a fix. `VALIDATION.md` and `CLAUDE.md` record the
results, including that SCG keeps both shapes of a key written as a scalar
and as a map, as Spring does.

Full diff: `v1.3.1...v1.4.0`.

## v1.3.1

**Fixed**
- Bracketed map keys (`spring.kafka.properties[sasl.jaas.config]`,
  `logging.level[com.example]`, or `"[security.protocol]"` in YAML) were
  treated as list indices. Rules look properties up by their dotted name, so
  they never matched the bracketed spelling: SCG007 missed a plaintext JAAS
  password written that way, and SCG014 reported Kafka as `PLAINTEXT` even
  when `spring.kafka.properties[security.protocol]=SASL_SSL` was set. In
  profiles, an entry added by the profile discarded every entry the base
  defined in that map. SCG now rewrites bracketed map keys into dotted form
  when loading `.yml` and `.properties` files, keeping numeric list indices,
  as Spring Boot's binder does. See ADR-007.
- The same input could produce a different report on each run: SCG001
  listed endpoints in an order that changed from one JVM run to the next,
  and findings one rule reported in the same file and profile could swap
  places. Output is now byte-identical on every run, in JSON and console:
  SCG001 lists endpoints in a fixed order (`env, threaddump, configprops,
  beans, loggers`; `env, configprops`), and findings tied on severity, file
  and profile are ordered by rule ID and then message.

**Detection changes**
- **More findings** where a sensitive property is written with brackets:
  SCG007 now reports a plaintext JAAS password in
  `spring.kafka.properties[sasl.jaas.config]`, in both formats.
- **Fewer findings**: SCG014 no longer reports Kafka as unencrypted when the
  secure protocol is set through `spring.kafka.properties[security.protocol]`.
- **More findings in profiles**: a profile adding one entry to a map
  written with brackets keeps the base's entries, as Spring does, so
  findings on those entries now appear in that profile too. For example, a
  hardcoded `spring.kafka.properties[ssl.keystore.password]` in the base
  was reported by SCG006 only on the base when a profile added its own
  `spring.kafka.properties[...]` entry; it is now reported on the profile
  as well.
- **Finding messages** name the dotted key
  (`spring.kafka.properties.sasl.jaas.config`), not the bracketed spelling
  written in the file.
- **Known limitation**: brackets keep characters relaxed binding ignores,
  so `[com.foo-bar]` and `[com.foobar]` are two entries in Spring but one
  key in SCG, the later overriding the earlier (ADR-007).
- The same findings and coverage warnings as `v1.3.0` on every reference
  project (demo fixtures, `spring-env-benchmark`, and the `VALIDATION.md`
  repositories): none of them uses bracketed keys. Only the order of the
  endpoint lists in SCG001 messages differs, now fixed.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Documentation: `VALIDATION.md` adds `spring-cloud-stream-samples`, with
three false negatives recorded for the rule-by-rule review, and the
`/actuator` benchmark now checks bracketed map keys against
`/actuator/configprops`.

Full diff: `v1.3.0...v1.3.1`.

## v1.3.0

**Added**
- `--version` flag: prints `spring-config-guard <version>` and exits 0,
  before validating any other argument (like `--help`, which still wins
  when both are given). The version comes from the `pom.properties` Maven
  writes into the jar; outside a packaged jar it is reported as unknown
  rather than guessed.
- The release workflow now fails unless the built jar's `--version` reports
  exactly the version being released, so a published jar always identifies
  itself correctly.

**Detection changes**
- None. Findings and coverage warnings are identical to `v1.2.0` on every
  reference project (demo fixtures, `spring-env-benchmark`, and the four
  `VALIDATION.md` repositories).

**Breaking changes**
- None. `--version` is a new flag; report formats, existing flags, exit
  codes and the Policy file schema are unchanged.

Documentation: README now explains what a finding's `sourceFile`
identifies, and CONTRIBUTING.md classifies a new optional JSON field as a
MINOR change.

Full diff: `v1.2.0...v1.3.0`.

## v1.2.0

**Added**
- New coverage warning for configuration split across Spring config
  locations. When one module has `application*` files in more than one of
  `src/main/resources`, `src/main/resources/config` and `config/`, SCG
  prints to stderr: `spring-config-guard: N application(s) have config
  files in more than one Spring config location, evaluated independently --
  risks split across locations are not detected.` Spring merges those
  locations at runtime; SCG evaluates each directory on its own, so a risky
  combination split across them (e.g. `allowed-origins: "*"` in one and
  `allow-credentials: true` in the other) produces no finding. The warning
  makes that gap visible. Like the `spring.config.import` warning, it is not
  a `Finding` and doesn't affect `--fail-on`. See ADR-005.
- Release jars are now built, tested and published by GitHub Actions from
  the exact commit of the release tag, with notes taken from `CHANGELOG.md`.

**Fixed**
- When `application.yml` and `application.properties` coexisted in the same
  directory (or two files for the same profile, in both formats), every
  property of one of the two files was silently dropped and never analyzed.
  Both are now merged, with `.properties` winning a key conflict, as Spring
  Boot does. See ADR-003.
- A named profile file (`application-prod.yml`) and a
  `spring.config.activate.on-profile: prod` document inside a base file are
  now merged into a single `prod` configuration, the named file winning a
  key conflict (confirmed against a running Spring Boot app). They were
  previously evaluated as two separate `prod` configurations. Also fixes a
  `NullPointerException` when that merge involved an explicit `null`
  override.

**Detection changes**
- **More findings** in projects affected by the first fix: the file that
  used to be dropped is now analyzed, so its findings appear for the first
  time.
- **Fewer findings**: `src/test/` and Maven/Gradle build output (`target/`
  or `build/` next to a `pom.xml`/`build.gradle`/`build.gradle.kts`) are no
  longer scanned, since neither ships with the application. Running SCG
  after a build no longer duplicates every finding from `target/classes`,
  and test-only config no longer fails the gate. On the `spring-boot`
  validation run, 66 findings become 64 (both removed ones came from
  `src/test/resources`). Passing one of those directories directly as
  `<project-path>` still scans it. See ADR-006.
- **Profiles defined both by a named file and by an on-profile block**
  (second fix), where the two used to be evaluated separately:
  - more findings when a risky combination is split between them (e.g.
    `allowed-origins: "*"` in the block, `allow-credentials: true` in the
    file now raises SCG003; it raised nothing before);
  - fewer findings when the file overrides the block with a safe value
    (a value the block enabled and the file disables is no longer flagged);
  - one finding instead of two when both define the same risky value.
- **Source file of base findings** when both formats are present: findings
  on the merged base configuration now always name the highest-precedence
  file (`application.properties`) as `sourceFile`, even when the property
  itself is defined in `application.yml`.

**Breaking changes**
- None. Report formats, CLI flags, exit codes and the Policy file schema are
  unchanged.

Full diff: `v1.1.0...v1.2.0`.

## v1.2.0-rc.1

Pre-release published to validate the automated release workflow
(`.github/workflows/release.yml`) end to end — manual trigger, version
and tag checks, build and tests, tag creation, notes from this changelog,
jar attached. Not intended for use: pin `v1.1.0` or wait for `v1.2.0`, whose
notes will list the changes since `v1.1.0`.

**Detection changes**
- Same as the current `main`; they will be listed in `v1.2.0`.

**Breaking changes**
- None.

Full diff: `v1.1.0...v1.2.0-rc.1`.

## v1.1.0

**Added**
- New coverage warning: SCG now prints an unconditional line to stderr
  (`spring-config-guard: N file(s) import external configuration via
  spring.config.import that was not scanned.`) whenever a scanned file
  declares `spring.config.import` — that imported content stays
  invisible to every rule, and previously nothing in the report
  indicated it had been skipped. Deliberately not a `Finding`: kept
  outside the report and the `--fail-on` filter so it can't compete
  with, or hide behind, actual findings. Does not resolve or follow the
  import itself; see `Scope & Limitations` in the README for why.

No breaking changes. Full diff: `v1.0.2...v1.1.0`.

## v1.0.2

**Fixed**
- `SCG002` (H2 console enabled) no longer leaks the internal "no active
  profile" sentinel (`__spring_config_guard_base__`) into the finding's
  message text for the base/no-profile case — it now behaves like every
  other rule, relying on the separate `profileLabel` field instead of
  restating the profile inline.
- `SCG008` (Swagger/OpenAPI exposure) no longer frames its description
  and messages around "production" — the rule has always been
  profile-agnostic (Zero-Trust, no profile exemption), and the old
  wording could mislead a reader into treating a `dev`/`test` finding as
  safe to ignore.

No breaking changes. Full diff: `v1.0.1...v1.0.2`.

## v1.0.1

**Fixed**
- `SCG010` (verbose HTTP error responses) now also detects the
  `spring.web.error.include-*` property family introduced in Spring Boot
  4.0, alongside the existing `server.error.include-*` (3.x) keys. Spring
  Boot 4.0 renamed the whole `server.error.*` group to `spring.web.error.*`
  (confirmed against the official OpenRewrite migration recipe,
  `SpringBootProperties_4_0`); a project already migrated to 4.0 using the
  new property names previously went undetected by this rule.

No breaking changes. Full diff: `v1.0...v1.0.1`.

## v1.0

Static-analysis CLI that lints Spring Boot `application.{properties,yml,yaml}`
files for security misconfigurations before deployment — runs as a CI gate,
not against a live URL.

**What's in this release**
- 17 rules (`SCG001`–`SCG017`) covering Actuator exposure, hardcoded
  credentials, insecure TLS transport (DB/broker, Kafka, RabbitMQ, Vault,
  OAuth2), CORS misconfiguration, Swagger/OpenAPI exposure, verbose
  logging/errors, and server SSL/session cookie settings — see the
  [rule catalog](https://github.com/rgiovann/spring-config-guard#rules).
- `--config-server` mode for scanning Spring Cloud Config Server backing
  repositories.
- `--policy` for explicit, auditable suppression of findings by rule +
  profile.
- `--json` output and `--fail-on` severity threshold for CI gating.
- Validated against real-world repositories (Spring Boot, Spring Boot Admin,
  Spring PetClinic, and a real Spring Cloud Config Server backing repo) —
  see [Validated against real-world code](https://github.com/rgiovann/spring-config-guard#validated-against-real-world-code).

**Usage**
```
java -jar spring-config-guard.jar <project-path> [--json] [--config-server] [--fail-on=HIGH|MEDIUM|LOW|NONE] [--policy=<file>]
```

Requires Java 21+. Apache License 2.0.
