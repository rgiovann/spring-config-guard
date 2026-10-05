# spring-env-benchmark

The Spring Boot apps and scripts SCG is checked against: what a real
application does with a configuration, compared with what SCG reports for
it. The results, and what each one shows, are in
[`VALIDATION.md`](../VALIDATION.md); each script's header says what it
measures and cites its section there.

This directory is not a module of SCG's build. Each app is its own Maven
project, so SCG never depends on Spring Boot.

## Requirements

Java 21, Maven, `curl` and `python3`. A few scripts need more (below).
Every script changes to its own directory first, so it can be run from
anywhere, and builds the apps it starts, except where noted.

## The `/actuator/env` benchmark

This directory's own app (`pom.xml`, `src/`) is the fixture for
`ActuatorEnvComparisonTest` ("ProfileMerger correctness benchmark"):

```bash
cd spring-env-benchmark
mvn spring-boot:run "-Dspring-boot.run.profiles=prod"
# then, from the repository root, in another shell:
mvn test -Dgroups=benchmark -DexcludedGroups=
```

## Rule scenarios

| Script | Rule | `VALIDATION.md` section | App | Also needs |
|---|---|---|---|---|
| `actuator-exposure-scenarios.sh` | SCG001 | SCG001 exposure scenarios | this directory's | the jar built first: `mvn -q package -DskipTests` |
| `h2-console-scenarios.sh` | SCG002 | SCG002 H2 console scenarios | `h2-console/` | |
| `cors-scenarios.sh` | SCG003 | SCG003 CORS scenarios | this directory's | the jar built first: `mvn -q package -DskipTests` |
| `graphql-cors-scenarios.sh` | SCG003 | SCG003 CORS scenarios | `graphql-cors/` | |
| `null-origin-browser-probe.sh` | SCG003 | SCG003 CORS scenarios | this directory's | Node.js and Playwright with a Chromium (`NODE_PATH`) |
| `cors-insecure-origin-scenarios.sh` | SCG004 | SCG004 insecure origin scenarios | this directory's, `graphql-cors/` | |
| `localhost-browser-probe.sh` | SCG004 | SCG004 insecure origin scenarios | none | a Chromium binary in `CHROME`; `getent` |
| `cors-methods-headers-scenarios.sh` | SCG005 | SCG005 methods and headers scenarios | this directory's | Node.js and Playwright with a Chromium (`NODE_PATH`) |
| `springdoc-scenarios.sh` | SCG008 | SCG008 SpringDoc scenarios | `springdoc/` | |
| `verbose-logging-scenarios.sh` | SCG009 | SCG009 verbose logging scenarios | `verbose-logging/` | |
| `error-response-scenarios.sh` | SCG010 | SCG010 error response scenarios | `error-response/`, `error-response-webflux/`, `error-response-boot3/` | |
| `server-transport-scenarios.sh` | SCG011 | SCG011 transport scenarios | `server-transport-tomcat/`, `-jetty/`, `-session/`, `-webflux/` | `keytool`, `openssl` |
| `health-details-scenarios.sh` | SCG013 | SCG013 health details scenarios | `health-details/`, `health-details-secured/` | |
| `kafka-precedence-scenarios.sh` | SCG014 | SCG014 protocol precedence | `kafka-precedence/` (a program, no server) | |
| `rabbit-transport-scenarios.sh` | SCG015 | SCG015 RabbitMQ transport scenarios | `rabbit-transport/` | `keytool` |
| `vault-transport-scenarios.sh` | SCG016 | SCG016 Vault transport scenarios | `vault-transport/` | |
| `jwt-transport-scenarios.sh` | SCG017 | SCG017 resource server transport scenarios | `jwt-transport/` | `openssl` |

The transport scripts (SCG015 to SCG017) need no broker or server: the
`listener.py` in each app's directory records what the client sends on
the wire. `h2-console/loopback-proxy.py` is the same-host reverse proxy
the SCG002 scenarios go through.

SCG006, SCG007 and SCG012 have no script: they were checked against
Spring Boot's configuration metadata and the drivers' own code, as their
sections describe.
