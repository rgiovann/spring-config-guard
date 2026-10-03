#!/bin/bash
# How Spring Boot answers a cross-origin request from a plain-HTTP origin, one CORS configuration at
# a time: the reference SCG004 is checked against (VALIDATION.md, "SCG004 insecure origin scenarios").
#
# Each scenario starts an app with extra properties as command-line arguments, waits until the
# previous app has released the port and the new one has started, sends a request with each Origin
# listed, and prints the CORS response headers. Actuator scenarios (A) run this benchmark app on
# port 8081 (GET /actuator/env); GraphQL scenarios (G) run the graphql-cors app on port 8091
# (POST /graphql).
set -u
cd "$(dirname "$0")"
mvn -q package -DskipTests || exit 1
(cd graphql-cors && mvn -q package -DskipTests) || exit 1
LOG=target/scg004-scenario.log
A=--management.endpoints.web.cors
G=--spring.graphql.cors

cors_headers() {
    tr -d '\r' | grep -iE "^HTTP|access-control-allow-(origin|credentials)" | tr '\n' ' '
}

# start <port> <jar> <started-line> <args...>: returns 0 once the app has logged its started line.
start() {
    local port=$1 jar=$2 started=$3; shift 3
    while (echo > /dev/tcp/localhost/$port) 2>/dev/null; do sleep 1; done
    java -jar "$jar" "$@" > "$LOG" 2>&1 &
    PID=$!
    for _ in $(seq 1 90); do
        grep -q "$started\|APPLICATION FAILED" "$LOG" && break
        kill -0 "$PID" 2>/dev/null || break
        sleep 1
    done
    grep -q "$started" "$LOG"
}

stop() {
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
}

actuator() {
    local name=$1 origins=$2; shift 2
    if start 8081 target/spring-env-benchmark-0.0.1-SNAPSHOT.jar "Started " --spring.profiles.active=prod "$@"; then
        for origin in $origins; do
            printf '%-46s %-32s %s\n' "$name" "$origin" \
                "$(curl -s -o /dev/null -D - localhost:8081/actuator/env -H "Origin: $origin" | cors_headers)"
        done
    else
        printf '%-46s app did not start\n' "$name"
    fi
    stop
}

graphql() {
    local name=$1 origins=$2; shift 2
    if start 8091 graphql-cors/target/graphql-cors.jar "Started GraphQlApp in" --server.port=8091 "$@"; then
        for origin in $origins; do
            printf '%-46s %-32s %s\n' "$name" "$origin" \
                "$(curl -s -o /dev/null -D - -X POST localhost:8091/graphql -H "Origin: $origin" \
                    -H "Content-Type: application/json" -d '{"query":"{hello}"}' | cors_headers)"
        done
    else
        printf '%-46s app did not start\n' "$name"
    fi
    stop
}

actuator "A1 origins=http://partner.example, cred."     "http://partner.example"  $A.allowed-origins=http://partner.example $A.allow-credentials=true
actuator "A2 origins=http://partner.example"            "http://partner.example"  $A.allowed-origins=http://partner.example
actuator "A3 origins=HTTP://PARTNER.EXAMPLE, cred."     "http://partner.example"  $A.allowed-origins=HTTP://PARTNER.EXAMPLE $A.allow-credentials=true
actuator "A4 patterns=HTTP://partner.example, cred."    "http://partner.example"  $A.allowed-origin-patterns=HTTP://partner.example $A.allow-credentials=true
actuator "A5 patterns=*.example.com, cred."             "http://a.example.com"    $A.allowed-origin-patterns='*.example.com' $A.allow-credentials=true
actuator "A6 patterns=*://app.example.com, cred."       "http://app.example.com"  $A.allowed-origin-patterns='*://app.example.com' $A.allow-credentials=true
actuator "A7 patterns=http*://app.example.com, cred."   "http://app.example.com"  $A.allowed-origin-patterns='http*://app.example.com' $A.allow-credentials=true
actuator "A8 patterns=http://localhost:*, cred."        "http://localhost:3000 http://localhost.evil.com" \
    $A.allowed-origin-patterns='http://localhost:*' $A.allow-credentials=true
actuator "A9 patterns=http://localhost:[8080,8082]"     "http://localhost:8080 http://localhost:8082" \
    $A.allowed-origin-patterns='http://localhost:[8080,8082]' $A.allow-credentials=true
actuator "A9b patterns[0]=http://localhost:[8080,8082]" "http://localhost:8080 http://localhost:8082 http://localhost:9000" \
    "$A.allowed-origin-patterns[0]=http://localhost:[8080,8082]" $A.allow-credentials=true
actuator "A10 patterns=http://localhost:[*], cred."     "http://localhost:3000 http://localhost.evil.com" \
    $A.allowed-origin-patterns='http://localhost:[*]' $A.allow-credentials=true
actuator "A11 patterns=http://*.localhost, cred."       "http://a.localhost http://a.localhost.evil.com" \
    $A.allowed-origin-patterns='http://*.localhost' $A.allow-credentials=true
actuator "A13 patterns=http://localhost*, cred."        "http://localhost.evil.com" \
    $A.allowed-origin-patterns='http://localhost*' $A.allow-credentials=true
graphql  "G1 origins=http://partner.example, cred."     "http://partner.example"  $G.allowed-origins=http://partner.example $G.allow-credentials=true
graphql  "G2 patterns=http://*.example.com"             "http://a.example.com"    $G.allowed-origin-patterns='http://*.example.com'
exit 0
