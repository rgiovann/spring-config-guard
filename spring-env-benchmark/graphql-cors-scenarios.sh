#!/bin/bash
# How Spring for GraphQL answers a credentialed cross-origin request, one CORS configuration at a
# time: the reference SCG003 is checked against (VALIDATION.md, "SCG003 CORS scenarios").
#
# Each scenario starts the graphql-cors app (a separate project, so this benchmark app doesn't get
# GraphQL) with the properties as command-line arguments, waits until the previous app has released
# the port and the new one has started, sends a preflight and a POST to /graphql with a foreign
# Origin, and prints the CORS response headers.
set -u
cd "$(dirname "$0")/graphql-cors"
mvn -q package -DskipTests || exit 1
JAR=target/graphql-cors.jar
LOG=target/scenario.log
PORT=8091
C=--spring.graphql.cors

cors_headers() {
    tr -d '\r' | grep -iE "^HTTP|access-control-allow-(origin|credentials)" | tr '\n' ' '
}

scenario() {
    local name=$1 origin=$2; shift 2
    while (echo > /dev/tcp/localhost/$PORT) 2>/dev/null; do sleep 1; done
    java -jar "$JAR" --server.port=$PORT "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started GraphQlApp in\|APPLICATION FAILED" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started GraphQlApp in" "$LOG"; then
        printf '%-52s app did not start\n' "$name"
    else
        local preflight post
        preflight=$(curl -s -o /dev/null -D - -X OPTIONS localhost:$PORT/graphql -H "Origin: $origin" \
            -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: content-type" | cors_headers)
        post=$(curl -s -o /dev/null -D - -X POST localhost:$PORT/graphql -H "Origin: $origin" \
            -H "Content-Type: application/json" -d '{"query":"{hello}"}' | cors_headers)
        printf '%-52s\n    preflight: %s\n    POST:      %s\n' "$name" "$preflight" "$post"
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

scenario "G1 allowed-origin-patterns=*, credentials"              https://evil.example  $C.allowed-origin-patterns='*' $C.allow-credentials=true
scenario "G2 allowed-origins=*, credentials"                      https://evil.example  $C.allowed-origins='*' $C.allow-credentials=true
scenario "G3 allowed-origins=https://*.example.com, credentials"  https://a.example.com $C.allowed-origins='https://*.example.com' $C.allow-credentials=true
scenario "G4 allowed-origin-patterns=https://*.example.com, cred." https://a.example.com $C.allowed-origin-patterns='https://*.example.com' $C.allow-credentials=true
exit 0
