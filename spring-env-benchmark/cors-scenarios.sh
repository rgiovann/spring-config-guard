#!/bin/bash
# How Spring Boot answers a credentialed cross-origin request to Actuator, one CORS configuration
# at a time: the reference SCG003 is checked against (VALIDATION.md, "SCG003 CORS scenarios").
#
# Each scenario starts this benchmark app with extra properties as command-line arguments, waits
# until the previous app has released the port and the new one has started, sends a preflight and
# a GET to /actuator/env with a foreign Origin, and prints the CORS response headers. N5 loads a YAML
# file with an unquoted null, written to target/ by this script.
# Build the jar first:  mvn -q package -DskipTests   (from this directory)
set -u
cd "$(dirname "$0")"
JAR=target/spring-env-benchmark-0.0.1-SNAPSHOT.jar
C=--management.endpoints.web.cors

scenario() {
    local name=$1 origin=$2; shift 2
    while curl -s -o /dev/null localhost:8081/actuator; do sleep 1; done
    java -jar "$JAR" --spring.profiles.active=prod "$@" > /tmp/scg003-scenario.log 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started \|APPLICATION FAILED" /tmp/scg003-scenario.log && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started " /tmp/scg003-scenario.log; then
        printf '%-56s app did not start: %s\n' "$name" "$(grep -oE 'When allowCredentials[^.]*' /tmp/scg003-scenario.log | head -1)"
        kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        return
    fi
    local headers
    headers=$(curl -s -o /dev/null -D - localhost:8081/actuator/env -H "Origin: $origin" \
        | tr -d '\r' | grep -iE "^HTTP|access-control-allow-(origin|credentials)" | tr '\n' ' ')
    printf '%-56s %s\n' "$name" "$headers"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

scenario "C1 allowed-origins=*, credentials"                         https://evil.example  $C.allowed-origins='*' $C.allow-credentials=true
scenario "C2 allowed-origin-patterns=*, credentials"                 https://evil.example  $C.allowed-origin-patterns='*' $C.allow-credentials=true
scenario "C3 allowed-origins=https://*.example.com, credentials"     https://a.example.com $C.allowed-origins='https://*.example.com' $C.allow-credentials=true
scenario "C4 allowed-origin-patterns=https://*.example.com, cred."   https://a.example.com $C.allowed-origin-patterns='https://*.example.com' $C.allow-credentials=true
scenario "C5 allowed-origins=*, no credentials"                      https://evil.example  $C.allowed-origins='*'
scenario "C6 allowed-origin-patterns=https://*, credentials"         https://evil.example  $C.allowed-origin-patterns='https://*' $C.allow-credentials=true
scenario "N1 allowed-origins=null, credentials"                     null                  $C.allowed-origins=null $C.allow-credentials=true
scenario "N2 allowed-origins=NULL, credentials"                     null                  $C.allowed-origins=NULL $C.allow-credentials=true
scenario "N3 allowed-origin-patterns=null, credentials"             null                  $C.allowed-origin-patterns=null $C.allow-credentials=true
scenario "N4 allowed-origins=null, no credentials"                  null                  $C.allowed-origins=null
printf 'management.endpoints.web.cors:\n  allowed-origins: null\n  allow-credentials: true\n' > target/unquoted-null.yml
scenario "N5 YAML allowed-origins: null (unquoted), credentials"    null                  --spring.config.additional-location=file:target/unquoted-null.yml
exit 0
