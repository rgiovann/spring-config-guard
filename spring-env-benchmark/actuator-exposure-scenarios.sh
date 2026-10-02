#!/bin/bash
# Which Actuator endpoints Spring Boot actually exposes over HTTP, one configuration at a time:
# the reference SCG001 is checked against (VALIDATION.md, "SCG001 exposure scenarios").
#
# Each scenario starts this benchmark app with extra properties as command-line arguments (so the
# fixtures in src/main/resources stay untouched), waits until the previous app has released the port
# and the new one has started (or failed), lists the endpoints /actuator links to, and stops the app.
# Build the jar first:  mvn -q package -DskipTests   (from this directory)
set -u
cd "$(dirname "$0")"
JAR=target/spring-env-benchmark-0.0.1-SNAPSHOT.jar
INCLUDE=--management.endpoints.web.exposure.include='*'
LOG=/tmp/scg001-scenario.log

scenario() {
    local name=$1; shift
    # A previous app still holding the port would answer for this scenario.
    while (echo > /dev/tcp/localhost/8081) 2>/dev/null; do sleep 1; done
    java -jar "$JAR" --spring.profiles.active=prod "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started \|APPLICATION FAILED\|Application run failed" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started " "$LOG"; then
        printf '%-58s app did not start: %s\n' "$name" "$(grep -m1 -A2 'Description:' "$LOG" | tail -1)"
        kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        return
    fi
    local links
    links=$(curl -s localhost:8081/actuator | python3 -c "
import json, sys
try:
    links = json.load(sys.stdin).get('_links', {})
    print(', '.join(sorted(k for k in links if k != 'self' and '-' not in k and '{' not in k)) or '(none)')
except Exception:
    print('(app did not start)')")
    printf '%-58s %s\n' "$name" "$links"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

scenario "S1  include=*"                                  $INCLUDE
scenario "S2  + exposure.exclude=env,heapdump"            $INCLUDE --management.endpoints.web.exposure.exclude=env,heapdump
scenario "S3  + access.default=none"                      $INCLUDE --management.endpoints.access.default=none
scenario "S4  + endpoint.env.enabled=false (legacy)"      $INCLUDE --management.endpoint.env.enabled=false
scenario "S5  + enabled-by-default=false (legacy)"        $INCLUDE --management.endpoints.enabled-by-default=false
scenario "S6  + management.server.port=-1"                $INCLUDE --management.server.port=-1
scenario "S7  + endpoint.heapdump.access=unrestricted"    $INCLUDE --management.endpoint.heapdump.access=unrestricted
scenario "S8  + access.default=none, env.access=unrestricted" $INCLUDE --management.endpoints.access.default=none --management.endpoint.env.access=unrestricted
scenario "S9  + enabled-by-default=false, env.enabled=true"   $INCLUDE --management.endpoints.enabled-by-default=false --management.endpoint.env.enabled=true
scenario "S10 + access.default=unrestricted"              $INCLUDE --management.endpoints.access.default=unrestricted
scenario "S11 + max-permitted=read-only, heapdump.access=unrestricted" $INCLUDE --management.endpoints.access.max-permitted=read-only --management.endpoint.heapdump.access=unrestricted
scenario "S12 + exposure.exclude=*"                       $INCLUDE --management.endpoints.web.exposure.exclude='*'
scenario "S13 + enabled-by-default=true (legacy)"         $INCLUDE --management.endpoints.enabled-by-default=true
scenario "S14 + max-permitted=none"                       $INCLUDE --management.endpoints.access.max-permitted=none
scenario "S15 + access.default=read-only"                 $INCLUDE --management.endpoints.access.default=read-only
scenario "S16 + env.access=unrestricted, env.enabled=false"   $INCLUDE --management.endpoint.env.access=unrestricted --management.endpoint.env.enabled=false
scenario "S17 + max-permitted=read-only, shutdown.access=unrestricted" $INCLUDE --management.endpoints.access.max-permitted=read-only --management.endpoint.shutdown.access=unrestricted
scenario "S18 + shutdown.access=unrestricted"             $INCLUDE --management.endpoint.shutdown.access=unrestricted
