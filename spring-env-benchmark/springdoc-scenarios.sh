#!/bin/bash
# What each SpringDoc flag turns off, one configuration at a time: the reference SCG008 is checked
# against (VALIDATION.md, "SCG008 SpringDoc scenarios").
#
# Each scenario starts the springdoc app (a separate project, so this benchmark app doesn't get
# SpringDoc) with the flags as command-line arguments, waits until the previous app has released
# the port and the new one has started, and prints the status of /v3/api-docs (and whether it lists
# the app's endpoint), /swagger-ui/index.html, /swagger-ui.html and /docs.
set -u
cd "$(dirname "$0")/springdoc"
mvn -q package -DskipTests || exit 1
JAR=target/springdoc.jar
LOG=target/scenario.log
PORT=8092
D=--springdoc

status() { curl -s -o /dev/null -w '%{http_code}' "localhost:$PORT$1"; }

scenario() {
    local name=$1; shift
    while (echo > /dev/tcp/localhost/$PORT) 2>/dev/null; do sleep 1; done
    java -jar "$JAR" --server.port=$PORT "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started SpringDocApp in\|APPLICATION FAILED" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started SpringDocApp in" "$LOG"; then
        printf '%-46s app did not start\n' "$name"
    else
        local lists
        lists=$(curl -s localhost:$PORT/v3/api-docs | grep -q '/api/orders/{id}' && echo ' (lists the API)')
        printf '%-46s api-docs=%s%s  ui/index.html=%s  swagger-ui.html=%s  /docs=%s\n' "$name" \
            "$(status /v3/api-docs)" "$lists" "$(status /swagger-ui/index.html)" "$(status /swagger-ui.html)" "$(status /docs)"
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

scenario "S1 defaults"
scenario "S2 api-docs.enabled=false"                    $D.api-docs.enabled=false
scenario "S9 api-docs.enabled=FALSE"                    $D.api-docs.enabled=FALSE
scenario "S11 api-docs.enabled=false, swagger-ui=true"  $D.api-docs.enabled=false $D.swagger-ui.enabled=true
scenario "S3 swagger-ui.enabled=false"                  $D.swagger-ui.enabled=false
scenario "S4 both false"                                $D.api-docs.enabled=false $D.swagger-ui.enabled=false
scenario "S5 api-docs.enabled=off"                      $D.api-docs.enabled=off
scenario "S6 api-docs.enabled=no"                       $D.api-docs.enabled=no
scenario "S7 api-docs.enabled=0"                        $D.api-docs.enabled=0
scenario "S8 swagger-ui.path=/docs"                     $D.swagger-ui.path=/docs
exit 0
