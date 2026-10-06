#!/bin/bash
# Which documents Spring Boot applies for a spring.config.activate.on-profile value, by active
# profiles, next to what SCG evaluates for the same files (VALIDATION.md, "Profile expressions in
# on-profile").
#
# Each fixture in profile-expressions/ sets spring.h2.console.enabled in a base document and in
# documents conditioned by on-profile (or in another file). For each set of active profiles, the
# scenario starts this benchmark app with that directory as its only config location, reads the
# resolved value from /actuator/env and stops the app ("on", "off", or why it didn't start). The
# SCG column runs the SCG jar on the same directory once and says whether the configuration SCG
# builds for those active profiles has the console on, which is when it reports SCG002: "on",
# "off", or "none" when SCG builds no configuration for that set (several profiles active
# together are never modeled). After each fixture, every configuration SCG builds is listed
# by its profile label, with the console's state in it.
# Build both jars first:  mvn -q package -DskipTests   (in this directory and in the repository root)
set -u
cd "$(dirname "$0")"
JAR=target/spring-env-benchmark-0.0.1-SNAPSHOT.jar
SCG_JAR=../target/spring-config-guard.jar
LOG=/tmp/profile-expression-scenario.log
PORT=8098
[ -f "$JAR" ] || { echo "build this app first: mvn -q package -DskipTests" >&2; exit 1; }
[ -f "$SCG_JAR" ] || { echo "build SCG first: mvn -q package -DskipTests (repository root)" >&2; exit 1; }

spring_value() {
    local dir=$1 active=$2 waited=0
    while (echo > /dev/tcp/localhost/$PORT) 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        [ $waited -lt 60 ] || { echo "port $PORT still in use after 60s" >&2; exit 1; }
    done
    local args=(--spring.config.location="file:$PWD/$dir/" --server.port=$PORT
                --management.endpoints.web.exposure.include=env --management.endpoint.env.show-values=ALWAYS)
    [ -n "$active" ] && args+=(--spring.profiles.active="$active")
    java -jar "$JAR" "${args[@]}" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 90); do
        grep -q "Started \|APPLICATION FAILED\|Application run failed" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started " "$LOG"; then
        echo "failed: $(grep -m1 -oE 'Malformed profile expression \[[^]]*\]|Reason: .*' "$LOG")"
    else
        curl -s --noproxy '*' "localhost:$PORT/actuator/env/spring.h2.console.enabled" \
            | python3 -c 'import json,sys
try: print("on" if str(json.load(sys.stdin)["property"]["value"]).lower() == "true" else "off")
except Exception: print("off")'
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

# Prints "<profile label>\t<on|off>" for every configuration SCG builds, from its SCG002 findings.
scg_configurations() {
    java -jar "$SCG_JAR" "$1" --json --fail-on=NONE 2>/dev/null | python3 -c 'import json,sys
labels = {"__spring_config_guard_base__"}
on = set()
for f in json.load(sys.stdin):
    labels.add(f["profileLabel"])
    if f["ruleId"] == "SCG002": on.add(f["profileLabel"])
for label in sorted(labels): print(label + "\t" + ("on" if label in on else "off"))'
}

fixture() {
    local dir=$1; shift
    local scg; scg=$(scg_configurations "profile-expressions/$dir")
    for active in "$@"; do
        local label scg_value
        if [ -z "$active" ]; then
            label=__spring_config_guard_base__
        elif [[ "$active" == *,* ]]; then
            label=
        else
            label=$active
        fi
        scg_value=$(awk -F'\t' -v l="$label" 'l != "" && $1 == l {print $2}' <<< "$scg")
        # SCG has no configuration of its own for a profile it doesn't know: none from a file or a
        # literal on-profile label. Such a profile would get the base's configuration in Spring.
        printf '%-28s active=%-6s Spring=%-44s SCG=%s\n' "$dir" "${active:-none}" \
            "$(spring_value "profile-expressions/$dir" "$active")" "${scg_value:-none}"
    done
    printf '%-28s SCG labels: %s\n' "$dir" "$(sed 's/__spring_config_guard_base__/(base)/; s/^\(.*\)\t\(.*\)$/[\1]=\2/' <<< "$scg" | paste -sd' ' -)"
}

fixture p1-not                     "" a b a,b c
fixture p2-comma                   "" a b a,b c
fixture p3-yaml-list               "" a b a,b c
fixture p4-and                     "" a b a,b c
fixture p5-or                      "" a b a,b c
fixture p6-parens                  "" a b a,b c
fixture p7-not-comma               "" a b a,b c
fixture p14-spaces                 "" a b
fixture p8-default-block           "" a
fixture p9-default-file            "" a
fixture p10-document-order         "" a
fixture p11-file-precedence        "" a
fixture p12-profile-file-condition "" x x,b
fixture p13-malformed              "" c
