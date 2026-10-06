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
# Then the grammar's edge cases (E1-E11), the order of a Config Server's files (P15) and profile
# groups (G1-G7), on Spring's side only.
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
        echo "failed: $(grep -m1 -oE '(Malformed|Invalid) profile expression \[[^]]*\](: must contain text)?|Reason: .*' "$LOG")"
    else
        curl -s --noproxy '*' "localhost:$PORT/actuator/env/spring.h2.console.enabled" \
            | python3 -c 'import json,sys
try: print("on" if str(json.load(sys.stdin)["property"]["value"]).lower() == "true" else "off")
except Exception: print("off")'
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

# Prints "<profile label>\t<on|off>" for every configuration SCG builds, from its SCG002 findings.
# SCG runs on a copy of the fixture whose application.properties also exposes every Actuator
# endpoint: a key no fixture sets, which leaves the console alone and makes every configuration
# report SCG001, so a configuration with the console off still shows up.
scg_configurations() {
    local copy=target/profile-expression-scg/$(basename "$1")
    rm -rf "$copy"; mkdir -p "$(dirname "$copy")"; cp -r "$1" "$copy"
    printf '\nmanagement.endpoints.web.exposure.include=*\n' >> "$copy/application.properties"
    local json
    json=$(java -jar "$SCG_JAR" "$copy" --json --fail-on=NONE 2>/dev/null) || { echo "input error"; return; }
    python3 -c 'import json,sys
labels = {"__spring_config_guard_base__"}
on = set()
for f in json.load(sys.stdin):
    labels.add(f["profileLabel"])
    if f["ruleId"] == "SCG002": on.add(f["profileLabel"])
for label in sorted(labels): print(label + "\t" + ("on" if label in on else "off"))' <<< "$json"
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
        if [ "$scg" = "input error" ]; then
            scg_value="input error (exit code 2)"
        else
            scg_value=$(awk -F'\t' -v l="$label" 'l != "" && $1 == l {print $2}' <<< "$scg")
        fi
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

# The grammar's edge cases (E1-E10): one document with the value, written to target/, the console on
# when it applies. Only Spring's side: SCG's parser for these is ProfileExpression, pinned by
# ProfileExpressionTest.
grammar() {
    local row=$1 value=$2; shift 2
    local dir=target/profile-expression-grammar
    mkdir -p "$dir"
    printf 'spring.h2.console.enabled: false\n---\nspring.config.activate.on-profile: "%s"\nspring.h2.console.enabled: true\n' \
        "$value" > "$dir/application.yml"
    local result="" active value_for
    for active in "$@"; do
        value_for=$(spring_value "$dir" "$active")
        result="$result ${active:-none}=$value_for"
    done
    printf '%-4s %-16s%s\n' "$row" "'$value'" "$result"
}

SETS=("" a b c a,b b,c)
grammar E1 '!default'      "${SETS[@]}"
grammar E2 'a b'           "${SETS[@]}" "a b"
grammar E3 'a)'            "${SETS[@]}"
grammar E3 '(a'            "${SETS[@]}"
grammar E3 '&a'            "${SETS[@]}"
grammar E3 'a&'            "${SETS[@]}"
grammar E4 '!!a'           "${SETS[@]}"
grammar E4 '(a)'           "${SETS[@]}"
grammar E5 'a & (b | c)'   "${SETS[@]}"
grammar E6 '!(a | b)'      "${SETS[@]}"
grammar E6 '!a & !b'       "${SETS[@]}"
grammar E7 '!'             ""
grammar E7 'a | !b & c'    ""
grammar E8 'a,,b'          ""
grammar E8 ',a'            ""
grammar E8 'a,'            ""
grammar E8 ' '             ""
grammar E9 'Prod'          "" prod Prod

# E10, E11 and E8's list form: the value as YAML writes it, unquoted (a null, an empty list), or in a
# .properties document.
grammar_raw() {
    local row=$1 label=$2 file=$3 content=$4; shift 4
    local dir=target/profile-expression-grammar
    rm -rf "$dir"; mkdir -p "$dir"
    printf '%s' "$content" > "$dir/$file"
    local result="" active
    for active in "$@"; do
        result="$result ${active:-none}=$(spring_value "$dir" "$active")"
    done
    printf '%-4s %-16s%s\n' "$row" "$label" "$result"
}
yaml_value() {
    printf 'spring.h2.console.enabled: false\n---\nspring.config.activate.on-profile:%s\nspring.h2.console.enabled: true\n' "$1"
}
grammar_raw E8  '[a, ""]'      application.yml "$(yaml_value ' [a, ""]')" ""
grammar_raw E10 '(null)'       application.yml "$(yaml_value '')" "" a
grammar_raw E10 '~'            application.yml "$(yaml_value ' ~')" "" a
grammar_raw E10 '""'           application.yml "$(yaml_value ' ""')" "" a
grammar_raw E10 '[]'           application.yml "$(yaml_value ' []')" "" a
grammar_raw E10 '= (.props)'   application.properties \
    "$(printf 'spring.h2.console.enabled=false\n#---\nspring.config.activate.on-profile=\nspring.h2.console.enabled=true\n')" "" a

# E11: on-profile written as a map, which Spring Boot doesn't read as a condition, or with a
# bracket that isn't a list index (columns: none, prod, x).
grammar_raw E11 '{x: prod}'    application.yml "$(printf 'spring.h2.console.enabled: false\n---\nspring.config.activate.on-profile:\n  x: prod\nspring.h2.console.enabled: true\n')" "" prod x
grammar_raw E11 '.x=prod'      application.properties \
    "$(printf 'spring.h2.console.enabled=false\n#---\nspring.config.activate.on-profile.x=prod\nspring.h2.console.enabled=true\n')" "" prod x
grammar_raw E11 '[prod]=x'     application.properties \
    "$(printf 'spring.h2.console.enabled=false\n#---\nspring.config.activate.on-profile[prod]=x\nspring.h2.console.enabled=true\n')" "" prod x

# P15: a Config Server repository's order, measured as the Spring Cloud Config reference says the
# server resolves it: a Spring Boot application with spring.config.name=application,svc. Each of
# k1-k4 is set in several of application.yml (base, then a dev block), svc.yml (base, then a dev
# block) and application-dev.yml; the value shows which source wins, with dev active and without.
p15_value() {
    local dir=$1 active=$2 waited=0
    while (echo > /dev/tcp/localhost/$PORT) 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        [ $waited -lt 60 ] || { echo "port $PORT still in use after 60s" >&2; exit 1; }
    done
    local args=(--spring.config.location="file:$PWD/$dir/" --spring.config.name=application,svc --server.port=$PORT
                --management.endpoints.web.exposure.include=env --management.endpoint.env.show-values=ALWAYS)
    [ -n "$active" ] && args+=(--spring.profiles.active="$active")
    java -jar "$JAR" "${args[@]}" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 90); do
        grep -q "Started \|APPLICATION FAILED\|Application run failed" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    local key result=""
    for key in k1 k2 k3 k4; do
        result="$result $key=$(curl -s --noproxy '*' "localhost:$PORT/actuator/env/$key" | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["property"]["value"])
except Exception: print("-")')"
    done
    echo "$result"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}
P15=target/profile-expression-config-server
rm -rf "$P15"; mkdir -p "$P15"
printf 'k1: app-base\nk2: app-base\nk3: app-base\n---\nspring.config.activate.on-profile: dev\nk1: app-block\nk2: app-block\n' \
    > "$P15/application.yml"
printf 'k1: svc-base\nk3: svc-base\nk4: svc-base\n---\nspring.config.activate.on-profile: dev\nk4: svc-block\n' \
    > "$P15/svc.yml"
printf 'k3: app-dev-file\nk4: app-dev-file\n' > "$P15/application-dev.yml"
printf 'P15  active=none %s\n' "$(p15_value "$P15" "")"
printf 'P15  active=dev  %s\n' "$(p15_value "$P15" dev)"

# G1-G7: profile groups (spring.profiles.group). Each case prints the active profiles /actuator/env
# reports and, for k1-k4, the value of the highest-precedence source that sets it.
group_value() {
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
        echo "failed: $(grep -m1 -oE 'Reason: .*' "$LOG")"
    else
        curl -s --noproxy '*' "localhost:$PORT/actuator/env" | python3 -c 'import json,sys
d = json.load(sys.stdin)
out = ["active=" + ",".join(d["activeProfiles"])]
for key in ["k1", "k2", "k3", "k4"]:
    value = "-"
    for source in d["propertySources"]:
        if key in source.get("properties", {}):
            value = source["properties"][key]["value"]
            break
    out.append(key + "=" + str(value))
print(" ".join(out))'
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}
G=target/profile-groups
group_fixture() { rm -rf "$G"; mkdir -p "$G"; }
group_row() { printf '%-3s active=%-5s %s\n' "$1" "${2:-none}" "$(group_value "$G" "$2")"; }

# G1: the order of a group's profile files (activation order) and of on-profile blocks (file order).
group_fixture
printf 'spring.profiles.group.dev: [a, b]\nk1: base\nk2: base\nk3: base\nk4: base\n---\nspring.config.activate.on-profile: b\nk4: b-block\n---\nspring.config.activate.on-profile: a\nk4: a-block\n' \
    > "$G/application.yml"
printf 'k1: dev\nk2: dev\nk3: dev\n' > "$G/application-dev.yml"
printf 'k1: a\nk2: a\n' > "$G/application-a.yml"
printf 'k1: b\n' > "$G/application-b.yml"
group_row G1 dev
group_row G1 ""
group_row G1 a
# G2: nested groups.
group_fixture
printf 'spring.profiles.group.dev: [a]\nspring.profiles.group.a: [b]\nk1: base\n' > "$G/application.yml"
printf 'k1: b\n' > "$G/application-b.yml"
group_row G2 dev
# G3: a group declared in a profile-specific file.
group_fixture
printf 'k1: base\n' > "$G/application.yml"
printf 'spring.profiles.group.dev: [a]\nk1: dev\n' > "$G/application-dev.yml"
printf 'k2: a\n' > "$G/application-a.yml"
group_row G3 dev
# G4: a group declared in an on-profile document.
group_fixture
printf 'k1: base\n---\nspring.config.activate.on-profile: dev\nspring.profiles.group.dev: [a]\nk1: dev\n' > "$G/application.yml"
printf 'k2: a\n' > "$G/application-a.yml"
group_row G4 dev
# G5: spring.profiles.include in the base (not evaluated by SCG).
group_fixture
printf 'spring.profiles.include: [x]\nk1: base\n' > "$G/application.yml"
printf 'k1: x\n' > "$G/application-x.yml"
printf 'k2: dev\n' > "$G/application-dev.yml"
printf 'k3: default\n' > "$G/application-default.yml"
group_row G5 ""
group_row G5 dev
# G6: a group written comma-separated in .properties.
group_fixture
printf 'spring.profiles.group.dev=a,b\nk1=base\n' > "$G/application.properties"
printf 'k1: a\n' > "$G/application-a.yml"
printf 'k2: b\n' > "$G/application-b.yml"
group_row G6 dev
# G7: a group for the default profile, with no profile active.
group_fixture
printf 'spring.profiles.group.default: [a]\nk1: base\n' > "$G/application.yml"
printf 'k1: a\n' > "$G/application-a.yml"
group_row G7 ""
