#!/bin/bash
# What /actuator/health returns for each health setting, one configuration at a time: the reference
# SCG013 is checked against (VALIDATION.md, "SCG013 health details scenarios").
#
# Each scenario starts one of two apps (Spring Boot 4.1.1, Spring MVC, Actuator and an H2 datasource;
# health-details-secured adds Spring Security, with every request permitted and one HTTP Basic user
# "user" with role USER) with the properties as command-line arguments, waits until the previous app
# has released the port and the new one has started, and requests the health endpoint: anonymously,
# and as that user on the secured app. Each response is printed as "details" (components with their
# details, such as diskSpace's path), "components" (component names and status only), "status" (the
# overall status only), or the HTTP status when it isn't 200.
set -u
cd "$(dirname "$0")"
for module in health-details health-details-secured; do
    (cd "$module" && mvn -q package -DskipTests) || exit 1
done
LOG=/tmp/scg013-scenario.log
PORT=8098

shape() {
    local url=$1; shift
    local body status
    body=$(curl -s -w '\n%{http_code}' "$@" "localhost:$PORT$url")
    status=${body##*$'\n'}
    body=${body%$'\n'*}
    if [ "$status" != 200 ] && [ "$status" != 503 ]; then
        echo "$status"
    elif grep -q '"details"' <<< "$body"; then
        echo details
    elif grep -q '"components"' <<< "$body"; then
        echo components
    else
        echo status
    fi
}

scenario() {
    local module=$1 name=$2 path=$3; shift 3
    local waited=0
    while (echo > /dev/tcp/localhost/$PORT) 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        [ $waited -lt 60 ] || { echo "port $PORT still in use after 60s" >&2; exit 1; }
    done
    java -jar "$module/target/$module.jar" --server.port=$PORT "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 90); do
        grep -q "Started HealthApp in\|APPLICATION FAILED" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started HealthApp in\|APPLICATION FAILED" "$LOG" && kill -0 "$pid" 2>/dev/null; then
        printf '%-60s timed out before starting\n' "$name"
    elif ! grep -q "Started HealthApp in" "$LOG"; then
        printf '%-60s app did not start: %s\n' "$name" "$(grep -m1 -oE 'Reason: .*' "$LOG" | sed -E 's/^Reason: //')"
    elif [ "$module" = health-details-secured ]; then
        printf '%-60s %s: anonymous=%-10s user=%s\n' "$name" "$path" "$(shape "$path")" "$(shape "$path" -u user:pass)"
    else
        printf '%-60s %s: %s\n' "$name" "$path" "$(shape "$path")"
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

H=--management.endpoint.health
G=$H.group.custom
P=/actuator/health
echo "== Without Spring Security"
scenario health-details "D0 defaults"                                         $P
scenario health-details "D1 show-details=always"                              $P $H.show-details=always
scenario health-details "D2 show-details=when-authorized"                     $P $H.show-details=when-authorized
scenario health-details "D3 show-details=WHEN_AUTHORIZED"                     $P $H.show-details=WHEN_AUTHORIZED
scenario health-details "D4 show-details=whenAuthorized"                      $P $H.show-details=whenAuthorized
scenario health-details "D5 show-details=never"                               $P $H.show-details=never
scenario health-details "D6 show-details=true"                                $P $H.show-details=true
scenario health-details "D7 show-details=ALWAYS"                              $P $H.show-details=ALWAYS
scenario health-details "C1 show-components=always"                           $P $H.show-components=always
scenario health-details "C2 show-components=never, show-details=always"       $P $H.show-components=never $H.show-details=always
scenario health-details "G1 group custom (db), show-details=always"           $P/custom $G.include=db $G.show-details=always
scenario health-details "G2 same group, main endpoint"                        $P $G.include=db $G.show-details=always
scenario health-details "G3 group custom (db), show-components=always"        $P/custom $G.include=db $G.show-components=always
scenario health-details "G4 group, additional-path=server:/healthz, always"   /healthz $G.include=db $G.show-details=always $G.additional-path=server:/healthz
scenario health-details "G5 show-details=always, group custom (db) without its own" $P/custom $H.show-details=always $G.include=db
scenario health-details "G6 show-details=always, group show-components=never"  $P/custom $H.show-details=always $G.include=db $G.show-components=never
scenario health-details "G7 show-details=always, group show-details= (empty)"  $P/custom $H.show-details=always $G.include=db "$G.show-details="
scenario health-details "X1 show-details=always, health access=none"          $P $H.show-details=always $H.access=none
scenario health-details "X2 show-details=always, exposure.exclude=health"     $P $H.show-details=always --management.endpoints.web.exposure.exclude=health
echo "== With Spring Security (health open to all)"
scenario health-details-secured "S0 defaults"                                 $P
scenario health-details-secured "S1 show-details=always"                      $P $H.show-details=always
scenario health-details-secured "S2 show-details=when-authorized"             $P $H.show-details=when-authorized
scenario health-details-secured "S3 when-authorized, roles=ADMIN"             $P $H.show-details=when-authorized $H.roles=ADMIN
scenario health-details-secured "S4 show-components=when-authorized"          $P $H.show-components=when-authorized
scenario health-details-secured "S5 group custom (db), when-authorized"       $P/custom $G.include=db $G.show-details=when-authorized
exit 0
