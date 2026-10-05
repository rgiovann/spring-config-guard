#!/bin/bash
# Which values turn the H2 console on, and from where it answers, one configuration at a time: the
# reference SCG002 is checked against (VALIDATION.md, "SCG002 H2 console scenarios").
#
# Each scenario starts the h2-console app (Spring Boot 4.1.1, Spring MVC, the H2 console module) with
# the properties as command-line arguments, waits until the previous app has released the port and
# the new one has started, and requests the console page from loopback, from this machine's first
# non-loopback address, which H2 treats as a remote client, and through loopback-proxy.py, a reverse
# proxy on that address forwarding to localhost as a proxy or sidecar on the same machine does. It
# prints, for each, "console" (the login page), "blocked" (H2's "remote connections are disabled"
# page) or the HTTP status. Y1 and P1 load files written to target/ by this script: an unquoted YAML
# on, and a trailing space after true.
set -u
cd "$(dirname "$0")/h2-console"
mvn -q package -DskipTests || exit 1
JAR=target/h2-console.jar
LOG=target/scenario.log
PORT=8096
REMOTE=$(hostname -I | awk '{print $1}')
[ -n "$REMOTE" ] || { echo "no non-loopback address found (hostname -I, Linux)" >&2; exit 1; }
PROXY_PORT=8097
if (echo > /dev/tcp/"$REMOTE"/$PROXY_PORT) 2>/dev/null; then
    echo "port $PROXY_PORT already in use: stop the process holding it first" >&2
    exit 1
fi
NO_PROXY='*' python3 loopback-proxy.py "$REMOTE" $PROXY_PORT $PORT &
PROXY_PID=$!
trap 'kill $PROXY_PID 2>/dev/null' EXIT
for _ in $(seq 1 10); do (echo > /dev/tcp/"$REMOTE"/$PROXY_PORT) 2>/dev/null && break; sleep 1; done
kill -0 $PROXY_PID 2>/dev/null || { echo "the proxy did not start" >&2; exit 1; }

reach() {
    local host=$1 port=$2 path=$3 status
    status=$(curl -s --noproxy '*' -o target/page.html -w '%{http_code}' "http://$host:$port$path")
    if [ "$status" != 200 ]; then
        echo "$status"
    elif grep -q "remote connections ('webAllowOthers') are disabled" target/page.html; then
        echo blocked
    elif grep -q "<title>H2 Console</title>" target/page.html; then
        echo console
    else
        echo "200-other"
    fi
}

scenario() {
    local name=$1 path=$2; shift 2
    local waited=0
    while (echo > /dev/tcp/localhost/$PORT) 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        [ $waited -lt 60 ] || { echo "port $PORT still in use after 60s" >&2; exit 1; }
    done
    java -jar "$JAR" --server.port=$PORT "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 90); do
        grep -q "Started H2ConsoleApp in\|APPLICATION FAILED" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started H2ConsoleApp in\|APPLICATION FAILED" "$LOG" && kill -0 "$pid" 2>/dev/null; then
        printf '%-52s timed out before starting\n' "$name"
    elif ! grep -q "Started H2ConsoleApp in" "$LOG"; then
        printf '%-52s app did not start: %s\n' "$name" \
            "$(grep -m1 -oE 'Reason: .*|Could not resolve placeholder [^ ]+' "$LOG" | sed -E 's/^Reason: //')"
    else
        printf '%-52s local=%-8s remote=%-8s proxied=%s\n' "$name" "$(reach localhost $PORT "$path")" \
            "$(reach "$REMOTE" $PORT "$path")" "$(reach "$REMOTE" $PROXY_PORT "$path")"
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

E=--spring.h2.console.enabled
S=--spring.h2.console.settings
C=/h2-console/
scenario "H0 defaults"                                   $C
scenario "H1 enabled=true"                               $C $E=true
scenario "H2 enabled=TRUE"                               $C $E=TRUE
scenario "H3 enabled=yes"                                $C $E=yes
scenario "H4 enabled=on"                                 $C $E=on
scenario "H5 enabled=1"                                  $C $E=1
scenario "H6 enabled=false"                              $C $E=false
scenario "H7 enabled=off"                                $C $E=off
scenario "H8 enabled= (empty)"                           $C $E=
scenario "H9 enabled=banana"                             $C $E=banana
scenario "H10 enabled=\${H2_ENABLED} (unset, no default)" $C "$E=\${H2_ENABLED}"
scenario "H11 enabled=\${H2_ENABLED:true}"               $C "$E=\${H2_ENABLED:true}"
printf 'spring.h2.console.enabled: on\n' > target/unquoted-on.yml
scenario "Y1 YAML enabled: on (unquoted)"                $C --spring.config.additional-location=file:target/unquoted-on.yml
printf 'spring.h2.console.enabled=true \n' > target/trailing-space.properties
scenario "P1 properties file: 'enabled=true ' (trailing space)" $C --spring.config.additional-location=file:target/trailing-space.properties
scenario "A1 enabled=true, web-allow-others=true"        $C $E=true $S.web-allow-others=true
scenario "A2 enabled=true, web-allow-others=yes"         $C $E=true $S.web-allow-others=yes
scenario "A3 web-allow-others=true alone"                $C $S.web-allow-others=true
scenario "A4 enabled=true, allow-others, web-admin-password" $C $E=true $S.web-allow-others=true $S.web-admin-password=secret
scenario "A5 enabled=true, web-allow-others=\${UNSET:true}" $C $E=true "$S.web-allow-others=\${UNSET:true}"
scenario "T1 enabled=true, path=/db"                     /db/ $E=true --spring.h2.console.path=/db
exit 0
