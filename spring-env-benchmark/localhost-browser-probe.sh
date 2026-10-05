#!/bin/bash
# Whether a browser resolves localhost names to the local machine by itself, or asks DNS, where an
# attacker on the network could answer with their own address: the reference for SCG004 leaving
# http://localhost and http://*.localhost origins unreported (VALIDATION.md, "SCG004 insecure origin
# scenarios"). Serves a page on 127.0.0.1:9000 and, for each host, prints what the system resolver
# answers (getent) and whether the browser loaded that page from http://<host>:9000.
#
# Needs a Chromium binary in CHROME (e.g. /opt/pw-browsers/chromium-1194/chrome-linux/chrome).
set -u
: "${CHROME:?set CHROME to a Chromium binary}"
WORK="$(dirname "$0")/target/localhost-probe"
mkdir -p "$WORK"
echo '<title>SERVED-FROM-LOOPBACK</title>' > "$WORK/index.html"

if (echo > /dev/tcp/127.0.0.1/9000) 2>/dev/null; then
    echo "port 9000 already in use: stop the process holding it first" >&2
    exit 1
fi
(cd "$WORK" && exec python3 -m http.server 9000 --bind 127.0.0.1 > /dev/null 2>&1) &
WEB=$!
trap 'kill $WEB 2>/dev/null' EXIT
for _ in $(seq 1 10); do (echo > /dev/tcp/127.0.0.1/9000) 2>/dev/null && break; sleep 1; done

"$CHROME" --version 2>/dev/null
for host in localhost a.localhost deep.a.localhost example.test; do
    resolver=$(getent hosts "$host" | awk '{print $1}' | sort | tr '\n' ' ')
    loaded=$(timeout 30 "$CHROME" --headless --no-sandbox --disable-gpu --virtual-time-budget=3000 \
        --dump-dom "http://$host:9000/" 2>/dev/null | grep -c 'SERVED-FROM-LOOPBACK')
    printf '%-18s system resolver: %-22s browser: %s\n' "$host" "${resolver:-no answer}" \
        "$([ "$loaded" -gt 0 ] && echo 'loaded from 127.0.0.1' || echo 'not loaded')"
done
exit 0
