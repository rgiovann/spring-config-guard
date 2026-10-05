#!/bin/bash
# What allowed-methods and exposed-headers change for a cross-origin script, one CORS configuration
# at a time: the reference SCG005 is checked against (VALIDATION.md, "SCG005 methods and headers
# scenarios").
#
# Part 1 starts this benchmark app per scenario (port 8081, env and loggers exposed), sends a
# preflight for POST /actuator/loggers/ROOT (or for the method in METHOD) and a GET /actuator/env
# with a foreign Origin, and prints the CORS response headers. Part 2 loads a page on port 9000 in
# Chromium that POSTs JSON to /actuator/loggers/ROOT with credentials, then prints the logger's
# level. Part 3 checks, against a minimal server on port 9100, which response headers a script can
# read: '*' in Access-Control-Expose-Headers with and without credentials, and an explicitly
# exposed Set-Cookie.
#
# Needs Node.js and Playwright with a Chromium (NODE_PATH pointing at the node_modules that has it).
set -u
cd "$(dirname "$0")"
mvn -q package -DskipTests || exit 1
WORK=target/methods-headers-scenarios
LOG=$WORK/app.log
mkdir -p "$WORK"
A=--management.endpoints.web.cors

cors_headers() {
    tr -d '\r' | grep -iE "^HTTP|access-control-(allow|expose)" | tr '\n' ' '
}

start() {
    while (echo > /dev/tcp/localhost/8081) 2>/dev/null; do sleep 1; done
    java -jar target/spring-env-benchmark-0.0.1-SNAPSHOT.jar --spring.profiles.active=prod \
        --management.endpoints.web.exposure.include=env,loggers "$@" > "$LOG" 2>&1 &
    PID=$!
    for _ in $(seq 1 60); do
        grep -q "Started \|APPLICATION FAILED" "$LOG" && break
        kill -0 "$PID" 2>/dev/null || break
        sleep 1
    done
}

stop() {
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
}

# scenario <name> <Access-Control-Request-Headers or empty> <args...>
scenario() {
    local name=$1 request_headers=$2 method=${METHOD:-POST}; shift 2
    start "$@"
    printf '%-48s preflight %s: %s\n' "$name" "$method" "$(curl -s -o /dev/null -D - -X OPTIONS localhost:8081/actuator/loggers/ROOT \
        -H 'Origin: https://trusted.example' -H "Access-Control-Request-Method: $method" \
        ${request_headers:+-H "Access-Control-Request-Headers: $request_headers"} | cors_headers)"
    printf '%-48s GET env:        %s\n' "$name" "$(curl -s -o /dev/null -D - localhost:8081/actuator/env \
        -H 'Origin: https://trusted.example' | cors_headers)"
    stop
}

echo "== Part 1: Spring Boot's answers"
scenario "M1 methods=*, no origin key"                  ""           $A.allowed-methods='*'
scenario "M2 origins, methods=*, credentials"           ""           $A.allowed-origins=https://trusted.example $A.allowed-methods='*' $A.allow-credentials=true
scenario "M3 origins, methods unset"                    ""           $A.allowed-origins=https://trusted.example
scenario "M5 origins, methods=*, JSON preflight"        content-type $A.allowed-origins=https://trusted.example $A.allowed-methods='*' $A.allow-credentials=true
scenario "M6 origins, methods=*, headers=*, JSON"       content-type $A.allowed-origins=https://trusted.example $A.allowed-methods='*' $A.allowed-headers='*' $A.allow-credentials=true
scenario "H1 origins, exposed-headers=*, credentials"   ""           $A.allowed-origins=https://trusted.example $A.exposed-headers='*' $A.allow-credentials=true
scenario "H3 exposed-headers=*, no origin key"          ""           $A.exposed-headers='*'
scenario "E1 origins=\${SCG_ORIGINS:}, methods=*"        ""           $A.allowed-origins='${SCG_ORIGINS:}' $A.allowed-methods='*' $A.allow-credentials=true
METHOD=DELETE \
scenario "M4 origins, methods=GET,DELETE, credentials"  ""           $A.allowed-origins=https://trusted.example $A.allowed-methods=GET,DELETE $A.allow-credentials=true
scenario "T1 origins, exposed-headers=X-Access-Token"   ""           $A.allowed-origins=https://trusted.example $A.exposed-headers=X-Access-Token $A.allow-credentials=true

cat > "$WORK/index.html" <<'HTML'
<html><body><script>
async function run() {
  const out = [];
  try {
    const r = await fetch('http://localhost:8081/actuator/loggers/ROOT', {method: 'POST', credentials: 'include',
        headers: {'Content-Type': 'application/json'}, body: '{"configuredLevel":"TRACE"}'});
    out.push('POST loggers: ' + r.status);
  } catch (e) { out.push('POST loggers: blocked'); }
  for (const path of ['star?cred=include', 'star?cred=omit', 'setcookie?cred=include']) {
    try {
      const r = await fetch('http://localhost:9100/' + path, {credentials: path.endsWith('include') ? 'include' : 'omit'});
      out.push(path + ': X-Auth-Token=' + r.headers.get('X-Auth-Token') + ' Set-Cookie=' + r.headers.get('Set-Cookie'));
    } catch (e) { out.push(path + ': blocked'); }
  }
  document.title = 'RESULT ' + out.join(' | ');
}
run();
</script></body></html>
HTML

cat > "$WORK/headers_server.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', 'http://localhost:9000')
        if 'cred=include' in self.path:
            self.send_header('Access-Control-Allow-Credentials', 'true')
        exposed = 'Set-Cookie, X-Auth-Token' if self.path.startswith('/setcookie') else '*'
        self.send_header('Access-Control-Expose-Headers', exposed)
        self.send_header('X-Auth-Token', 'session-token')
        self.send_header('Set-Cookie', 'SESSION=abc')
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *args):
        pass
HTTPServer(('localhost', 9100), Handler).serve_forever()
PY

cat > "$WORK/probe.js" <<'JS'
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('http://localhost:9000/index.html');
  await page.waitForFunction(() => document.title.startsWith('RESULT'), null, { timeout: 15000 });
  console.log((await page.title()).replace(/ \| /g, '\n    '));
  await browser.close();
})();
JS

(cd "$WORK" && exec python3 -m http.server 9000 > /dev/null 2>&1) &
WEB=$!
python3 "$WORK/headers_server.py" &
HEADERS=$!
sleep 1

browser() {
    local name=$1; shift
    start $A.allowed-origins=http://localhost:9000 $A.allow-credentials=true "$@"
    printf '%s\n    %s\n    ROOT logger after: %s\n' "$name" "$(node "$WORK/probe.js" 2>&1 | tail -4)" \
        "$(curl -s localhost:8081/actuator/loggers/ROOT)"
    stop
}

echo "== Parts 2 and 3: Chromium"
browser "B1 methods=*, headers=*"   $A.allowed-methods='*' $A.allowed-headers='*'
browser "B2 methods=* only"         $A.allowed-methods='*'
browser "B3 headers=* only"         $A.allowed-headers='*'
kill "$WEB" "$HEADERS" 2>/dev/null
exit 0
