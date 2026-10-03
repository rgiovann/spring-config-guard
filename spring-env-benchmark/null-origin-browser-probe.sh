#!/bin/bash
# Whether a page can read /actuator/env with credentials from a sandboxed iframe, which a browser
# sends as "Origin: null": the reference for SCG003's 'null' origin (VALIDATION.md, "SCG003 CORS
# scenarios"). Runs this benchmark app twice, with allowed-origins=null and with another origin as a
# control, and loads a page on port 9000 whose sandboxed iframe fetches /actuator/env.
#
# Needs Node.js and Playwright with a Chromium (NODE_PATH pointing at the node_modules that has it).
set -u
cd "$(dirname "$0")"
mvn -q package -DskipTests || exit 1
WORK=target/null-origin-probe
LOG=$WORK/app.log
mkdir -p "$WORK"

cat > "$WORK/index.html" <<'HTML'
<html><body><script>
window.addEventListener('message', e => { document.title = 'RESULT ' + e.data; });
</script>
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('http://localhost:8081/actuator/env',{credentials:'include'}).then(r=>r.text()).then(t=>parent.postMessage('read '+t.length+' bytes','*')).catch(e=>parent.postMessage('blocked: '+e,'*'))</script>"></iframe>
</body></html>
HTML

cat > "$WORK/probe.js" <<'JS'
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('http://localhost:9000/index.html');
  await page.waitForFunction(() => document.title.startsWith('RESULT'), null, { timeout: 15000 });
  console.log(await page.title());
  await browser.close();
})();
JS

(cd "$WORK" && exec python3 -m http.server 9000 > /dev/null 2>&1) &
WEB=$!

probe() {
    local name=$1; shift
    while (echo > /dev/tcp/localhost/8081) 2>/dev/null; do sleep 1; done
    java -jar target/spring-env-benchmark-0.0.1-SNAPSHOT.jar --spring.profiles.active=prod "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started \|APPLICATION FAILED" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    printf '%-44s %s\n' "$name" "$(node "$WORK/probe.js" 2>&1 | tail -1)"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

C=--management.endpoints.web.cors
probe "allowed-origins=null, credentials"         $C.allowed-origins=null $C.allow-credentials=true
probe "allowed-origins=https://other.example"      $C.allowed-origins=https://other.example $C.allow-credentials=true
kill "$WEB" 2>/dev/null
exit 0
