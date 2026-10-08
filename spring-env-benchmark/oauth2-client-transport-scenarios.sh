#!/bin/bash
# Whether a Spring Boot OAuth2 client sends its client secret, or fetches its provider's metadata,
# over plain HTTP or TLS, one configuration at a time: the reference for the OAuth2 Client provider
# URIs (VALIDATION.md, "OAuth2 Client provider transport scenarios").
#
# There is no authorization server. jwt-transport/listener.py listens on 127.0.0.1:8300 and records
# each connection's first bytes: a TLS handshake record ("TLS") or a plain HTTP request ("HTTP",
# "+secret" when it carries the client secret, in a Basic Authorization header or in the clear),
# and answers a plain request with 404. Each scenario runs the oauth2-client-transport app (Spring
# Boot 4.1.1, spring-boot-starter-oauth2-client), which runs one client_credentials grant for the
# registration "scg" at startup and exits, with the properties as command-line arguments, and prints
# what the listener saw ("-" when no connection was attempted).
set -u
cd "$(dirname "$0")"
(cd oauth2-client-transport && mvn -q package -DskipTests) || exit 1
JAR=oauth2-client-transport/target/oauth2-client-transport.jar
T=oauth2-client-transport/target
LOG=$T/scenario.log
SEEN=$T/seen.txt
SECRET=scg-client-secret

if (echo > /dev/tcp/127.0.0.1/8300) 2>/dev/null; then
    echo "port 8300 already in use: stop the process holding it first" >&2
    exit 1
fi
: > "$SEEN"
python3 jwt-transport/listener.py "$SEEN" 8300 "$SECRET" &
LISTENER_PID=$!
trap 'kill $LISTENER_PID 2>/dev/null' EXIT
for _ in $(seq 1 10); do (echo > /dev/tcp/127.0.0.1/8300) 2>/dev/null && break; sleep 1; done
sleep 1

R=--spring.security.oauth2.client.registration.scg
P=--spring.security.oauth2.client.provider.scg
scenario() {
    local name=$1; shift
    : > "$SEEN"
    timeout 120 java -jar "$JAR" --server.port=0 $R.client-id=scg-client $R.client-secret=$SECRET \
        $R.authorization-grant-type=client_credentials $R.provider=scg "$@" > "$LOG" 2>&1
    sleep 1
    local seen
    seen=$(sort "$SEEN" | uniq | tr '\n' ' ')
    if grep -q "APPLICATION FAILED\|Application run failed" "$LOG"; then
        printf '%-58s %s (app did not start)\n' "$name" "${seen:--}"
    else
        printf '%-58s %s\n' "$name" "${seen:--}"
    fi
}

scenario "C1 token-uri=http://, client_secret_basic"        $P.token-uri=http://127.0.0.1:8300/token
scenario "C2 token-uri=http://, client_secret_post"         $P.token-uri=http://127.0.0.1:8300/token $R.client-authentication-method=client_secret_post
scenario "C3 token-uri=https://"                            $P.token-uri=https://127.0.0.1:8300/token
scenario "C4 token-uri=HTTP://"                             $P.token-uri=HTTP://127.0.0.1:8300/token
scenario "I1 issuer-uri=http://"                            $P.issuer-uri=http://127.0.0.1:8300
scenario "I2 issuer-uri=https://"                           $P.issuer-uri=https://127.0.0.1:8300
exit 0
