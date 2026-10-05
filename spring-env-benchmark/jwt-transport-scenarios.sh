#!/bin/bash
# Whether a Spring Boot OAuth2 resource server fetches its keys, OIDC metadata and token
# introspection over plain HTTP or TLS, one configuration at a time: the reference SCG017 is checked
# against (VALIDATION.md, "SCG017 resource server transport scenarios").
#
# There is no authorization server. listener.py listens on 127.0.0.1:8300 and records each
# connection's first bytes: a TLS handshake record ("TLS") or a plain HTTP request ("HTTP",
# "+secret" when it carries the introspection client secret, in a Basic Authorization header, in the
# clear). Each scenario starts the jwt-transport app (Spring Boot 4.1.1, Spring MVC and
# spring-boot-starter-oauth2-resource-server) with the properties as command-line arguments, waits
# until it has started, sends one GET /api with a bearer token (a well-formed JWT that never
# validates: its signature is a placeholder), and prints what the listener saw and the response
# status ("-" when no connection was attempted). The listener serves a generated RSA
# public key for paths ending in ".pub", as a key server would (K1).
set -u
cd "$(dirname "$0")/jwt-transport"
mvn -q package -DskipTests || exit 1
JAR=target/jwt-transport.jar
LOG=target/scenario.log
SEEN=target/seen.txt
PORT=8099
SECRET=scg-client-secret

for p in 8300 $PORT; do
    if (echo > /dev/tcp/127.0.0.1/$p) 2>/dev/null; then
        echo "port $p already in use: stop the process holding it first" >&2
        exit 1
    fi
done
: > "$SEEN"
rm -f target/key.pem target/key.pub
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out target/key.pem 2>/dev/null \
    && openssl pkey -in target/key.pem -pubout -out target/key.pub 2>/dev/null || exit 1
python3 listener.py "$SEEN" 8300 "$SECRET" target/key.pub &
LISTENER_PID=$!
trap 'kill $LISTENER_PID 2>/dev/null' EXIT
for _ in $(seq 1 10); do (echo > /dev/tcp/127.0.0.1/8300) 2>/dev/null && break; sleep 1; done
kill -0 $LISTENER_PID 2>/dev/null || { echo "the listener did not start" >&2; exit 1; }
sleep 1

b64url() { printf '%s' "$1" | base64 | tr -d '=\n' | tr '/+' '_-'; }
JWT="$(b64url '{"alg":"RS256","kid":"k1"}').$(b64url '{"sub":"u","iss":"http://127.0.0.1:8300"}').c2ln"

scenario() {
    local name=$1; shift
    : > "$SEEN"
    java -jar "$JAR" --server.port=$PORT "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started ResourceServerApp in\|APPLICATION FAILED\|Application run failed" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started ResourceServerApp in" "$LOG"; then
        local seen
        seen=$(sort "$SEEN" | uniq | tr '\n' ' ')
        printf '%-62s %s app did not start: %s\n' "$name" "${seen:--}" \
            "$(grep -m1 -oE 'Reason: .*|IllegalArgumentException: .*|IllegalStateException: .*' "$LOG" | sed -E 's/^Reason: //' | cut -c1-120)"
    else
        local status seen
        status=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $JWT" "localhost:$PORT/api")
        sleep 1
        seen=$(sort "$SEEN" | uniq | tr '\n' ' ')
        printf '%-62s %s(response %s)\n' "$name" "${seen:--}" "$status"
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    local waited=0
    while (echo > /dev/tcp/127.0.0.1/$PORT) 2>/dev/null; do
        sleep 1; waited=$((waited + 1)); [ $waited -lt 60 ] || { echo "port $PORT still in use" >&2; exit 1; }
    done
}

J=--spring.security.oauth2.resourceserver.jwt
O=--spring.security.oauth2.resourceserver.opaquetoken
L=127.0.0.1:8300
scenario "J1 jwk-set-uri=http://"                                   $J.jwk-set-uri=http://$L/jwks
scenario "J2 jwk-set-uri=https://"                                  $J.jwk-set-uri=https://$L/jwks
scenario "J3 jwk-set-uri=HTTP://"                                   $J.jwk-set-uri=HTTP://$L/jwks
scenario "I1 issuer-uri=http://"                                    $J.issuer-uri=http://$L
scenario "I2 issuer-uri=https://"                                   $J.issuer-uri=https://$L
scenario "I3 issuer-uri=HTTP://"                                    $J.issuer-uri=HTTP://$L
scenario "B1 issuer-uri=https://, jwk-set-uri=http://"              $J.issuer-uri=https://$L $J.jwk-set-uri=http://$L/jwks
scenario "B2 issuer-uri=http://, jwk-set-uri=https://"              $J.issuer-uri=http://$L $J.jwk-set-uri=https://$L/jwks
scenario "K1 public-key-location=http://"                           $J.public-key-location=http://$L/key.pub
scenario "B3 issuer-uri=http://, public-key-location=file:"         $J.issuer-uri=http://$L $J.public-key-location=file:target/key.pub
scenario "B4 jwk-set-uri=https://, public-key-location=http://"     $J.jwk-set-uri=https://$L/jwks $J.public-key-location=http://$L/key.pub
scenario "B5 issuer-uri=https://, public-key-location=http://"      $J.issuer-uri=https://$L $J.public-key-location=http://$L/key.pub
scenario "O1 introspection-uri=http://, client-id, client-secret"   $O.introspection-uri=http://$L/introspect \
    $O.client-id=scg-client $O.client-secret=$SECRET
scenario "O2 introspection-uri=https://, client-id, client-secret"  $O.introspection-uri=https://$L/introspect \
    $O.client-id=scg-client $O.client-secret=$SECRET
exit 0
