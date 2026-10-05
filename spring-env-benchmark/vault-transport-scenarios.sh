#!/bin/bash
# Whether a Spring Cloud Vault client speaks plain HTTP or TLS, one configuration at a time: the
# reference SCG016 is checked against (VALIDATION.md, "SCG016 Vault transport scenarios").
#
# There is no Vault server. listener.py listens on 127.0.0.1:8200 and records each connection's first
# bytes: a TLS handshake record ("TLS") or a plain HTTP request ("HTTP", "+token" when the Vault token
# travels in it in the clear). Each scenario runs the vault-transport app (Spring Cloud 2025.1.3:
# Spring Boot 4.0.8, Spring Cloud Vault 5.0.2), which imports configuration from Vault at startup with
# token authentication, with the properties as command-line arguments, and prints what the listener
# saw ("-" when no connection was attempted).
set -u
cd "$(dirname "$0")/vault-transport"
mvn -q package -DskipTests || exit 1
JAR=target/vault-transport.jar
LOG=target/scenario.log
SEEN=target/seen.txt
TOKEN=scg-test-token

if (echo > /dev/tcp/127.0.0.1/8200) 2>/dev/null; then
    echo "port 8200 already in use: stop the process holding it first" >&2
    exit 1
fi
: > "$SEEN"
python3 listener.py "$SEEN" 8200 "$TOKEN" &
LISTENER_PID=$!
trap 'kill $LISTENER_PID 2>/dev/null' EXIT
for _ in $(seq 1 10); do (echo > /dev/tcp/127.0.0.1/8200) 2>/dev/null && break; sleep 1; done
kill -0 $LISTENER_PID 2>/dev/null || { echo "the listener did not start" >&2; exit 1; }
sleep 1

V=--spring.cloud.vault
scenario() {
    local name=$1; shift
    : > "$SEEN"
    timeout 120 java -jar "$JAR" --spring.config.import=optional:vault:// $V.token=$TOKEN \
        $V.connection-timeout=2000 $V.read-timeout=2000 "$@" > "$LOG" 2>&1
    sleep 1
    local seen
    seen=$(sort "$SEEN" | uniq | tr '\n' ' ')
    if grep -q "APPLICATION FAILED\|Application run failed" "$LOG"; then
        printf '%-58s %s app did not start: %s\n' "$name" "${seen:--}" \
            "$(grep -m1 -oE 'Reason: .*|IllegalArgumentException: .*' "$LOG" | sed -E 's/^Reason: //')"
    else
        printf '%-58s %s\n' "$name" "${seen:--}"
    fi
}

scenario "D0 defaults (localhost:8200)"                             $V.host=127.0.0.1
scenario "S1 scheme=http"                                           $V.host=127.0.0.1 $V.scheme=http
scenario "S2 scheme=HTTP"                                           $V.host=127.0.0.1 $V.scheme=HTTP
scenario "S3 scheme=https"                                          $V.host=127.0.0.1 $V.scheme=https
scenario "S4 scheme= (empty)"                                       $V.host=127.0.0.1 $V.scheme=
scenario "U1 uri=http://127.0.0.1:8200"                             $V.uri=http://127.0.0.1:8200
scenario "U2 uri=https://127.0.0.1:8200"                            $V.uri=https://127.0.0.1:8200
scenario "U3 uri=https://127.0.0.1:8200, scheme=http"               $V.uri=https://127.0.0.1:8200 $V.scheme=http
scenario "U4 uri=http://127.0.0.1:8200, scheme=https"               $V.uri=http://127.0.0.1:8200 $V.scheme=https
scenario "U5 uri=HTTP://127.0.0.1:8200"                             $V.uri=HTTP://127.0.0.1:8200
scenario "U6 uri= (empty), scheme=http"                             $V.uri= $V.host=127.0.0.1 $V.scheme=http
scenario "E1 scheme=http, vault.enabled=false"                      $V.host=127.0.0.1 $V.scheme=http $V.enabled=false
scenario "E2 scheme=http, vault.enabled=FALSE"                      $V.host=127.0.0.1 $V.scheme=http $V.enabled=FALSE
scenario "E3 scheme=http, vault.enabled=off"                        $V.host=127.0.0.1 $V.scheme=http $V.enabled=off
scenario "E4 scheme=http, vault.enabled=no"                         $V.host=127.0.0.1 $V.scheme=http $V.enabled=no
scenario "E5 scheme=http, vault.enabled=0"                          $V.host=127.0.0.1 $V.scheme=http $V.enabled=0
exit 0
