#!/bin/bash
# What the embedded server's SSL, management SSL and session cookie keys do, one configuration at a
# time: the reference SCG011 is checked against (VALIDATION.md, "SCG011 transport scenarios").
#
# Four separate projects, so this benchmark app stays as it is: server-transport-tomcat (T, M and K
# scenarios), -session (Spring Session, K), -jetty (K) and -webflux (R). Each scenario starts one
# app on port 9443 (a separate management port is 9444) with the properties as command-line
# arguments, waits until the previous app has released both ports and the new one has started (or
# failed), then requests /session and /actuator/health over HTTPS, falling back to HTTP, and prints
# the scheme each port answers on and the session cookie's attributes. It waits for Spring Boot's
# "Started TransportApp in" line: Jetty logs its own "Started ..." lines before its connector is up.
#
# The TLS material is a throwaway self-signed key, generated into target/scenario-tls on the first
# run (keytool, openssl), so no private key is committed.
#
# Usage: ./server-transport-scenarios.sh [tomcat|session|jetty|webflux ...]   (default: all four)
set -u
cd "$(dirname "$0")"
TLS=target/scenario-tls
LOG=target/server-transport-scenario.log

if [ ! -f "$TLS/ks.p12" ]; then
    mkdir -p "$TLS"
    keytool -genkeypair -alias scenario -keyalg RSA -keysize 2048 -validity 3650 -dname CN=localhost \
        -storetype PKCS12 -keystore "$TLS/ks.p12" -storepass changeit -keypass changeit 2>/dev/null || exit 1
    openssl pkcs12 -in "$TLS/ks.p12" -passin pass:changeit -nokeys -out "$TLS/cert.pem" 2>/dev/null || exit 1
    openssl pkcs12 -in "$TLS/ks.p12" -passin pass:changeit -nocerts -nodes -out "$TLS/key.pem" 2>/dev/null || exit 1
fi
KS="--server.ssl.key-store=file:$TLS/ks.p12 --server.ssl.key-store-password=changeit"
MKS="--management.server.ssl.key-store=file:$TLS/ks.p12 --management.server.ssl.key-store-password=changeit"
PEM="--server.ssl.certificate=file:$TLS/cert.pem --server.ssl.certificate-private-key=file:$TLS/key.pem"
BUNDLE="--spring.ssl.bundle.jks.web.keystore.location=file:$TLS/ks.p12 --spring.ssl.bundle.jks.web.keystore.password=changeit --server.ssl.bundle=web"
C=--server.servlet.session.cookie
R=--server.reactive.session.cookie

# scheme the port answers on, plus the Set-Cookie attributes (the session ID itself removed)
probe() {
    local port=$1 path=$2 headers
    for scheme in https http; do
        if headers=$(curl -sk --max-time 5 -o /dev/null -D - "$scheme://localhost:$port$path" 2>/dev/null) && [ -n "$headers" ]; then
            echo "$scheme $(echo "$headers" | tr -d '\r' | grep -i '^set-cookie' \
                | sed 's/^[Ss]et-[Cc]ookie: //; s/^\(JSESSIONID\|SESSION\)=[^;]*;//')"
            return
        fi
    done
    echo down
}

scenario() {
    local name=$1; shift
    while (echo > /dev/tcp/localhost/9443) 2>/dev/null || (echo > /dev/tcp/localhost/9444) 2>/dev/null; do sleep 1; done
    java -jar "$JAR" --server.port=9443 "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started TransportApp in\|APPLICATION FAILED\|Application run failed" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started TransportApp in" "$LOG"; then
        printf '%-56s did not start: %s\n' "$name" "$(grep -m1 -A2 'Description:' "$LOG" | tail -1 | cut -c1-100)"
    else
        printf '%-56s main=[%s] mgmt9444=[%s]\n' "$name" "$(probe 9443 /session)" "$(probe 9444 /actuator/health)"
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

use() {
    echo "== $1"
    mvn -q -f "server-transport-$1/pom.xml" package -DskipTests || exit 1
    JAR="server-transport-$1/target/server-transport-$1.jar"
}

cookie_scenarios() {
    scenario "K0 TLS, cookie defaults"                       $KS
    scenario "K1 TLS, secure=false"                          $KS $C.secure=false
    scenario "K2 TLS, secure=off"                            $KS $C.secure=off
    scenario "K3 http-only=false"                            $C.http-only=false
    scenario "K4 same-site=None"                             $C.same-site=None
    scenario "K5 same-site=none"                             $C.same-site=none
    scenario "K6 plain HTTP, cookie defaults"
    scenario "K7 TLS, same-site=None, secure=false"          $KS $C.same-site=None $C.secure=false
}

for app in "${@:-tomcat session jetty webflux}"; do
  for app in $app; do
    case $app in
    tomcat)
        use tomcat
        scenario "T0 key-store only"                             $KS
        scenario "T1 key-store, enabled=false"                   $KS --server.ssl.enabled=false
        scenario "T2 key-store, enabled=off"                     $KS --server.ssl.enabled=off
        scenario "T3 key-store, enabled=no"                      $KS --server.ssl.enabled=no
        scenario "T4 key-store, enabled=0"                       $KS --server.ssl.enabled=0
        scenario "T5 key-store, enabled=FALSE"                   $KS --server.ssl.enabled=FALSE
        scenario "T6 key-store, enabled=disabled"                $KS --server.ssl.enabled=disabled
        scenario "T7 key-store, enabled= (empty)"                $KS --server.ssl.enabled=
        scenario "T8 PEM certificate, enabled=false"             $PEM --server.ssl.enabled=false
        scenario "T9 PEM certificate"                            $PEM
        scenario "T10 bundle, enabled=false"                     $BUNDLE --server.ssl.enabled=false
        scenario "T11 bundle"                                    $BUNDLE
        scenario "T12 enabled=false, no TLS material"            --server.ssl.enabled=false
        scenario "M1 server TLS, management port"                $KS --management.server.port=9444
        scenario "M2 M1 + management enabled=false"              $KS --management.server.port=9444 --management.server.ssl.enabled=false
        scenario "M3 management port, key-store, enabled=false"  --management.server.port=9444 $MKS --management.server.ssl.enabled=false
        scenario "M4 management port, key-store"                 --management.server.port=9444 $MKS
        scenario "M5 M3 with management port=-1"                 --management.server.port=-1 $MKS --management.server.ssl.enabled=false
        scenario "M6 management port = server port"              $KS --management.server.port=9443 $MKS --management.server.ssl.enabled=false
        cookie_scenarios
        ;;
    session|jetty)
        use $app
        cookie_scenarios
        ;;
    webflux)
        use webflux
        scenario "R0 TLS, defaults"                              $KS
        scenario "R1 TLS, secure=false"                          $KS $R.secure=false
        scenario "R2 http-only=false"                            $R.http-only=false
        scenario "R3 same-site=None"                             $R.same-site=None
        scenario "R4 TLS, servlet secure/http-only=false"        $KS $C.secure=false $C.http-only=false
        ;;
    *) echo "unknown app: $app" >&2; exit 2 ;;
    esac
  done
done
exit 0
