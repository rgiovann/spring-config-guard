#!/bin/bash
# Whether TLS 1.0 and 1.1 settings take effect on Java 21, one configuration at a time: the
# measurement behind not reporting them (VALIDATION.md, "TLS 1.0 and 1.1 on Java 21").
#
# Server: the embedded server of server-transport-tomcat, -jetty and -webflux (Netty) on port 9443,
# with server.ssl.* or an SSL bundle as command-line arguments. openssl s_client connects once per
# version (-tls1, -tls1_1, -tls1_2, -tls1_3) and prints the version negotiated, or "fail".
# Client: kafka-tls/ (an AdminClient built from Spring Boot 4.1.1's auto-configured KafkaAdmin)
# connects to an openssl s_server on port 9311 that accepts only TLS 1.0 (-tls1) or any version;
# the server's handshake trace says whether the client sent a ClientHello and which version the
# handshake ended with. The host name check is off (a blank ssl.endpoint.identification.algorithm)
# so the only variable is the protocol: the certificate is self-signed for localhost and trusted.
#
# Each scenario runs twice: on the JDK as installed ("stock"), whose jdk.tls.disabledAlgorithms
# lists TLSv1 and TLSv1.1, and with a java.security override that takes them out ("legacy", the
# control that shows the harness sees TLS 1.0 when the JVM allows it). OpenSSL 3 refuses TLS 1.0
# and 1.1 at its default security level, so both openssl ends run at @SECLEVEL=0.
#
# The TLS material is a throwaway self-signed key, generated into target/tls-protocol on the first
# run (keytool, openssl), so no private key is committed.
#
# Usage: ./tls-protocol-scenarios.sh [server] [client]   (default: both)
set -u
cd "$(dirname "$0")"
T=target/tls-protocol
LOG=$T/scenario.log
mkdir -p "$T"

for port in 9443 9311; do
    if (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null; then
        echo "port $port already in use: stop the process holding it first" >&2
        exit 1
    fi
done

if [ ! -f "$T/ks.p12" ]; then
    keytool -genkeypair -alias scenario -keyalg RSA -keysize 2048 -validity 3650 -dname CN=localhost \
        -storetype PKCS12 -keystore "$T/ks.p12" -storepass changeit -keypass changeit 2>/dev/null || exit 1
    openssl pkcs12 -in "$T/ks.p12" -passin pass:changeit -nokeys -out "$T/cert.pem" 2>/dev/null || exit 1
    openssl pkcs12 -in "$T/ks.p12" -passin pass:changeit -nocerts -nodes -out "$T/key.pem" 2>/dev/null || exit 1
    keytool -importcert -noprompt -alias scenario -file "$T/cert.pem" -storetype PKCS12 \
        -keystore "$T/trust.p12" -storepass changeit > /dev/null 2>&1 || exit 1
fi
# the installed list without TLSv1, TLSv1.1, DTLSv1.0, TLS_RSA_* and the SHA-1 signature limits
printf 'jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, ECDH\n' \
    > "$T/legacy.security"
jvm() { # stock|legacy
    [ "$1" = legacy ] && echo "-Djava.security.properties=$T/legacy.security"
}

# --- server ---

KS="--server.ssl.key-store=file:$T/ks.p12 --server.ssl.key-store-password=changeit"
BUNDLE="--spring.ssl.bundle.jks.web.keystore.location=file:$T/ks.p12 --spring.ssl.bundle.jks.web.keystore.password=changeit --server.ssl.bundle=web"
S=--server.ssl

# The "New, <version>, Cipher is" line names the cipher's version (TLSv1.0 for a TLS 1.1 handshake);
# the session's "Protocol :" line names the protocol, but isn't printed for TLS 1.3, whose ciphers
# exist in TLS 1.3 only.
handshake() { # s_client version flag: the version negotiated, or fail
    local out cipher_version protocol
    out=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:9443 "$1" -cipher 'DEFAULT:@SECLEVEL=0' 2>/dev/null)
    cipher_version=$(echo "$out" | grep -m1 -oE '^New, [^,]+' | cut -c6-)
    protocol=$(echo "$out" | grep -m1 -oE 'Protocol *: *[^ ]+' | awk '{print $NF}')
    if [ -z "$cipher_version" ] || [ "$cipher_version" = "(NONE)" ]; then echo fail; else echo "${protocol:-$cipher_version}"; fi
}

server_scenario() { # name, jar, mode, arguments
    local name=$1 jar=$2 mode=$3; shift 3
    while (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null; do sleep 1; done
    java $(jvm "$mode") -jar "$jar" --server.port=9443 "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started TransportApp in\|APPLICATION FAILED\|Application run failed" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started TransportApp in" "$LOG"; then
        printf '%-6s %-50s did not start\n' "$mode" "$name"
    else
        printf '%-6s %-50s 1.0=%-8s 1.1=%-8s 1.2=%-8s 1.3=%s\n' "$mode" "$name" \
            "$(handshake -tls1)" "$(handshake -tls1_1)" "$(handshake -tls1_2)" "$(handshake -tls1_3)"
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

servers() {
    for app in tomcat jetty webflux; do
        mvn -q -f "server-transport-$app/pom.xml" package -DskipTests || exit 1
        local jar="server-transport-$app/target/server-transport-$app.jar"
        echo "== server: $app"
        for mode in stock legacy; do
            server_scenario "S0 TLS, protocol defaults"                     "$jar" $mode $KS
            server_scenario "S1 enabled-protocols=TLSv1,TLSv1.1"            "$jar" $mode $KS $S.enabled-protocols=TLSv1,TLSv1.1
            server_scenario "S2 enabled-protocols=TLSv1.2,TLSv1.1,TLSv1"    "$jar" $mode $KS $S.enabled-protocols=TLSv1.2,TLSv1.1,TLSv1
            server_scenario "S3 protocol=TLSv1"                             "$jar" $mode $KS $S.protocol=TLSv1
            server_scenario "S4 protocol=TLSv1.1"                           "$jar" $mode $KS $S.protocol=TLSv1.1
            server_scenario "S5 bundle, options.enabled-protocols=TLSv1"    "$jar" $mode $BUNDLE \
                --spring.ssl.bundle.jks.web.options.enabled-protocols=TLSv1
        done
    done
}

# --- client ---

K=--spring.kafka
KAFKA="$K.bootstrap-servers=127.0.0.1:9311 $K.security.protocol=SSL $K.ssl.trust-store-location=file:$T/trust.p12 $K.ssl.trust-store-password=changeit $K.ssl.trust-store-type=PKCS12 $K.properties.ssl.endpoint.identification.algorithm="
TRACE=$T/s_server.log

client_scenario() { # name, mode, s_server version flag ("" for any), arguments
    local name=$1 mode=$2 peer=$3 result; shift 3
    while (echo > /dev/tcp/127.0.0.1/9311) 2>/dev/null; do sleep 1; done
    # s_server exits when its stdin closes: keep it open for the client's lifetime
    (sleep 30 | timeout 30 openssl s_server -accept 9311 -cert "$T/cert.pem" -key "$T/key.pem" $peer \
        -cipher 'DEFAULT:@SECLEVEL=0' -naccept 1 -msg > "$TRACE" 2>&1) &
    local server=$!
    # wait for s_server's ACCEPT line: a probe connection would use up its only accept
    for _ in $(seq 1 50); do grep -q '^ACCEPT' "$TRACE" 2>/dev/null && break; sleep 0.2; done
    timeout 25 java $(jvm "$mode") -jar kafka-tls/target/kafka-tls.jar $KAFKA "$@" > "$LOG" 2>&1
    kill "$server" 2>/dev/null; wait "$server" 2>/dev/null
    if grep -aq '^>>> .*ServerHello' "$TRACE" && grep -aq 'CIPHER is' "$TRACE"; then
        result="accepted, $(grep -a -m1 -oE '^>>> TLS [0-9.]+, Handshake \[length [0-9a-f]+\], ServerHello' "$TRACE" | cut -d, -f1 | cut -c5-)"
    elif grep -aq '^<<< .*ClientHello' "$TRACE"; then
        result="failed after the ClientHello"
    else
        result="no ClientHello: $(grep -m1 -oE 'No appropriate protocol' "$LOG" || echo 'no connection')"
    fi
    printf '%-6s %-56s %s\n' "$mode" "$name" "$result"
}

clients() {
    (cd kafka-tls && mvn -q package -DskipTests) || exit 1
    echo "== client: Kafka"
    local P=$K.properties.ssl.enabled.protocols
    for mode in stock legacy; do
        client_scenario "C0 protocol defaults, TLS 1.0 peer"                   $mode -tls1
        client_scenario "C1 enabled.protocols=TLSv1.2,TLSv1.1,TLSv1, 1.0 peer" $mode -tls1 $P=TLSv1.2,TLSv1.1,TLSv1
        client_scenario "C2 enabled.protocols=TLSv1, 1.0 peer"                 $mode -tls1 $P=TLSv1
        client_scenario "C3 ssl.protocol=TLSv1, 1.0 peer"                      $mode -tls1 $K.ssl.protocol=TLSv1
        client_scenario "C4 enabled.protocols=TLSv1.2,TLSv1.1,TLSv1, any peer" $mode ""    $P=TLSv1.2,TLSv1.1,TLSv1
        client_scenario "C5 protocol defaults, any peer"                       $mode ""
    done
}

for part in "${@:-server client}"; do
    for p in $part; do
        case $p in
            server) servers ;;
            client) clients ;;
            *) echo "unknown part: $p" >&2; exit 1 ;;
        esac
    done
done
