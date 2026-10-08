#!/bin/bash
# Whether a Spring Boot Kafka or RabbitMQ client that uses TLS verifies the server, one
# configuration at a time: the reference SCG014 and SCG015 are checked against (VALIDATION.md,
# "TLS without server verification (Kafka and RabbitMQ)").
#
# There is no broker. tls-verification/tls_listener.py listens with TLS on three ports, each
# presenting its own certificate, generated into target/ with openssl:
#   9301  signed by a test CA, for localhost and 127.0.0.1     (the control: a valid server)
#   9302  signed by the same CA, for wrong.example only         (a trusted certificate, wrong host)
#   9303  self-signed, for localhost and 127.0.0.1              (the right host, untrusted)
# The clients trust the test CA (target/trust.p12) and connect to 127.0.0.1. The listener records
# whether the client finished the handshake ("accepted") or aborted it ("refused", with the alert);
# a connection dropped without an alert, a client exiting in the middle of a retry, isn't printed.
# Each scenario runs kafka-tls/ (an AdminClient built from Spring Boot 4.1.1's auto-configured
# KafkaAdmin) or rabbit-transport/ (one connection from the auto-configured ConnectionFactory),
# with the properties as command-line arguments. Y1 and Y2 load a YAML file.
set -u
cd "$(dirname "$0")"
(cd kafka-tls && mvn -q package -DskipTests) || exit 1
(cd rabbit-transport && mvn -q package -DskipTests) || exit 1
T=tls-verification/target
mkdir -p "$T"
SEEN=$T/seen.txt
LOG=$T/scenario.log

for port in 9301 9302 9303; do
    if (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null; then
        echo "port $port already in use: stop the process holding it first" >&2
        exit 1
    fi
done

rm -f "$T"/*.pem "$T"/*.p12 "$T"/*.srl
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=scg-test-ca \
    -keyout "$T/ca-key.pem" -out "$T/ca.pem" 2> /dev/null || exit 1
leaf() { # name, CN, subjectAltName
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$2" -keyout "$T/$1-key.pem" -out "$T/$1.csr" 2> /dev/null &&
    openssl x509 -req -days 2 -in "$T/$1.csr" -CA "$T/ca.pem" -CAkey "$T/ca-key.pem" -CAcreateserial \
        -extfile <(printf 'subjectAltName=%s' "$3") -out "$T/$1.pem" 2> /dev/null
}
leaf good localhost DNS:localhost,IP:127.0.0.1 || exit 1
leaf wrong wrong.example DNS:wrong.example || exit 1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
    -keyout "$T/untrusted-key.pem" -out "$T/untrusted.pem" 2> /dev/null || exit 1
keytool -importcert -noprompt -alias scg-test-ca -file "$T/ca.pem" -storetype PKCS12 \
    -keystore "$T/trust.p12" -storepass changeit > /dev/null 2>&1 || exit 1
printf 'spring.kafka.properties.ssl.endpoint.identification.algorithm:\n' > "$T/null-algorithm.yml"
printf "spring.kafka.properties.ssl.endpoint.identification.algorithm: ' '\n" > "$T/blank-algorithm.yml"

python3 tls-verification/tls_listener.py "$SEEN" \
    "9301:$T/good.pem:$T/good-key.pem" "9302:$T/wrong.pem:$T/wrong-key.pem" \
    "9303:$T/untrusted.pem:$T/untrusted-key.pem" &
LISTENER_PID=$!
trap 'kill $LISTENER_PID 2>/dev/null' EXIT
for _ in $(seq 1 10); do (echo > /dev/tcp/127.0.0.1/9303) 2>/dev/null && break; sleep 1; done
sleep 1

scenario() { # name, jar, arguments
    local name=$1 jar=$2; shift 2
    : > "$SEEN"
    timeout 120 java -jar "$jar" "$@" > "$LOG" 2>&1
    sleep 1
    local seen
    seen=$(grep -v ':closed:' "$SEEN" | sort | uniq | tr '\n' ' ')
    if grep -q "APPLICATION FAILED" "$LOG"; then
        printf '%-58s app did not start: %s\n' "$name" "$(grep -m1 -oE 'Reason: .*' "$LOG" | sed -E 's/^Reason: //')"
    else
        printf '%-58s %s\n' "$name" "${seen:--}"
    fi
}

K=--spring.kafka
KJ=kafka-tls/target/kafka-tls.jar
kafka() { # name, port, arguments
    local name=$1 port=$2; shift 2
    scenario "$name" "$KJ" $K.bootstrap-servers=127.0.0.1:$port $K.security.protocol=SSL "$@"
}
KT="$K.ssl.trust-store-location=file:$T/trust.p12 $K.ssl.trust-store-password=changeit $K.ssl.trust-store-type=PKCS12"
KB="--spring.ssl.bundle.jks.kafka.truststore.location=file:$T/trust.p12 --spring.ssl.bundle.jks.kafka.truststore.password=changeit --spring.ssl.bundle.jks.kafka.truststore.type=PKCS12 $K.ssl.bundle=kafka"
A=ssl.endpoint.identification.algorithm
kafka "K0 valid server"                                     9301 $KT
kafka "K1 wrong host"                                       9302 $KT
kafka "K2 wrong host, properties.$A="                       9302 $KT $K.properties.$A=
kafka "K3 wrong host, admin.properties.$A="                 9302 $KT $K.admin.properties.$A=
kafka "K4 wrong host, consumer.properties.$A="              9302 $KT $K.consumer.properties.$A=
kafka "K5 wrong host, properties.$A=https"                  9302 $KT $K.properties.$A=https
kafka "K6 wrong host, properties.$A=HTTPS"                  9302 $KT $K.properties.$A=HTTPS
kafka "K7 untrusted, properties.$A="                        9303 $KT $K.properties.$A=
kafka "K8 wrong host, properties.$A=none"                   9302 $KT $K.properties.$A=none
kafka "K9 wrong host, properties.$A=LDAPS"                  9302 $KT $K.properties.$A=LDAPS
kafka "K10 valid server, properties.$A=none"                9301 $KT $K.properties.$A=none
kafka "Y1 wrong host, YAML $A: (null)"                      9302 $KT --spring.config.additional-location=file:$T/null-algorithm.yml
kafka "Y2 wrong host, YAML $A: ' '"                         9302 $KT --spring.config.additional-location=file:$T/blank-algorithm.yml
kafka "KB0 valid server, ssl.bundle"                        9301 $KB
kafka "KB1 wrong host, ssl.bundle"                          9302 $KB
kafka "KB2 wrong host, ssl.bundle, properties.$A="          9302 $KB $K.properties.$A=
kafka "KB3 untrusted, ssl.bundle"                           9303 $KB

R=--spring.rabbitmq
RJ=rabbit-transport/target/rabbit-transport.jar
rabbit() { # name, port, arguments
    local name=$1 port=$2; shift 2
    scenario "$name" "$RJ" $R.connection-timeout=2s $R.host=127.0.0.1 $R.port=$port $R.ssl.enabled=true "$@"
}
RT="$R.ssl.trust-store=file:$T/trust.p12 $R.ssl.trust-store-password=changeit $R.ssl.trust-store-type=PKCS12"
RB="--spring.ssl.bundle.jks.rabbit.truststore.location=file:$T/trust.p12 --spring.ssl.bundle.jks.rabbit.truststore.password=changeit --spring.ssl.bundle.jks.rabbit.truststore.type=PKCS12 $R.ssl.bundle=rabbit"
rabbit "R0 valid server"                                    9301 $RT
rabbit "R1 wrong host"                                      9302 $RT
rabbit "R2 wrong host, verify-hostname=false"               9302 $RT $R.ssl.verify-hostname=false
rabbit "R3 wrong host, verify-hostname=off"                 9302 $RT $R.ssl.verify-hostname=off
rabbit "R4 untrusted"                                       9303 $RT
rabbit "R5 untrusted, validate-server-certificate=false"    9303 $RT $R.ssl.validate-server-certificate=false
rabbit "R6 wrong host, validate-server-certificate=false"   9302 $RT $R.ssl.validate-server-certificate=false
rabbit "R7 untrusted, verify-hostname=false"                9303 $RT $R.ssl.verify-hostname=false
rabbit "R8 untrusted, no trust-store"                       9303
rabbit "R9 untrusted, no trust-store, validate-server-certificate=false" 9303 $R.ssl.validate-server-certificate=false
rabbit "R10 wrong host, no trust-store, validate-server-certificate=false" 9302 $R.ssl.validate-server-certificate=false
rabbitaddr() { # name, arguments: TLS from an amqps:// address, ssl.enabled left unset
    local name=$1; shift
    scenario "$name" "$RJ" $R.connection-timeout=2s "$@"
}
rabbitaddr "R11 wrong host, addresses=amqps://"                     $R.addresses=amqps://127.0.0.1:9302 $RT
rabbitaddr "R12 wrong host, addresses=amqps://, verify-hostname=false" $R.addresses=amqps://127.0.0.1:9302 $RT $R.ssl.verify-hostname=false
rabbitaddr "R13 untrusted, addresses=amqps://, no trust-store, validate-server-certificate=false" $R.addresses=amqps://127.0.0.1:9303 $R.ssl.validate-server-certificate=false
rabbit "RB0 valid server, ssl.bundle"                       9301 $RB
rabbit "RB1 wrong host, ssl.bundle"                         9302 $RB
rabbit "RB2 wrong host, ssl.bundle, verify-hostname=false"  9302 $RB $R.ssl.verify-hostname=false
rabbit "RB3 untrusted, ssl.bundle, validate-server-certificate=false" 9303 $RB $R.ssl.validate-server-certificate=false
exit 0
