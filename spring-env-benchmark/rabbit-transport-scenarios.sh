#!/bin/bash
# Whether a Spring Boot RabbitMQ client speaks plain AMQP or TLS, one configuration at a time: the
# reference SCG015 is checked against (VALIDATION.md, "SCG015 RabbitMQ transport scenarios").
#
# There is no broker. listener.py listens on 127.0.0.1:5672 and 5671 and records the first bytes of
# each connection: the plain AMQP protocol header ("AMQP") or a TLS handshake record ("TLS"). Each
# scenario runs the rabbit-transport app (Spring Boot 4.1.1, spring-boot-starter-amqp), which opens
# one connection with the auto-configured ConnectionFactory and exits, with the properties as
# command-line arguments, and prints what the listener saw ("-" when no connection was attempted).
# B1 uses an SSL bundle whose trust store is generated into target/ with keytool; Y1 loads a YAML
# file with addresses written as a list.
set -u
cd "$(dirname "$0")/rabbit-transport"
mvn -q package -DskipTests || exit 1
JAR=target/rabbit-transport.jar
LOG=target/scenario.log
SEEN=target/seen.txt

for port in 5672 5671; do
    if (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null; then
        echo "port $port already in use: stop the process holding it first" >&2
        exit 1
    fi
done
: > "$SEEN"
python3 listener.py "$SEEN" 5672 5671 &
LISTENER_PID=$!
trap 'kill $LISTENER_PID 2>/dev/null' EXIT
for _ in $(seq 1 10); do (echo > /dev/tcp/127.0.0.1/5672) 2>/dev/null && break; sleep 1; done
sleep 1
: > "$SEEN"

rm -f target/trust.p12
keytool -genkeypair -alias scg -keyalg RSA -dname CN=localhost -validity 2 -storetype PKCS12 \
    -keystore target/trust.p12 -storepass changeit -keypass changeit > /dev/null 2>&1 || exit 1
printf 'spring.rabbitmq.addresses:\n  - 127.0.0.1:5672\n' > target/addresses-list.yml

R=--spring.rabbitmq
scenario() {
    local name=$1; shift
    : > "$SEEN"
    timeout 120 java -jar "$JAR" $R.connection-timeout=2s "$@" > "$LOG" 2>&1
    sleep 1
    local seen
    seen=$(sort "$SEEN" | uniq | tr '\n' ' ')
    if grep -q "APPLICATION FAILED" "$LOG"; then
        printf '%-62s app did not start: %s\n' "$name" "$(grep -m1 -oE 'Reason: .*' "$LOG" | sed -E 's/^Reason: //')"
    else
        printf '%-62s %s\n' "$name" "${seen:--}"
    fi
}

B=--spring.ssl.bundle.jks.rabbit.truststore
scenario "H0 host=127.0.0.1"                                        $R.host=127.0.0.1
scenario "H1 host, ssl.enabled=true"                                $R.host=127.0.0.1 $R.ssl.enabled=true
scenario "H2 host, ssl.enabled=false"                               $R.host=127.0.0.1 $R.ssl.enabled=false
scenario "H3 host, ssl.enabled=yes"                                 $R.host=127.0.0.1 $R.ssl.enabled=yes
scenario "H4 host, ssl.enabled=TRUE"                                $R.host=127.0.0.1 $R.ssl.enabled=TRUE
scenario "H5 host, port=5671 (no ssl)"                              $R.host=127.0.0.1 $R.port=5671
scenario "B1 host, ssl.bundle=rabbit"                               $R.host=127.0.0.1 $R.ssl.bundle=rabbit \
    $B.location=file:target/trust.p12 $B.password=changeit $B.type=PKCS12
scenario "V1 host, ssl.enabled=true, validate-server-certificate=false" $R.host=127.0.0.1 $R.ssl.enabled=true \
    $R.ssl.validate-server-certificate=false
scenario "A1 addresses=127.0.0.1:5672"                              $R.addresses=127.0.0.1:5672
scenario "A2 addresses=amqps://127.0.0.1:5672"                      $R.addresses=amqps://127.0.0.1:5672
scenario "A3 addresses=amqp://127.0.0.1:5672, ssl.enabled=true"     $R.addresses=amqp://127.0.0.1:5672 $R.ssl.enabled=true
scenario "A4 addresses=AMQPS://127.0.0.1:5672"                      $R.addresses=AMQPS://127.0.0.1:5672
scenario "A5 addresses=127.0.0.1:5672, ssl.enabled=true"            $R.addresses=127.0.0.1:5672 $R.ssl.enabled=true
scenario "A6 addresses=127.0.0.1:5672,amqps://127.0.0.1:5672"       $R.addresses=127.0.0.1:5672,amqps://127.0.0.1:5672
scenario "A7 addresses=amqps://127.0.0.1:5672,127.0.0.1:5672"       $R.addresses=amqps://127.0.0.1:5672,127.0.0.1:5672
scenario "Y1 YAML addresses as a list [127.0.0.1:5672]"            --spring.config.additional-location=file:target/addresses-list.yml
exit 0
