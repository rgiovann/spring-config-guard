#!/bin/bash
# Which security.protocol each Kafka client gets, one configuration at a time: the reference SCG014
# is checked against (VALIDATION.md, "SCG014 protocol precedence").
#
# Each scenario binds its properties to Spring Boot 4.1.1's KafkaProperties (kafka-precedence/, a
# separate project so this benchmark app doesn't auto-configure Kafka) and prints the protocol each
# client's configuration gets; "(unset)" falls back to kafka-clients' default, PLAINTEXT.
set -eu
cd "$(dirname "$0")/kafka-precedence"
mvn -q compile dependency:build-classpath -Dmdep.outputFile=target/classpath.txt
K=spring.kafka

java -cp "target/classes:$(cat target/classpath.txt)" dev.scg.benchmark.kafka.KafkaPrecedence \
    "P1|$K.security.protocol=PLAINTEXT;$K.properties.security.protocol=SSL" \
    "P2|$K.security.protocol=SSL;$K.properties.security.protocol=PLAINTEXT" \
    "P3|$K.consumer.security.protocol=SSL;$K.properties.security.protocol=PLAINTEXT" \
    "P4|$K.consumer.security.protocol=PLAINTEXT;$K.consumer.properties.security.protocol=SSL" \
    "P5|$K.security.protocol=PLAINTEXT;$K.consumer.security.protocol=SSL;$K.producer.security.protocol=SSL;$K.admin.security.protocol=SSL;$K.streams.security.protocol=SSL" \
    "P6|$K.consumer.security.protocol=SSL" \
    "P7|$K.consumer.security.protocol=SSL;$K.producer.security.protocol=SSL;$K.admin.security.protocol=SSL" \
    "X1|$K.consumer.security.protocol=SSL;$K.consumer.properties.security.protocol=PLAINTEXT" \
    "X2|$K.consumer.security.protocol=PLAINTEXT;$K.properties.security.protocol=SSL" \
    2>&1 | grep -v '^SLF4J'
