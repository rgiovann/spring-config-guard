package dev.scg.benchmark.kafka;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.kafka.autoconfigure.KafkaProperties;

/**
 * Which {@code security.protocol} each Kafka client gets from a set of {@code spring.kafka.*}
 * properties: the reference SCG014 is checked against (VALIDATION.md, "SCG014 protocol
 * precedence").
 * <p>
 * Each argument is one scenario, {@code name|key=value;key=value}. The properties are bound to
 * Spring Boot's own {@code KafkaProperties}, as the application context would, and each client's
 * configuration is built with {@code buildConsumerProperties()} and the others. "(unset)" means
 * the client falls back to kafka-clients' default, {@code PLAINTEXT}.
 */
public final class KafkaPrecedence {

    public static void main(String[] args) {
        for (String scenario : args) {
            String[] nameAndProperties = scenario.split("\\|", 2);
            Map<String, String> properties = new LinkedHashMap<>();
            for (String pair : nameAndProperties[1].split(";")) {
                String[] keyValue = pair.split("=", 2);
                properties.put(keyValue[0].strip(), keyValue[1].strip());
            }
            KafkaProperties kafka = new Binder(new MapConfigurationPropertySource(properties))
                    .bind("spring.kafka", KafkaProperties.class)
                    .orElseGet(KafkaProperties::new);

            Map<String, Map<String, Object>> clients = new LinkedHashMap<>();
            clients.put("consumer", kafka.buildConsumerProperties());
            clients.put("producer", kafka.buildProducerProperties());
            clients.put("admin", kafka.buildAdminProperties());
            clients.put("streams", kafka.buildStreamsProperties());

            StringBuilder line = new StringBuilder(String.format("%-4s", nameAndProperties[0]));
            clients.forEach((client, config) -> line.append(String.format(" %s=%-10s", client,
                    config.getOrDefault("security.protocol", "(unset)"))));
            System.out.println(line.toString().stripTrailing());
        }
    }
}
