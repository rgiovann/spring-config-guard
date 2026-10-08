package dev.scg.benchmark.kafkatls;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.kafka.core.KafkaAdmin;

/**
 * Opens one admin client with the configuration Spring Boot auto-configures for {@code KafkaAdmin}
 * (the {@code spring.kafka.*} properties and SSL bundles), asks for the cluster once and exits.
 * There is no broker: the scenario script listens with TLS and records whether the client finished
 * the handshake or refused the server's certificate.
 */
@SpringBootApplication
public class KafkaTlsApp {

    public static void main(String[] args) {
        System.exit(SpringApplication.exit(SpringApplication.run(KafkaTlsApp.class, args)));
    }

    @Bean
    ApplicationRunner connectOnce(KafkaAdmin kafkaAdmin) {
        return args -> {
            Map<String, Object> config = new HashMap<>(kafkaAdmin.getConfigurationProperties());
            config.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, 3000);
            config.put(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, 3000);
            try (AdminClient admin = AdminClient.create(config)) {
                admin.describeCluster().nodes().get(4, TimeUnit.SECONDS);
            } catch (Exception expected) {
                System.out.println("CONNECT-ATTEMPT-DONE: " + expected.getClass().getSimpleName());
            }
        };
    }
}
