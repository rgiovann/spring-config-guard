package dev.scg.benchmark.rabbit;

import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Opens one connection with the auto-configured ConnectionFactory at startup and exits. There is no
 * broker: the scenario script listens on the broker's ports and records whether the client spoke
 * plain AMQP or started a TLS handshake.
 */
@SpringBootApplication
public class RabbitApp {

    public static void main(String[] args) {
        System.exit(SpringApplication.exit(SpringApplication.run(RabbitApp.class, args)));
    }

    @Bean
    ApplicationRunner connectOnce(ConnectionFactory connectionFactory) {
        return args -> {
            try {
                connectionFactory.createConnection().close();
            } catch (RuntimeException expected) {
                System.out.println("CONNECT-ATTEMPT-DONE: " + expected.getClass().getSimpleName());
            }
        };
    }
}
