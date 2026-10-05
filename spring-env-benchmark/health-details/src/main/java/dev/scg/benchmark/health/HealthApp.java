package dev.scg.benchmark.health;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** A web app with Actuator and an H2 datasource, so /actuator/health has db and diskSpace components. */
@SpringBootApplication
public class HealthApp {

    public static void main(String[] args) {
        SpringApplication.run(HealthApp.class, args);
    }
}
