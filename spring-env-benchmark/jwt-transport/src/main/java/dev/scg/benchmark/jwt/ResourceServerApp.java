package dev.scg.benchmark.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A resource server with one protected endpoint, GET /api. Spring Boot configures token
 * validation from the scenario's properties; the scenario script sends one request with a bearer
 * token, which makes the app fetch its keys, OIDC metadata or token introspection from the
 * configured URIs, where a listener records whether it spoke plain HTTP or TLS.
 */
@SpringBootApplication
public class ResourceServerApp {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerApp.class, args);
    }

    @RestController
    static class Api {

        @GetMapping("/api")
        String api() {
            return "ok";
        }
    }
}
