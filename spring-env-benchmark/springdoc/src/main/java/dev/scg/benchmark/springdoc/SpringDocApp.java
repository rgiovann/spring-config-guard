package dev.scg.benchmark.springdoc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/** One documented endpoint, GET /api/orders/{id}, so a served spec can be told from an empty one. */
@SpringBootApplication
public class SpringDocApp {

    public static void main(String[] args) {
        SpringApplication.run(SpringDocApp.class, args);
    }

    @RestController
    static class Orders {

        @GetMapping("/api/orders/{id}")
        String order(@PathVariable String id) {
            return id;
        }
    }
}
