package dev.scg.benchmark.error;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;

/**
 * Two endpoints that fail, so the error response shows what each error property adds:
 * GET /boom throws an exception whose message is an internal detail, GET /bind?qty=abc fails
 * binding a request parameter.
 */
@SpringBootApplication
public class ErrorApp {

    public static void main(String[] args) {
        SpringApplication.run(ErrorApp.class, args);
    }

    public record Form(Integer qty) {
    }

    @RestController
    static class Failing {

        @GetMapping("/boom")
        String boom() {
            throw new IllegalStateException("internal-detail-db-orders-primary");
        }

        @GetMapping("/bind")
        String bind(@ModelAttribute Form form) {
            return String.valueOf(form.qty());
        }
    }
}
