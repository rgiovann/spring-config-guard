package dev.scg.benchmark.transport;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Creates an HTTP session on GET /session, so each scenario can read the session cookie it sets. */
@SpringBootApplication
@RestController
public class TransportApp {

    public static void main(String[] args) {
        SpringApplication.run(TransportApp.class, args);
    }

    @GetMapping("/session")
    String session(HttpServletRequest request) {
        return request.getSession(true).getId();
    }
}
