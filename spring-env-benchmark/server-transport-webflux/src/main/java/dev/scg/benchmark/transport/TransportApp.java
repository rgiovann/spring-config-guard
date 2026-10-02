package dev.scg.benchmark.transport;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

/** Starts a WebSession on GET /session, so each scenario can read the session cookie it sets. */
@SpringBootApplication
@RestController
public class TransportApp {

    public static void main(String[] args) {
        SpringApplication.run(TransportApp.class, args);
    }

    @GetMapping("/session")
    Mono<String> session(WebSession session) {
        session.getAttributes().put("started", true);
        return Mono.just(session.getId());
    }
}
