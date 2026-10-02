package dev.scg.benchmark.transport;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

/** Spring Session with an in-memory repository: its own session cookie replaces the container's. */
@Configuration
@EnableSpringHttpSession
class SessionConfig {

    @Bean
    MapSessionRepository sessionRepository() {
        return new MapSessionRepository(new ConcurrentHashMap<>());
    }
}
