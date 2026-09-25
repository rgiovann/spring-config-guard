package dev.scg.benchmark.spring_env_benchmark;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds {@code app.bracket-map} so /actuator/configprops shows the map exactly as Spring's
 * Binder resolves it: entries merged key by key across base and profile, bracketed and dotted
 * spellings treated as the same key, precedence already applied. /actuator/env can't show that,
 * since it lists each property source's raw keys separately.
 */
@ConfigurationProperties("app")
public record BenchmarkProperties(Map<String, String> bracketMap) {
}
