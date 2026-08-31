package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;

/**
 * SCG003 — detects the combination of wildcard CORS origin (allowed-origins/
 * allowed-origin-patterns = "*") with allow-credentials=true.
 * <p>
 * Scoped to management.endpoints.web.cors.* (Actuator) only. Spring MVC's
 * own CORS support (for application controllers, not Actuator endpoints)
 * has no native application.yml/.properties binding in vanilla Spring
 * Boot — it's configured programmatically via WebMvcConfigurer,
 * @CrossOrigin, or XML <mvc:cors>. Confirmed against the real Spring Boot
 * source (CorsEndpointProperties.java, spring-projects/spring-boot on
 * GitHub): only management.endpoints.web.cors is a real
 * @ConfigurationProperties-bound prefix. A prior version of this rule
 * also checked spring.mvc.cors.* under the assumption that Spring MVC
 * exposed an equivalent binding — it does not, so those keys never
 * matched anything in a real application and were removed.
 * <p>
 * Consequence: this rule (and, by the same reasoning, the sibling CORS
 * rules SCG004/SCG005) cannot detect insecure CORS configured
 * programmatically in application controllers — only Actuator's CORS,
 * which is the one surface actually exposed through config files.
 */
public final class CorsWildcardWithCredentialsRule implements Rule {

    private static final Set<String> ORIGIN_KEYS = Set.of(
            "management.endpoints.web.cors.allowed-origins",
            "management.endpoints.web.cors.allowed-origin-patterns"
    );

    private static final Set<String> CREDENTIALS_KEYS = Set.of(
            "management.endpoints.web.cors.allow-credentials"
    );

    @Override
    public String id() {
        return "SCG003";
    }

    @Override
    public String description() {
        return "CORS with global or pattern-based wildcard in allowed-origins/patterns combined with allow-credentials=true.";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        boolean hasCredentialsEnabled = CREDENTIALS_KEYS.stream()
                .map(key -> RelaxedProperties.get(config.properties(), key))
                .anyMatch(RelaxedBoolean::isTruthy);

        if (!hasCredentialsEnabled) {
            return findings;
        }

        for (String originKey : ORIGIN_KEYS) {
            List<String> values = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), originKey);

            WildcardScope wildcardScope = values.stream()
                    .map(this::classifyWildcard)
                    .max(WildcardScope::compareTo)
                    .orElse(WildcardScope.NONE);

            if (wildcardScope == WildcardScope.GLOBAL) {
                findings.add(new Finding(
                        id(),
                        Severity.HIGH,
                        ("Insecure CORS combination detected in key '%s': a global wildcard pattern allows credentialed " +
                                "requests from any host (*, https://*, etc.). This combination exposes the application " +
                                "to severe Cross-Site Request Forgery (CSRF) and session data leakage. " +
                                "Replace global wildcards with explicit origins or restricted domain patterns.")
                                .formatted(originKey),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            } else if (wildcardScope == WildcardScope.NON_GLOBAL) {
                findings.add(new Finding(
                        id(),
                        Severity.MEDIUM,
                        ("CORS origin pattern in key '%s' contains a domain-scoped wildcard while credential " +
                                "sending (allow-credentials) is enabled. This grants credentialed access to every " +
                                "matching subdomain. Review subdomain ownership and takeover risks, or use explicit origins.")
                                .formatted(originKey),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }

        return findings;
    }

    private WildcardScope classifyWildcard(String value) {
        if (value == null) {
            return WildcardScope.NONE;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        if (resolved.isEmpty()) {
            return WildcardScope.GLOBAL;
        }

        WildcardScope result = WildcardScope.NONE;
        for (String rawOrigin : resolved.get().split(",")) {
            String origin = rawOrigin.trim().toLowerCase(Locale.ROOT);
            WildcardScope scope = evaluateOriginScope(origin);

            if (scope == WildcardScope.GLOBAL) {
                return WildcardScope.GLOBAL;
            }
            if (scope == WildcardScope.NON_GLOBAL) {
                result = WildcardScope.NON_GLOBAL;
            }
        }
        return result;
    }

    private WildcardScope evaluateOriginScope(String origin) {
        if (!origin.contains("*")) {
            return WildcardScope.NONE;
        }

        // 1. Literal '*' puro
        if ("*".equals(origin)) {
            return WildcardScope.GLOBAL;
        }

        // Extrair apenas o host (removendo esquema HTTP/HTTPS/Wildcard-Scheme se presente)
        String host = origin;
        int schemeIdx = host.indexOf("://");
        if (schemeIdx != -1) {
            host = host.substring(schemeIdx + 3);
        }

        // Remover porta se presente
        int portIdx = host.indexOf(":");
        if (portIdx != -1) {
            host = host.substring(0, portIdx);
        }

        // 2. Sem host literal presente (ex: https://*, http://*, *://*) -> GLOBAL
        if ("*".equals(host)) {
            return WildcardScope.GLOBAL;
        }

        // 3. Qualquer outro padrão que contenha '*' com host literal -> NON_GLOBAL (MEDIUM)
        return WildcardScope.NON_GLOBAL;
    }

    private enum WildcardScope {
        NONE,
        NON_GLOBAL,
        GLOBAL
    }
}