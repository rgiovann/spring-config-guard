package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

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
        return "CORS with wildcard (*) in allowed-origins/patterns combined with allow-credentials=true.";
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
                        ("Insecure CORS combination detected: the key '%s' allows a wildcard (*), " +
                                "while credential sending (allow-credentials) is enabled as 'true'. " +
                                "This combination is invalid/dangerous and exposes the application to Cross-Site Request Forgery (CSRF) attacks and session data leakage. " +
                                "Replace '*' with explicit origins or disable allow-credentials.")
                                .formatted(originKey),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            } else if (wildcardScope == WildcardScope.NON_GLOBAL) {
                findings.add(new Finding(
                        id(),
                        Severity.MEDIUM,
                        ("CORS origin pattern in key '%s' contains a domain-scoped wildcard while " +
                                "credential sending (allow-credentials) is enabled. This is narrower than allowing " +
                                "every origin, but grants credentialed access to every matching subdomain. " +
                                "Review the ownership and takeover risk of those subdomains, or use explicit origins.")
                                .formatted(originKey),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }

        return findings;
    }

    /**
     * A literal "*" grants access to any origin and is therefore HIGH risk.
     * Patterns such as "https://*.example.com" are intentionally classified
     * separately: Spring matches only origins in that domain, so treating them
     * as equivalent to the global wildcard would overstate the risk.
     */
    private WildcardScope classifyWildcard(String value) {
        if (value == null) {
            return WildcardScope.NONE;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        if (resolved.isEmpty()) {
            // The runtime value cannot be verified and may be the global wildcard.
            return WildcardScope.GLOBAL;
        }

        WildcardScope result = WildcardScope.NONE;
        for (String rawOrigin : resolved.get().split(",")) {
            String origin = rawOrigin.trim();
            if (origin.equals("*")) {
                return WildcardScope.GLOBAL;
            }
            if (origin.contains("*")) {
                result = WildcardScope.NON_GLOBAL;
            }
        }
        return result;
    }

    private enum WildcardScope {
        NONE,
        NON_GLOBAL,
        GLOBAL
    }
}
