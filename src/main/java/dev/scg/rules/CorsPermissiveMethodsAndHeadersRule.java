package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;

public final class CorsPermissiveMethodsAndHeadersRule implements Rule {

    private static final String ALLOWED_METHODS_KEY = "management.endpoints.web.cors.allowed-methods";
    private static final String EXPOSED_HEADERS_KEY = "management.endpoints.web.cors.exposed-headers";

    private static final Set<String> SENSITIVE_HEADERS = Set.of("authorization", "set-cookie");

    @Override
    public String id() {
        return "SCG005";
    }

    @Override
    public String description() {
        return "Permissive CORS configuration exposing all HTTP methods or sensitive/wildcard response headers";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        checkAllowedMethods(config, findings);
        checkExposedHeaders(config, findings);

        return findings;
    }

    private void checkAllowedMethods(EffectiveConfig config, List<Finding> findings) {
        List<String> rawValues = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), ALLOWED_METHODS_KEY);

        for (String rawValue : rawValues) {
            Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);
            if (resolved.isEmpty()) {
                findings.add(createUnresolvedPlaceholderFinding(ALLOWED_METHODS_KEY, rawValue, config));
                continue;
            }

            if (containsWildcard(resolved.get())) {
                findings.add(new Finding(
                        id(),
                        Severity.MEDIUM,
                        ("Permissive CORS allowed-methods detected in key '%s': wildcard '*' allows all HTTP verbs. " +
                                "Explicitly list only the required HTTP methods (e.g., GET, POST).")
                                .formatted(ALLOWED_METHODS_KEY),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }
    }

    private void checkExposedHeaders(EffectiveConfig config, List<Finding> findings) {
        List<String> rawValues = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), EXPOSED_HEADERS_KEY);

        for (String rawValue : rawValues) {
            Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);
            if (resolved.isEmpty()) {
                findings.add(createUnresolvedPlaceholderFinding(EXPOSED_HEADERS_KEY, rawValue, config));
                continue;
            }

            String value = resolved.get();

            // Check 1: Wildcard exposed headers (MEDIUM)
            if (containsWildcard(value)) {
                findings.add(new Finding(
                        id(),
                        Severity.MEDIUM,
                        ("Permissive CORS exposed-headers detected in key '%s': wildcard '*' attempts to expose all response headers. " +
                                "Explicitly list only safe operational headers (e.g., Content-Disposition).")
                                .formatted(EXPOSED_HEADERS_KEY),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }

            // Check 2: Explicit sensitive headers exposed (MEDIUM)
            List<String> foundSensitive = findSensitiveHeaders(value);
            if (!foundSensitive.isEmpty()) {
                findings.add(new Finding(
                        id(),
                        Severity.MEDIUM,
                        ("Sensitive response headers exposed via CORS in key '%s': [%s]. " +
                                "Exposing authentication or session tokens (Authorization/Set-Cookie) to client-side scripts increases XSS impact.")
                                .formatted(EXPOSED_HEADERS_KEY, String.join(", ", foundSensitive)),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }
    }

    private Finding createUnresolvedPlaceholderFinding(String key, String rawValue, EffectiveConfig config) {
        return new Finding(
                id(),
                Severity.INFO,
                ("CORS configuration key '%s' relies on an unresolved environment placeholder '%s'. " +
                        "Static analysis cannot determine the runtime CORS policy; " +
                        "verify this value in your deployment pipeline or secret manager.")
                        .formatted(key, rawValue),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }

    private boolean containsWildcard(String value) {
        String[] tokens = value.split(",");
        for (String token : tokens) {
            if ("*".equals(token.strip())) {
                return true;
            }
        }
        return false;
    }

    private List<String> findSensitiveHeaders(String value) {
        String[] tokens = value.split(",");
        List<String> detected = new ArrayList<>();

        for (String token : tokens) {
            String header = token.strip().toLowerCase(Locale.ROOT);
            if (SENSITIVE_HEADERS.contains(header)) {
                detected.add(token.strip());
            }
        }

        return detected;
    }
}