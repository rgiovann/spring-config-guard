package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;

public final class CorsPermissiveMethodsAndHeadersRule implements Rule {

    private static final String ALLOWED_METHODS_KEY = "management.endpoints.web.cors.allowed-methods";
    private static final String EXPOSED_HEADERS_KEY = "management.endpoints.web.cors.exposed-headers";

    // 1. Effective exposure -> MEDIUM
    private static final Set<String> EFFECTIVE_SENSITIVE_HEADERS = Set.of(
            "authorization",
            "x-auth-token"
    );

    // 2. Ineffective browser blocks -> LOW
    private static final Set<String> FORBIDDEN_RESPONSE_HEADERS = Set.of(
            "set-cookie",
            "set-cookie2"
    );

    // 3. Direction anomaly (Request Header in Expose-Headers) -> INFO
    private static final Set<String> REQUEST_HEADERS_MISPLACED = Set.of(
            "cookie"
    );

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

            // Check 2: Categorized sensitive/misconfigured header analysis
            checkExposedHeaderCategories(value, config, findings);
        }
    }

    private void checkExposedHeaderCategories(String value, EffectiveConfig config, List<Finding> findings) {
        String[] tokens = value.split(",");

        for (String token : tokens) {
            String rawHeader = token.strip();
            String header = rawHeader.toLowerCase(Locale.ROOT);

            if (EFFECTIVE_SENSITIVE_HEADERS.contains(header)) {
                findings.add(new Finding(
                        id(),
                        Severity.MEDIUM,
                        ("Exposing sensitive response header '%s' via CORS in key '%s' allows client-side scripts " +
                                "from permitted origins to read authentication tokens.")
                                .formatted(rawHeader, EXPOSED_HEADERS_KEY),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            } else if (FORBIDDEN_RESPONSE_HEADERS.contains(header)) {
                findings.add(new Finding(
                        id(),
                        Severity.LOW,
                        ("Header '%s' in key '%s' is ineffective. Modern browsers treat Set-Cookie/Set-Cookie2 as " +
                                "forbidden response headers and strictly block client-side JavaScript access regardless of CORS rules.")
                                .formatted(rawHeader, EXPOSED_HEADERS_KEY),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            } else if (REQUEST_HEADERS_MISPLACED.contains(header)) {
                findings.add(new Finding(
                        id(),
                        Severity.INFO,
                        ("Header '%s' in key '%s' is a request header, not a response header. " +
                                "Including it in exposed-headers has no effect on CORS behavior.")
                                .formatted(rawHeader, EXPOSED_HEADERS_KEY),
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
}