// FILE: CorsPermissiveMethodsAndHeadersRule.java
// PACKAGE: dev.scg.rules

package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class CorsPermissiveMethodsAndHeadersRule implements Rule {

    private static final Set<String> METHODS_KEYS = Set.of(
            "spring.mvc.cors.allowed-methods",
            "management.endpoints.web.cors.allowed-methods"
    );

    private static final Set<String> EXPOSED_HEADERS_KEYS = Set.of(
            "spring.mvc.cors.exposed-headers",
            "management.endpoints.web.cors.exposed-headers"
    );

    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            "authorization", "set-cookie", "cookie", "x-auth-token"
    );

    @Override
    public String id() {
        return "SCG005";
    }

    @Override
    public String description() {
        return "Permissive HTTP method configuration or exposure of sensitive headers in CORS";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        checkAllowedMethods(config, findings);
        checkExposedHeaders(config, findings);

        return findings;
    }

    private void checkAllowedMethods(EffectiveConfig config, List<Finding> findings) {
        for (String key : METHODS_KEYS) {
            List<String> values = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), key);

            boolean hasWildcard = values.stream().anyMatch(val -> {
                Optional<String> res = EnvironmentPlaceholder.resolve(val);
                return res.map(s -> s.trim().equals("*") || s.contains("*")).orElse(true);
            });

            if (hasWildcard) {
                findings.add(new Finding(
                        id(),
                        Severity.MEDIUM,
                        ("Key '%s' allows all HTTP methods via wildcard (*). " +
                                "This exposes the application to cross-origin requests using unintended methods. " +
                                "Specify only the required methods (e.g., GET, POST, PUT).")
                                .formatted(key),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }
    }

    private void checkExposedHeaders(EffectiveConfig config, List<Finding> findings) {
        for (String key : EXPOSED_HEADERS_KEYS) {
            List<String> values = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), key);

            for (String rawValue : values) {
                if (rawValue == null) continue;

                Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);
                if (resolved.isEmpty()) continue;

                String value = resolved.get();
                List<String> sensitiveFound = findSensitiveHeaders(value);

                if (!sensitiveFound.isEmpty()) {
                    findings.add(new Finding(
                            id(),
                            Severity.MEDIUM,
                            ("Key '%s' exposes authentication/session headers to cross-origin reads: %s. " +
                                    "This increases the risk of credential leakage through third-party scripts in the browser.")
                                    .formatted(key, String.join(", ", sensitiveFound)),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                } else if (value.trim().equals("*")) {
                    findings.add(new Finding(
                            id(),
                            Severity.LOW,
                            ("Key '%s' exposes all response headers via wildcard (*). " +
                                    "Avoid exposing headers globally and restrict them to only the necessary operational headers.")
                                    .formatted(key),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                }
            }
        }
    }

    private List<String> findSensitiveHeaders(String headerValue) {
        String[] tokens = headerValue.split(",");
        List<String> found = new ArrayList<>();

        for (String token : tokens) {
            String header = token.strip().toLowerCase();
            if (SENSITIVE_HEADERS.contains(header)) {
                found.add(token.strip());
            }
        }

        return found;
    }
}