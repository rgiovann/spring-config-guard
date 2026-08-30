package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class CorsWildcardWithCredentialsRule implements Rule {

    private static final Set<String> ORIGIN_KEYS = Set.of(
            "spring.mvc.cors.allowed-origins",
            "spring.mvc.cors.allowed-origin-patterns",
            "management.endpoints.web.cors.allowed-origins",
            "management.endpoints.web.cors.allowed-origin-patterns"
    );

    private static final Set<String> CREDENTIALS_KEYS = Set.of(
            "spring.mvc.cors.allow-credentials",
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

        // 1. Verifica se allow-credentials está habilitado em alguma chave relevante
        boolean hasCredentialsEnabled = CREDENTIALS_KEYS.stream()
                .map(key -> RelaxedProperties.get(config.properties(), key))
                .anyMatch(RelaxedBoolean::isTruthy);

        if (!hasCredentialsEnabled) {
            return findings;
        }

        // 2. Look for wildcards in allowed-origin configurations
        for (String originKey : ORIGIN_KEYS) {
            List<String> values = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), originKey);

            boolean containsWildcard = values.stream().anyMatch(this::mayContainWildcard);

            if (containsWildcard) {
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
            }
        }

        return findings;
    }

    private boolean mayContainWildcard(String value) {
        if (value == null) {
            return false;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        if (resolved.isEmpty()) {
            // Dynamic placeholder without a default: we assume the worst-case scenario (engine security posture)
            return true;
        }

        String resolvedValue = resolved.get().trim();
        return resolvedValue.contains("*");
    }
}