package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;
import java.util.stream.Collectors;

public final class HardcodedSecretsRule implements ConfigurableRule {

    private Set<String> highRiskKeys;
    private List<String> secretKeyPatterns;
    private List<String> ignoredValuePrefixes;
    private static final String RULE_NAME = "SCG006";
    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Hardcoded plaintext credentials or sensitive secrets in configuration files";
    }

    @Override
    public void configure(Map<String, List<String>> metadata) {
        Objects.requireNonNull(metadata, RULE_NAME + " metadata map cannot be null");

        List<String> rawHighRisk = metadata.get("high-risk-keys");
        List<String> rawPatterns = metadata.get("secret-key-patterns");
        List<String> rawIgnoredPrefixes = metadata.getOrDefault("ignored-value-prefixes", List.of());

        for (String prefix : rawIgnoredPrefixes) {
            if (prefix.contains("${")) {
                throw new IllegalArgumentException(
                        "Cannot include placeholder prefix '${' in 'ignored-value-prefixes'. " +
                                "Placeholders must be evaluated by EnvironmentPlaceholder resolution."
                );
            }
        }

        if (rawHighRisk == null || rawHighRisk.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'high-risk-keys' is missing or empty.");
        }
        if (rawPatterns == null || rawPatterns.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'secret-key-patterns' is missing or empty.");
        }

        // Canonicalizes all keys and patterns only once at startup.
        this.highRiskKeys = rawHighRisk.stream()
                .map(RelaxedProperties::canonicalize)
                .collect(Collectors.toUnmodifiableSet());

        this.secretKeyPatterns = rawPatterns.stream()
                .map(RelaxedProperties::canonicalize)
                .toList();

        this.ignoredValuePrefixes = rawIgnoredPrefixes.stream()
                .map(String::strip)
                .toList();
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        ensureConfigured();

        List<Finding> findings = new ArrayList<>();

        for (Map.Entry<String, String> entry : config.properties().entrySet()) {
            String rawValue = entry.getValue();

            if (rawValue == null || rawValue.isBlank()) {
                continue;
            }

            String trimmedValue = rawValue.strip();

            // Checagem dinamica contra a lista do YAML
            if (isIgnoredValue(trimmedValue)) {
                continue;
            }

            String canonicalKey = RelaxedProperties.canonicalize(entry.getKey());

            boolean isKnownHighRiskKey = highRiskKeys.contains(canonicalKey);
            boolean isCustomSecretKey = !isKnownHighRiskKey && matchesSecretPattern(canonicalKey);

            if (isKnownHighRiskKey || isCustomSecretKey) {
                Optional<String> resolvedValue = EnvironmentPlaceholder.resolve(trimmedValue);

                // Padrão de observabilidade: Notifica INFO quando não é possível avaliar estaticamente
                if (resolvedValue.isEmpty()) {
                    findings.add(new Finding(
                            id(),
                            Severity.INFO,
                            ("Sensitive property '%s' relies on an unresolved environment placeholder '%s'. " +
                                    "Static analysis cannot verify the runtime value; " +
                                    "ensure production secrets are injected securely via environment variables or a secret manager.")
                                    .formatted(entry.getKey(), rawValue),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                    continue;
                }

                String valueToInspect = resolvedValue.get();

                if (!valueToInspect.isBlank()) {
                    findings.add(new Finding(
                            id(),
                            Severity.HIGH,
                            ("Hardcoded secret or static default fallback detected in property '%s'. " +
                                    "Avoid storing credentials in plaintext files or default placeholder values; " +
                                    "use environment variables or a secret management system (e.g., Vault, AWS Secrets Manager).")
                                    .formatted(entry.getKey()),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                } else {
                    // ${VAR:} — the placeholder WAS resolved, its declared default is just an
                    // empty string. Distinct from the unresolvable case above: here we know the
                    // static value (empty), we just don't know what the env var holds at runtime.
                    findings.add(new Finding(
                            id(),
                            Severity.INFO,
                            ("Sensitive property '%s' declares an empty default fallback for its environment placeholder '%s'. " +
                                    "Static analysis cannot verify the runtime value if the environment variable is unset; " +
                                    "ensure production secrets are injected securely via environment variables or a secret manager.")
                                    .formatted(entry.getKey(), rawValue),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                }
            }
        }

        return findings;
    }

    private boolean isIgnoredValue(String value) {
        for (String prefix : ignoredValuePrefixes) {
            if (value.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private void ensureConfigured() {
        if (highRiskKeys == null || secretKeyPatterns == null || ignoredValuePrefixes == null) {
            throw new IllegalStateException("Rule " + RULE_NAME + " must be configured before execution.");
        }
    }

    private boolean matchesSecretPattern(String canonicalKey) {
        for (String pattern : secretKeyPatterns) {
            if (canonicalKey.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
}