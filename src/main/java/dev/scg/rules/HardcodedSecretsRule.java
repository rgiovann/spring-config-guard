package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * SCG006 — detects hardcoded credentials/secrets: an exact-match list of native Spring Boot
 * infrastructure properties ({@code high-risk-keys}) plus patterns for custom/third-party keys
 * that name a secret ({@code secret-key-patterns}).
 * Always {@link Severity#HIGH} for a concrete value; {@link Severity#INFO} for a blank
 * high-risk key or an unresolved/blank-default placeholder.
 * <p>
 * A custom key matches only when it <b>ends</b> in a pattern ({@code app.jwt.secret},
 * {@code ...registration.client-secret}), so the key names the secret itself. Matching a
 * pattern anywhere in the key reported, as HIGH, properties whose namespace, map key or package
 * name merely contains the word: checked against Spring Boot 4.1.1's own metadata and a
 * hand-built set, 18 of 20 non-secret properties were reported, e.g.
 * {@code spring.security.oauth2.authorizationserver.client.<id>.token.access-token-time-to-live=5m},
 * {@code spring.security.oauth2.resourceserver.opaquetoken.client-id},
 * {@code spring.cloud.kubernetes.secrets.namespace}. Every SCG006 finding on the reference corpus
 * already ended in a pattern. The accepted cost: a secret whose key carries the word before
 * another one ({@code app.secret-key-base}, {@code app.password-hash}) or in the plural
 * ({@code app.api-keys}) is no longer reported. Patterns are not matched in the plural on
 * purpose: {@code token} would then match {@code max-tokens: 4000}.
 * <p>
 * Keys under {@code ignored-key-prefixes} ({@code logging.level}, {@code logging.group}) are
 * skipped entirely: their last segment is a logger or package name, which can end in a pattern
 * ({@code logging.level.org.springframework.security.oauth2.server.authorization.token=DEBUG}),
 * and their value is never a secret.
 * <p>
 * Also accepted: a key that names a secret but holds a plain file path, e.g.
 * {@code server.ssl.certificate-private-key=/etc/tls/server.key}, is reported. Only
 * {@code classpath:}/{@code file:} values are recognized as locations, since the same family of
 * keys ({@code spring.ssl.bundle.pem.*.private-key}) also accepts the PEM content itself.
 * <p>
 * Two suppression mechanisms, both added after a real-world corpus run (session 2026-09-16
 * against spring-projects/spring-boot's own source) surfaced false positives that a
 * synthetic test suite hadn't:
 * <ul>
 *     <li>{@code ignored-value-prefixes} (value-based): {@code classpath:}/{@code file:} mean
 *     the value is a *reference* to where secret material lives, not the material itself
 *     (SAML's {@code certificate-location}, the PEM SSL bundle's bare {@code private-key}).</li>
 *     <li>{@code ignored-key-suffixes} (key-based): {@code -uri}/{@code -url}/{@code -endpoint}
 *     mean the property is a network location, not a value (OAuth2 Authorization Server's
 *     {@code token-uri}/{@code token-revocation-uri} matched the {@code token} pattern despite
 *     holding a path, not a token).</li>
 * </ul>
 * <b>Known, deliberately accepted limitation</b> of the key-suffix mechanism: a property whose
 * key ends in {@code -uri}/{@code -url}/{@code -endpoint} AND whose value is itself a secret
 * (e.g. a Slack/Discord webhook URL, which embeds its credential as a path segment rather than
 * a query param or userinfo) is also silenced. A value-based alternative (checking the value for
 * "no {@code ?}, no {@code @}") was considered and rejected: it would apply to *every*
 * secret-key-patterns match, not just {@code -uri}/{@code -url}/{@code -endpoint} ones, so a
 * property literally named {@code ...secret} or {@code ...password} holding that same kind of
 * webhook URL would also go silent — a broader and more dangerous blind spot than this rule
 * accepts today. Detecting a secret by entropy inside a URL path segment is a generic
 * secret-scanner's job (GitLeaks, TruffleHog), not this tool's declared scope (Spring Boot
 * property-key semantics).
 */
public final class HardcodedSecretsRule implements ConfigurableRule {

    private Set<String> highRiskKeys;
    private List<String> secretKeyPatterns;
    private List<String> ignoredValuePrefixes;
    private List<String> ignoredKeySuffixes;
    private List<String> ignoredKeyPrefixes;
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
        List<String> rawIgnoredKeySuffixes = metadata.getOrDefault("ignored-key-suffixes", List.of());
        List<String> rawIgnoredKeyPrefixes = metadata.getOrDefault("ignored-key-prefixes", List.of());

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

        this.highRiskKeys = rawHighRisk.stream()
                .map(RelaxedProperties::canonicalize)
                .collect(Collectors.toUnmodifiableSet());

        this.secretKeyPatterns = rawPatterns.stream()
                .map(RelaxedProperties::canonicalize)
                .toList();

        this.ignoredValuePrefixes = rawIgnoredPrefixes.stream()
                .map(String::strip)
                .toList();

        this.ignoredKeySuffixes = rawIgnoredKeySuffixes.stream()
                .map(RelaxedProperties::canonicalize)
                .toList();

        this.ignoredKeyPrefixes = rawIgnoredKeyPrefixes.stream()
                .map(RelaxedProperties::canonicalize)
                .toList();
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        ensureConfigured();

        List<Finding> findings = new ArrayList<>();

        for (Map.Entry<String, String> entry : config.properties().entrySet()) {
            String rawValue = entry.getValue();

            String canonicalKey = RelaxedProperties.canonicalize(entry.getKey());
            if (hasIgnoredKeyPrefix(canonicalKey)) {
                continue;
            }
            boolean isKnownHighRiskKey = highRiskKeys.contains(canonicalKey);
            boolean isCustomSecretKey = !isKnownHighRiskKey
                    && namesTheSecret(canonicalKey)
                    && !hasIgnoredKeySuffix(canonicalKey);

            //Skips properties that don't match either native keys or secret patterns.
            if (!isKnownHighRiskKey && !isCustomSecretKey) {
                continue;
            }

            // Handles missing values ​​/ blank values
            if (rawValue == null || rawValue.isBlank()) {
                // Emits INFO (CWE-258) only for native infrastructure keys
                if (isKnownHighRiskKey) {
                    findings.add(new Finding(
                            id(),
                            Severity.INFO,
                            ("Core Spring Boot sensitive property '%s' is declared blank in configuration. " +
                                    "Ensure credentials are injected securely via environment variables or a secret manager at runtime.")
                                    .formatted(entry.getKey()),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                }
                // Blank generic patterns (secret-key-patterns) continue to be silently discarded.
                continue;
            }

            String trimmedValue = rawValue.strip();

            // Dynamic check against the YAML list
            if (isIgnoredValue(trimmedValue)) {
                continue;
            }

            Optional<String> resolvedValue = EnvironmentPlaceholder.resolve(trimmedValue);

            // Observability pattern: Notifies INFO when it is not possible to evaluate statically
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

            // If the resolved value (e.g., the placeholder default) is an ignored prefix (e.g., {cipher}), skip the rule.
            if (isIgnoredValue(valueToInspect)) {
                continue;
            }

            // A boolean in a custom key is a switch, not a secret (require-password: true).
            // Checked against the RESOLVED value so it applies equally to a bare literal and to a
            // placeholder's static default. A numeric value is reported: the key names the secret,
            // so the number is the secret (ssl.keystore.password: 123456, found in
            // spring-cloud-stream-samples).
            if (isCustomSecretKey && isBoolean(valueToInspect)) {
                continue;
            }

            if (!valueToInspect.isBlank()) {
                boolean isFromPlaceholderDefault = trimmedValue.contains("${");

                findings.add(new Finding(
                        id(),
                        Severity.HIGH,
                        buildHardcodedCredentialMessage(entry.getKey(), rawValue, isKnownHighRiskKey, isFromPlaceholderDefault),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            } else {
                // ${VAR:} — the placeholder WAS resolved, its declared default is just an empty string.
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
        if (highRiskKeys == null || secretKeyPatterns == null || ignoredValuePrefixes == null
                || ignoredKeySuffixes == null || ignoredKeyPrefixes == null) {
            throw new IllegalStateException("Rule " + RULE_NAME + " must be configured before execution.");
        }
    }

    private String buildHardcodedCredentialMessage(
            String key, String rawValue, boolean isKnownHighRiskKey, boolean isFromPlaceholderDefault
    ) {
        String base = isKnownHighRiskKey
                ? ("Hardcoded credential detected in core Spring Boot property '%s'. " +
                "Never store infrastructure credentials in plaintext configuration files; " +
                "inject them dynamically via environment variables or a secret management system (e.g., Vault, AWS Secrets Manager).")
                .formatted(key)
                : ("Hardcoded secret detected matching custom key pattern in property '%s'. " +
                "Avoid storing application secrets or API keys in plaintext configuration files; " +
                "use environment variables or a secret management system.")
                .formatted(key);

        if (!isFromPlaceholderDefault) {
            return base;
        }
        return base + " The value originates from a static placeholder default ('%s').".formatted(rawValue);
    }

    /** Whether the key ends in a secret pattern (e.g. {@code ...keystore.password}), naming the secret itself. */
    private boolean namesTheSecret(String canonicalKey) {
        for (String pattern : secretKeyPatterns) {
            if (canonicalKey.endsWith(pattern)) {
                return true;
            }
        }
        return false;
    }

    /** Whether the key is one of {@code ignored-key-prefixes} or under it, on a {@code .} boundary. */
    private boolean hasIgnoredKeyPrefix(String canonicalKey) {
        for (String prefix : ignoredKeyPrefixes) {
            if (canonicalKey.equals(prefix) || canonicalKey.startsWith(prefix + ".")) {
                return true;
            }
        }
        return false;
    }

    private boolean hasIgnoredKeySuffix(String canonicalKey) {
        for (String suffix : ignoredKeySuffixes) {
            if (canonicalKey.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isBoolean(String value) {
        String trimmed = value.trim();
        return trimmed.equalsIgnoreCase("true") || trimmed.equalsIgnoreCase("false");
    }
}