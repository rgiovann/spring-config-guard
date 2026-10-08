package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * SCG006 — detects hardcoded credentials/secrets: an exact-match list of native Spring Boot
 * infrastructure properties ({@code high-risk-keys}) plus patterns for custom/third-party keys
 * that name a secret ({@code secret-key-patterns}).
 * Always {@link Severity#HIGH} for a concrete value; {@link Severity#INFO} for a blank
 * high-risk key, an unresolved/blank-default placeholder, or a key that only contains a pattern.
 * <p>
 * A custom key is reported as HIGH only when it <b>ends</b> in a pattern ({@code app.jwt.secret},
 * {@code ...registration.client-secret}), so the key names the secret itself. Matching a
 * pattern anywhere in the key reported, as HIGH, properties whose namespace, map key or package
 * name merely contains the word: checked against Spring Boot 4.1.1's own metadata and a
 * hand-built set, 18 of 20 non-secret properties were reported, e.g.
 * {@code spring.security.oauth2.authorizationserver.client.<id>.token.access-token-time-to-live=5m},
 * {@code spring.security.oauth2.resourceserver.opaquetoken.client-id},
 * {@code spring.cloud.kubernetes.secrets.namespace}. Every SCG006 finding on the reference corpus
 * already ended in a pattern. A key that contains a pattern without ending in it may still name
 * a secret ({@code app.secret-key-base}, {@code app.password-hash}, the plural
 * {@code app.api-keys}), so it is reported as {@link Severity#INFO} rather than silenced: visible
 * in the report, never failing a build on its own. Booleans, numbers ({@code max-tokens: 4000}),
 * blank values, ignored value prefixes and placeholders without a default stay silent there, since
 * none can be a hardcoded secret.
 * <p>
 * Keys under {@code ignored-key-prefixes} ({@code logging.level}, {@code logging.group}) are
 * skipped entirely: their last segment is a logger or package name, which can end in a pattern
 * ({@code logging.level.org.springframework.security.oauth2.server.authorization.token=DEBUG}),
 * and their value is never a secret.
 * <p>
 * Under {@code user-named-map-prefixes}, Spring Boot maps whose key is a name the application
 * chooses and whose value is an object Spring Boot defines (an OAuth2 client registration, an SSL
 * bundle), the map key doesn't count toward the INFO for a key that only contains a pattern. Each
 * field of such an object is a known property, and the field's own name says whether it holds a
 * secret: {@code registration.<id>.client-secret} ends in a pattern and is still HIGH, while
 * {@code client-id} or {@code scope} isn't one whatever the registration is named. Without this, a
 * registration named after its grant ({@code messaging-client-client-credentials}, in
 * spring-authorization-server's samples) made each of its fields an INFO, which a policy can only
 * suppress with the whole rule. A map the application defines ({@code app.secrets.github}) isn't
 * listed: its entries may be secrets, so they stay INFO.
 * <p>
 * Also accepted: a key that names a secret but holds a plain file path, e.g.
 * {@code server.ssl.certificate-private-key=/etc/tls/server.key}, is reported. Only prefixed
 * values are recognized as locations, since the same family of keys
 * ({@code spring.ssl.bundle.pem.*.private-key}) also accepts the PEM content itself.
 * <p>
 * Locations, refined after a real-world corpus run (session 2026-09-16 against
 * spring-projects/spring-boot's own source) surfaced false positives that a synthetic test suite
 * hadn't:
 * <ul>
 *     <li>Value-based. {@code ignored-value-prefixes}: {@code file:} points to secret material
 *     outside the application, and {@code {cipher}}/{@code {vault}}/{@code ENC(} are encrypted or
 *     managed values, so they are silent. {@code packaged-value-prefixes}: {@code classpath:}
 *     points to material packaged inside the jar, usually committed to the repository (SAML's
 *     {@code private-key-location}, the PEM SSL bundle's bare {@code private-key}), so it is
 *     {@link Severity#INFO}, not HIGH (the value isn't the secret) and not silent (the secret
 *     ships with the application).</li>
 *     <li>Key-based. {@code ignored-key-suffixes}: a key containing a pattern but ending in
 *     {@code -uri}/{@code -url}/{@code -endpoint} holds an address (OAuth2 Authorization Server's
 *     {@code token-uri} holds a path, not a token). The URL is still checked: a query string is
 *     INFO, anything else is silent. A credential written in the URL (user-info, a
 *     {@code password=} parameter) is SCG007's, which checks every property's value for it.
 *     {@code public-material-suffixes}: a key that only contains a pattern but ends in
 *     {@code certificate}/{@code certificate-location} names a certificate, public by design, so
 *     it is silent (SAML's {@code ...signing.credentials[0].certificate-location} contains the
 *     pattern only through its namespace).</li>
 * </ul>
 * <b>Known, deliberately accepted limitation</b> of the key-suffix mechanism: a secret embedded as
 * a path segment of a URL in such a key (e.g. a Slack/Discord webhook URL) is silent. Applying
 * the URL checks to <i>every</i> pattern match instead was rejected: a property named
 * {@code ...secret} or {@code ...password} holding such a webhook URL, reported as HIGH today,
 * would go silent. Detecting a secret by entropy inside a URL path segment is a generic
 * secret-scanner's job (GitLeaks, TruffleHog), not this tool's declared scope (Spring Boot
 * property-key semantics).
 */
public final class HardcodedSecretsRule implements ConfigurableRule {

    private Set<String> highRiskKeys;
    private List<String> secretKeyPatterns;
    private List<String> ignoredValuePrefixes;
    private List<String> packagedValuePrefixes;
    private List<String> ignoredKeySuffixes;
    private List<String> ignoredKeyPrefixes;
    private List<String> publicMaterialSuffixes;
    private List<String> userNamedMapPrefixes;
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
        List<String> rawPackagedPrefixes = metadata.getOrDefault("packaged-value-prefixes", List.of());
        List<String> rawIgnoredKeySuffixes = metadata.getOrDefault("ignored-key-suffixes", List.of());
        List<String> rawIgnoredKeyPrefixes = metadata.getOrDefault("ignored-key-prefixes", List.of());
        List<String> rawPublicMaterialSuffixes = metadata.getOrDefault("public-material-suffixes", List.of());
        List<String> rawUserNamedMapPrefixes = metadata.getOrDefault("user-named-map-prefixes", List.of());

        for (String prefix : rawIgnoredPrefixes) {
            if (prefix.contains("${")) {
                throw new IllegalArgumentException(
                        "Cannot include placeholder prefix '${' in 'ignored-value-prefixes'. " +
                                "Placeholders must be evaluated by EnvironmentPlaceholder resolution."
                );
            }
        }
        for (String prefix : rawPackagedPrefixes) {
            if (prefix.contains("${")) {
                throw new IllegalArgumentException(
                        "Cannot include placeholder prefix '${' in 'packaged-value-prefixes'. " +
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

        this.packagedValuePrefixes = rawPackagedPrefixes.stream()
                .map(String::strip)
                .toList();

        this.ignoredKeySuffixes = rawIgnoredKeySuffixes.stream()
                .map(RelaxedProperties::canonicalize)
                .toList();

        this.ignoredKeyPrefixes = rawIgnoredKeyPrefixes.stream()
                .map(RelaxedProperties::canonicalize)
                .toList();

        this.publicMaterialSuffixes = rawPublicMaterialSuffixes.stream()
                .map(RelaxedProperties::canonicalize)
                .toList();

        this.userNamedMapPrefixes = rawUserNamedMapPrefixes.stream()
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

            if (!isKnownHighRiskKey && !isCustomSecretKey) {
                if (containsSecretPattern(canonicalKey) && !namesPublicMaterial(canonicalKey)) {
                    Optional<Finding> finding = hasIgnoredKeySuffix(canonicalKey)
                            ? locationKeyFinding(config, entry.getKey(), rawValue)
                            : ambiguousKeyFinding(config, entry.getKey(), rawValue);
                    finding.ifPresent(findings::add);
                }
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

            if (isPackagedValue(valueToInspect)) {
                findings.add(packagedValueFinding(config, entry.getKey(), rawValue));
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

    /**
     * INFO for a key that contains a secret pattern without ending in it: it may name a secret
     * ({@code app.secret-key-base}, {@code app.password-hash}) or a setting
     * ({@code spring.cloud.kubernetes.secrets.namespace}), which static analysis can't tell
     * apart. Reported only for a value that could be a secret: blank values, booleans, numbers,
     * ignored value prefixes and placeholders without a default are skipped.
     */
    private Optional<Finding> ambiguousKeyFinding(EffectiveConfig config, String key, String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return Optional.empty();
        }
        String trimmedValue = rawValue.strip();
        Optional<String> resolved = EnvironmentPlaceholder.resolve(trimmedValue);
        if (isIgnoredValue(trimmedValue) || resolved.isEmpty()) {
            return Optional.empty();
        }
        String value = resolved.get();
        if (value.isBlank() || isIgnoredValue(value) || isBoolean(value) || isNumeric(value)) {
            return Optional.empty();
        }
        if (isPackagedValue(value)) {
            return Optional.of(packagedValueFinding(config, key, rawValue));
        }
        String message = ("Property '%s' contains a secret-related word but its name doesn't end in it, so static " +
                "analysis can't tell whether its value is a secret (e.g. 'app.secret-key-base') or a setting " +
                "(e.g. a namespace or a duration). If it holds a secret, inject it via environment variables " +
                "or a secret management system.").formatted(key);
        if (trimmedValue.contains("${")) {
            message += " The value originates from a static placeholder default ('%s').".formatted(rawValue);
        }
        return Optional.of(new Finding(id(), Severity.INFO, message,
                config.sourceFile().toString(), config.profileLabel()));
    }

    /**
     * A key that contains a secret pattern but ends in a location suffix ({@code token-uri},
     * {@code app.secret-url}) holds an address. A URL can still carry a secret: a credential
     * written in it is reported by SCG007 (EmbeddedCredentials), so it is left to that rule here; a
     * query string may hold a token or an API key (INFO); a secret in the path itself (a webhook URL) can't be told from an ordinary path
     * without entropy analysis, a generic secret scanner's job, so a URL with neither stays
     * silent.
     */
    private Optional<Finding> locationKeyFinding(EffectiveConfig config, String key, String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return Optional.empty();
        }
        String trimmedValue = rawValue.strip();
        Optional<String> resolved = EnvironmentPlaceholder.resolve(trimmedValue);
        if (resolved.isEmpty()) {
            return Optional.empty();
        }
        String value = resolved.get();
        String origin = trimmedValue.contains("${")
                ? " The value originates from a static placeholder default ('%s').".formatted(rawValue)
                : "";
        if (EmbeddedCredentials.find(value).stream().anyMatch(credential -> !credential.isBlank())) {
            return Optional.empty(); // a credential written in the URL is SCG007's to report
        }
        int query = value.indexOf('?');
        if (query >= 0 && query < value.length() - 1) {
            return Optional.of(new Finding(id(), Severity.INFO,
                    ("The URL in property '%s' carries a query string, which may hold a token or an API key; " +
                            "static analysis can't tell. If it does, inject it via environment variables or a " +
                            "secret management system.").formatted(key) + origin,
                    config.sourceFile().toString(), config.profileLabel()));
        }
        return Optional.empty();
    }

    /** INFO for secret material referenced from the classpath, i.e. packaged inside the application. */
    private Finding packagedValueFinding(EffectiveConfig config, String key, String rawValue) {
        return new Finding(id(), Severity.INFO,
                ("Property '%s' points to secret material packaged with the application ('%s'): a classpath " +
                        "resource ships inside the jar and is usually committed to the repository. Make sure it " +
                        "isn't a real key, or load it from outside the application (a file: path or a secret " +
                        "management system).").formatted(key, rawValue),
                config.sourceFile().toString(), config.profileLabel());
    }

    private boolean isPackagedValue(String value) {
        for (String prefix : packagedValuePrefixes) {
            if (value.startsWith(prefix)) {
                return true;
            }
        }
        return false;
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
                || packagedValuePrefixes == null || ignoredKeySuffixes == null || ignoredKeyPrefixes == null
                || publicMaterialSuffixes == null || userNamedMapPrefixes == null) {
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

    /**
     * Whether the key names public material ({@code ...certificate}, {@code ...certificate-location}),
     * e.g. SAML's {@code ...signing.credentials[0].certificate-location}, which contains the
     * {@code credentials} pattern only through its namespace. Applies to keys that don't end in a
     * pattern: a certificate is public by design, so neither it nor its location is a secret.
     */
    private boolean namesPublicMaterial(String canonicalKey) {
        for (String suffix : publicMaterialSuffixes) {
            if (canonicalKey.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsSecretPattern(String canonicalKey) {
        String keyWithoutMapKey = withoutUserNamedMapKey(canonicalKey);
        for (String pattern : secretKeyPatterns) {
            if (keyWithoutMapKey.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The key without the segment that names an entry of a {@code user-named-map-prefixes} map
     * ({@code spring.security.oauth2.client.registration.<id>.client-id} becomes
     * {@code spring.security.oauth2.client.registration.client-id}); any other key unchanged. Only
     * the first segment after the prefix is removed: a map key written with dots spans several,
     * and the ones after it still count, as before.
     */
    private String withoutUserNamedMapKey(String canonicalKey) {
        for (String prefix : userNamedMapPrefixes) {
            if (canonicalKey.startsWith(prefix + ".")) {
                int start = prefix.length() + 1;
                int end = canonicalKey.indexOf('.', start);
                return end < 0 ? prefix : prefix + canonicalKey.substring(end);
            }
        }
        return canonicalKey;
    }

    private static boolean isNumeric(String value) {
        return value.trim().matches("\\d+");
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

    /**
     * A word Spring reads as a boolean ({@code true}, {@code on}, {@code yes} and their opposites):
     * a switch such as {@code allow-credentials: on}, not a secret. {@code 1}/{@code 0}, which Spring
     * also reads as booleans, are left to the numeric check, so a numeric secret isn't missed.
     */
    private static boolean isBoolean(String value) {
        return (RelaxedBoolean.isTrueLiteral(value) || RelaxedBoolean.isFalseLiteral(value)) && !isNumeric(value);
    }
}