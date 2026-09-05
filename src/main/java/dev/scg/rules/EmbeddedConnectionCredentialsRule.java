package dev.scg.rules;


import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Security rule (SCG007) that detects hardcoded plaintext credentials embedded within
 * connection strings, database URIs, and JAAS configurations.
 *
 * <p>This rule inspects properties defined in {@code uri-based} and {@code jaas-based} targets.
 * It enforces a strict Zero-Trust approach across all execution profiles, flagging static
 * credentials in URI user-info sections (e.g., JDBC, R2DBC, Redis, MongoDB) as well as
 * explicitly declared passwords in JAAS modules (e.g., Kafka SASL).</p>
 *
 * <p>Placeholder defaults (e.g., {@code ${DB_PASS:hardcoded123}}) are also evaluated
 * and reported as high-severity violations when static fallback credentials are exposed.</p>
 *
 * @see ConfigurableRule
 * @see EnvironmentPlaceholder
 */
public final class EmbeddedConnectionCredentialsRule implements ConfigurableRule {

    private static final String RULE_NAME = "SCG007";

    // Pattern for capturing passwords in jaas.config (e.g., password="myPassword" or password='myPassword').
    // Capture group uses '*' (not '+') so a present-but-empty credential (password="") still matches —
    // distinguishing "no password field at all" from "password field present, resolved to empty".
    private static final Pattern JAAS_PASSWORD_PATTERN = Pattern.compile("password\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

    // Captures any format <schema>://<user>:<password>@<host>
    // Ignores prefixes like jdbc:, r2dbc:, pool:, etc.
    // Capture group uses '*' for the same reason as JAAS_PASSWORD_PATTERN above (e.g. "user:@host").
    private static final Pattern EMBEDDED_URI_PASSWORD_PATTERN =
            Pattern.compile("://[^:@]*:([^@]*)@", Pattern.CASE_INSENSITIVE);

    private Set<String> uriBasedKeys;
    private Set<String> jaasBasedKeys;

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Embedded plaintext credentials in connection URIs or JAAS configurations";
    }

    @Override
    public void configure(Map<String, List<String>> metadata) {
        Objects.requireNonNull(metadata, RULE_NAME + " metadata map cannot be null");

        List<String> rawUriKeys = metadata.get("uri-based");
        List<String> rawJaasKeys = metadata.get("jaas-based");

        if (rawUriKeys == null || rawUriKeys.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'uri-based' is missing or empty.");
        }
        if (rawJaasKeys == null || rawJaasKeys.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'jaas-based' is missing or empty.");
        }

        this.uriBasedKeys = rawUriKeys.stream()
                .map(RelaxedProperties::canonicalize)
                .collect(Collectors.toUnmodifiableSet());

        this.jaasBasedKeys = rawJaasKeys.stream()
                .map(RelaxedProperties::canonicalize)
                .collect(Collectors.toUnmodifiableSet());
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

            String canonicalKey = RelaxedProperties.canonicalize(entry.getKey());
            boolean isUriTarget = uriBasedKeys.contains(canonicalKey);
            boolean isJaasTarget = jaasBasedKeys.contains(canonicalKey);

            if (!isUriTarget && !isJaasTarget) {
                continue;
            }

            String trimmedValue = rawValue.strip();

            // 1. Resolve os placeholders com seus defaults estáticos
            Optional<String> resolvedValue = EnvironmentPlaceholder.resolve(trimmedValue);

            // Se o placeholder for completamente irresolvível e sem default -> INFO
            if (resolvedValue.isEmpty()) {
                findings.add(new Finding(
                        id(),
                        Severity.INFO,
                        ("Connection property '%s' relies on an unresolved environment placeholder '%s'. " +
                                "Static analysis cannot verify the runtime value; ensure credentials are injected securely.")
                                .formatted(entry.getKey(), rawValue),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
                continue;
            }

            String valueToInspect = resolvedValue.get();

            // ${VAR:} — the WHOLE property value was a placeholder that resolved to an empty
            // default. Distinct from the unresolvable case above: here the static value is known
            // (empty), we just don't know what the env var holds at runtime. Mirrors SCG006's
            // handling of the same placeholder shape.
            if (valueToInspect.isBlank()) {
                findings.add(new Finding(
                        id(),
                        Severity.INFO,
                        ("Connection property '%s' declares an empty default fallback for its environment placeholder '%s'. " +
                                "Static analysis cannot verify the runtime value if the environment variable is unset; " +
                                "ensure credentials are injected securely via environment variables or a secret manager.")
                                .formatted(entry.getKey(), rawValue),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
                continue;
            }

            // 2. Extract the credential (if there is a slot for it) in the resolved value
            Optional<String> extractedCredential = isUriTarget
                    ? extractUriCredential(valueToInspect)
                    : extractJaasCredential(valueToInspect);

            if (extractedCredential.isPresent()) {
                String credential = extractedCredential.get();
                // The password only came from a default placeholder if the original string contained '${'
                boolean isFromPlaceholderDefault = trimmedValue.contains("${");

                if (!credential.isBlank()) {
                    findings.add(new Finding(
                            id(),
                            Severity.HIGH,
                            buildEmbeddedCredentialMessage(entry.getKey(), rawValue, isFromPlaceholderDefault),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                } else if (isFromPlaceholderDefault) {
                    // Credential slot is present (e.g. "user:${DB_PASSWORD:}@host") but resolved to
                    // empty because of the placeholder's default — distinct from a literal, permanently
                    // empty credential with no placeholder involved, which stays silent (see below).
                    findings.add(new Finding(
                            id(),
                            Severity.INFO,
                            ("Connection property '%s' has a credential placeholder that resolves to an empty value ('%s'). " +
                                    "Static analysis cannot verify the runtime value if the environment variable is unset; " +
                                    "ensure credentials are injected securely via environment variables or a secret manager.")
                                    .formatted(entry.getKey(), rawValue),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                }
                // else: a literal, permanently empty credential (e.g. "user:@host") with no placeholder
                // involved — nothing hardcoded, nothing to verify at runtime either. Stays silent.
            }
        }

        return findings;
    }

    private Optional<String> extractUriCredential(String uriString) {
        if (uriString == null || uriString.isBlank()) {
            return Optional.empty();
        }

        // Processes the first node in the case of URIs with multiple hosts separated by commas (MongoDB, Elastic, etc.)
        String primaryUri = uriString.split(",")[0].trim();

        Matcher matcher = EMBEDDED_URI_PASSWORD_PATTERN.matcher(primaryUri);
        if (matcher.find()) {
            String password = matcher.group(1);

            // If the extracted password is an unresolvable placeholder (e.g., ${DB_PASS}), ignore it.
            if (password.startsWith("${") && password.endsWith("}")) {
                return Optional.empty();
            }

            return Optional.of(password);
        }

        return Optional.empty();
    }

    private Optional<String> extractJaasCredential(String jaasConfig) {
        Matcher matcher = JAAS_PASSWORD_PATTERN.matcher(jaasConfig);
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    private String buildEmbeddedCredentialMessage(String key, String rawValue, boolean isFromPlaceholderDefault) {
        String base = ("Embedded plaintext credential detected in connection property '%s'. " +
                "Never store database or broker passwords in connection strings; " +
                "use environment variables or separate username/password properties.")
                .formatted(key);

        if (!isFromPlaceholderDefault) {
            return base;
        }
        return base + " The value originates from a static placeholder default ('%s').".formatted(rawValue);
    }

    private void ensureConfigured() {
        if (uriBasedKeys == null || jaasBasedKeys == null) {
            throw new IllegalStateException("Rule " + RULE_NAME + " must be configured before execution.");
        }
    }
}