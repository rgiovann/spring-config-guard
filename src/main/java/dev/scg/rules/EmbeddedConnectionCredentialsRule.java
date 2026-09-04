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

    // Pattern for capturing passwords in jaas.config (e.g., password="myPassword" or password='myPassword')
    private static final Pattern JAAS_PASSWORD_PATTERN = Pattern.compile("password\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);

    // Captura qualquer formato <schema>://<user>:<password>@<host>
    // Ignora prefixos como jdbc:, r2dbc:, pool:, etc.
    private static final Pattern EMBEDDED_URI_PASSWORD_PATTERN =
            Pattern.compile("://[^:@]*:([^@]+)@", Pattern.CASE_INSENSITIVE);

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
            if (valueToInspect.isBlank()) {
                continue;
            }

            // 2. Extrai e valida a credencial no valor resolvido
            boolean hasCredential = isUriTarget
                    ? hasEmbeddedUriCredential(valueToInspect)
                    : hasEmbeddedJaasCredential(valueToInspect);

            if (hasCredential) {
                // A senha só veio de um placeholder default se a string original continha '${'
                boolean isFromPlaceholderDefault = trimmedValue.contains("${");

                String message = buildEmbeddedCredentialMessage(entry.getKey(), rawValue, isFromPlaceholderDefault);

                findings.add(new Finding(
                        id(),
                        Severity.HIGH,
                        message,
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }

        return findings;
    }

    private boolean hasEmbeddedUriCredential(String uriString) {
        if (uriString == null || uriString.isBlank()) {
            return false;
        }

        // Processa o primeiro nó em caso de URIs com múltiplos hosts separados por vírgula (MongoDB, Elastic, etc.)
        String primaryUri = uriString.split(",")[0].trim();

        Matcher matcher = EMBEDDED_URI_PASSWORD_PATTERN.matcher(primaryUri);
        if (matcher.find()) {
            String password = matcher.group(1);

            // Se a senha extraída for um placeholder irresolvível (ex: ${DB_PASS}), ignora.
            if (password.startsWith("${") && password.endsWith("}")) {
                return false;
            }

            // Se contiver texto claro (mesmo que seja um default estático de placeholder já resolvido)
            return !password.isBlank();
        }

        return false;
    }

    private boolean hasEmbeddedJaasCredential(String jaasConfig) {
        Matcher matcher = JAAS_PASSWORD_PATTERN.matcher(jaasConfig);
        if (matcher.find()) {
            String password = matcher.group(1);
            return !password.isBlank();
        }
        return false;
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