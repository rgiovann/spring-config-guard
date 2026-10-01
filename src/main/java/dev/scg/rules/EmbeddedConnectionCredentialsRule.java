package dev.scg.rules;


import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Security rule (SCG007) that detects hardcoded plaintext credentials embedded within
 * connection strings, database URIs, and JAAS configurations.
 *
 * <p>Detection is by the shape of the value, in every property, not by a list of keys
 * ({@link EmbeddedCredentials}): a password in a URL's user-info, a {@code password=} URL parameter
 * (PostgreSQL, MySQL, SQL Server, H2), Oracle's {@code user/password@host}, or a {@code password} or
 * {@code clientSecret} option in a JAAS configuration (Kafka SASL). A list of keys went stale as
 * Spring Boot renamed properties ({@code spring.redis.url} became {@code spring.data.redis.url},
 * {@code spring.data.mongodb.uri} became {@code spring.mongodb.uri}) and never covered Spring Cloud
 * ({@code spring.cloud.config.uri}, Eureka's {@code defaultZone}) or the application's own keys.
 * A key inside a Spring Cloud Stream binder's {@code environment} is the same property for that
 * binder (ADR-009); with value-based detection it needs no special handling.</p>
 *
 * <p>Placeholders are substituted before inspection: a static default is inspected like a
 * literal and reported HIGH, and a placeholder without a default is not a hardcoded credential.
 * {@code connection-keys} lists the native connection properties for which a value that
 * can't be verified statically (an unresolved placeholder, an empty default) is reported as INFO,
 * since the URL injected at runtime may carry a credential.</p>
 *
 * @see ConfigurableRule
 * @see EnvironmentPlaceholder
 */
public final class EmbeddedConnectionCredentialsRule implements ConfigurableRule {

    private static final String RULE_NAME = "SCG007";

    /** Stands for a placeholder without a default: not a credential written in the file. */
    private static final String UNRESOLVED = "\u0000unresolved\u0000";

    private Set<String> connectionKeys;

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

        List<String> rawConnectionKeys = metadata.get("connection-keys");
        if (rawConnectionKeys == null || rawConnectionKeys.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'connection-keys' is missing or empty.");
        }

        this.connectionKeys = rawConnectionKeys.stream()
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
            String trimmedValue = rawValue.strip();
            boolean hasPlaceholder = trimmedValue.contains("${");

            List<String> credentials = EmbeddedCredentials.find(EnvironmentPlaceholder.substitute(trimmedValue, UNRESOLVED));
            boolean hardcoded = credentials.stream().anyMatch(c -> !c.isBlank() && !c.contains(UNRESOLVED));
            if (hardcoded) {
                findings.add(finding(config, Severity.HIGH,
                        buildEmbeddedCredentialMessage(entry.getKey(), rawValue, hasPlaceholder)));
                continue;
            }
            if (hasPlaceholder && credentials.stream().anyMatch(String::isBlank)
                    && EmbeddedCredentials.find(trimmedValue).stream().anyMatch(c -> c.contains("${"))) {
                // Credential slot present (e.g. "user:${DB_PASSWORD:}@host") but empty because of the
                // placeholder's default -- distinct from a literal, permanently empty credential with no
                // placeholder involved ("user:@host"), which stays silent: nothing hardcoded, nothing to verify.
                findings.add(finding(config, Severity.INFO,
                        ("Connection property '%s' has a credential placeholder that resolves to an empty value ('%s'). " +
                                "Static analysis cannot verify the runtime value if the environment variable is unset; " +
                                "ensure credentials are injected securely via environment variables or a secret manager.")
                                .formatted(entry.getKey(), rawValue)));
                continue;
            }

            // canonicalRoot strips a trailing "[0]"/"[1]"/... so a key written as one item of a YAML
            // list (e.g. spring.elasticsearch.uris[0]) still matches the plain connection key; a key
            // inside a Spring Cloud Stream binder's environment is matched without that prefix (ADR-009).
            String canonicalKey = RelaxedProperties.canonicalRoot(
                    KafkaBinderContexts.withoutBinderEnvironment(RelaxedProperties.canonicalize(entry.getKey())));
            if (!connectionKeys.contains(canonicalKey)) {
                continue;
            }
            Optional<String> resolvedValue = EnvironmentPlaceholder.resolve(trimmedValue);
            if (resolvedValue.isEmpty()) {
                findings.add(finding(config, Severity.INFO,
                        ("Connection property '%s' relies on an unresolved environment placeholder '%s'. " +
                                "Static analysis cannot verify the runtime value; ensure credentials are injected securely.")
                                .formatted(entry.getKey(), rawValue)));
            } else if (resolvedValue.get().isBlank()) {
                // ${VAR:} -- the whole value was a placeholder with an empty default. Mirrors SCG006.
                findings.add(finding(config, Severity.INFO,
                        ("Connection property '%s' declares an empty default fallback for its environment placeholder '%s'. " +
                                "Static analysis cannot verify the runtime value if the environment variable is unset; " +
                                "ensure credentials are injected securely via environment variables or a secret manager.")
                                .formatted(entry.getKey(), rawValue)));
            }
        }

        return findings;
    }

    private Finding finding(EffectiveConfig config, Severity severity, String message) {
        return new Finding(id(), severity, message, config.sourceFile().toString(), config.profileLabel());
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
        if (connectionKeys == null) {
            throw new IllegalStateException("Rule " + RULE_NAME + " must be configured before execution.");
        }
    }
}
