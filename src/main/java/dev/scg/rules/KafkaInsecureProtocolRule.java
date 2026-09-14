package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * SCG014 — detects insecure Kafka transport protocol configuration: {@code security.protocol}
 * set to {@code PLAINTEXT} or {@code SASL_PLAINTEXT} — or left entirely unset — across
 * {@code spring.kafka.security.protocol} (common), its per-client-type overrides
 * ({@code producer}/{@code consumer}/{@code admin}/{@code streams}), and each one's
 * {@code properties.security.protocol} pass-through alias.
 * <p>
 * Unlike this project's other enum-matching rules, absence is not safe here: Kafka's own default
 * for {@code security.protocol} is {@code PLAINTEXT}. {@link #check(EffectiveConfig)} stays
 * silent only when no {@code spring.kafka.*} key exists at all; if Kafka is in use and the common
 * key is unset, that alone is reported ({@link #isCommonProtocolConfigured(EffectiveConfig)} is
 * intentionally independent of the per-client-type loop, since only the common key protects
 * client types without their own override).
 * <p>
 * {@code SASL_PLAINTEXT} gets its own message: the SASL handshake itself still travels
 * unencrypted, so it leaks credentials in addition to payload data.
 * <p>
 * Severity {@link Severity#HIGH}: unencrypted transport exposes data — and for
 * {@code SASL_PLAINTEXT}, credentials — to anyone with network visibility. No profile exemption
 * (Zero-Trust). Plain {@link Rule}: the protocol values are fixed facts of the Kafka wire
 * protocol, not organization-specific.
 */
public final class KafkaInsecureProtocolRule implements Rule {

    private static final String RULE_NAME = "SCG014";

    private static final String SPRING_KAFKA_PREFIX = "spring.kafka";

    private static final List<String> CLIENT_PREFIXES = List.of(
            "",          // common: spring.kafka.security.protocol
            "producer.", // spring.kafka.producer.security.protocol
            "consumer.", // spring.kafka.consumer.security.protocol
            "admin.",    // spring.kafka.admin.security.protocol
            "streams."   // spring.kafka.streams.security.protocol
    );

    private static final Set<String> RISKY_CANONICAL_VALUES = Set.of("plaintext", "saslplaintext");

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Kafka cluster communication uses an unencrypted transport protocol (PLAINTEXT or SASL_PLAINTEXT)";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        // Step 1: Check for evidence of Spring Kafka usage
        if (!RelaxedProperties.hasKeyWithPrefix(config.properties(), SPRING_KAFKA_PREFIX)) {
            return findings;
        }

        // Step 2: Evaluate all 10 explicit target keys (common + client-specific)
        List<String> targetKeys = buildTargetKeys();
        for (String key : targetKeys) {
            String raw = RelaxedProperties.get(config.properties(), key);
            if (raw != null && !raw.isBlank()) {
                evaluateExplicitKey(config, key, raw, findings);
            }
        }

        // Step 3: Check if the COMMON protocol configuration is absent
        // A client-specific override (e.g. consumer) does NOT protect other clients (producer, etc.)
        // from defaulting to PLAINTEXT if no common protocol is set.
        boolean commonProtocolConfigured = isCommonProtocolConfigured(config);
        if (!commonProtocolConfigured) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    "Kafka is configured via 'spring.kafka.*' properties, but 'spring.kafka.security.protocol' " +
                            "is not explicitly set. Unless overridden per client, Kafka clients default to " +
                            "'PLAINTEXT' (unencrypted/unauthenticated). Set 'spring.kafka.security.protocol' " +
                            "to 'SSL' or 'SASL_SSL'.",
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }

        return findings;
    }

    /**
     * Deliberately independent of the Step 2 loop above: only the two common keys protect every
     * client type that doesn't define its own override, so a client-type-specific value (e.g.
     * {@code spring.kafka.consumer.security.protocol=SASL_SSL}) must never suppress this check —
     * it says nothing about whether {@code producer}/{@code admin}/{@code streams} also have
     * coverage.
     */
    private boolean isCommonProtocolConfigured(EffectiveConfig config) {
        String common = RelaxedProperties.get(config.properties(), "spring.kafka.security.protocol");
        if (common != null && !common.isBlank()) {
            return true;
        }
        String commonProps = RelaxedProperties.get(config.properties(), "spring.kafka.properties.security.protocol");
        return commonProps != null && !commonProps.isBlank();
    }

    private void evaluateExplicitKey(EffectiveConfig config, String key, String raw, List<Finding> findings) {
        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(new Finding(
                    id(),
                    Severity.INFO,
                    ("Kafka security protocol property '%s' relies on an unresolved environment placeholder '%s'. " +
                            "Static analysis cannot verify whether network traffic is encrypted.")
                            .formatted(key, raw),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
            return;
        }

        String rawValue = resolved.get().strip();
        String canonicalValue = canonicalize(rawValue);

        if (!RISKY_CANONICAL_VALUES.contains(canonicalValue)) {
            return;
        }

        String message;
        if ("saslplaintext".equals(canonicalValue)) {
            message = ("'%s=%s' uses SASL authentication over an unencrypted transport protocol, exposing " +
                    "both client credentials and payload traffic in plaintext. Set this property to 'SASL_SSL'.")
                    .formatted(key, raw);
        } else {
            message = ("'%s=%s' transmits Kafka cluster traffic in plaintext without encryption or authentication. " +
                    "Set this property to 'SSL' or 'SASL_SSL'.")
                    .formatted(key, raw);
        }

        findings.add(new Finding(
                id(),
                Severity.HIGH,
                message,
                config.sourceFile().toString(),
                config.profileLabel()
        ));
    }

    private static List<String> buildTargetKeys() {
        List<String> keys = new ArrayList<>();
        for (String clientPrefix : CLIENT_PREFIXES) {
            keys.add("spring.kafka." + clientPrefix + "security.protocol");
            keys.add("spring.kafka." + clientPrefix + "properties.security.protocol");
        }
        return keys;
    }

    private static String canonicalize(String value) {
        StringBuilder canonical = new StringBuilder(value.length());
        value.chars()
                .filter(Character::isLetterOrDigit)
                .map(Character::toLowerCase)
                .forEach(c -> canonical.append((char) c));
        return canonical.toString();
    }
}