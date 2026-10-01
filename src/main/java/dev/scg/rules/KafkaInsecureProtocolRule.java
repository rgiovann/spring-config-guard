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
 * The Spring Cloud Stream Kafka and Kafka Streams binders are evaluated too, each named binder's
 * {@code environment} as a context of its own ({@link #checkBinders}; ARCHITECTURE.md, ADR-009).
 * <p>
 * Severity {@link Severity#HIGH} for an insecure protocol written in the file: unencrypted transport
 * exposes data — and for {@code SASL_PLAINTEXT}, credentials — to anyone with network visibility.
 * {@link Severity#MEDIUM} when the protocol is only absent: the same default applies, but the
 * protocol may be set outside the scanned files (ARCHITECTURE.md, ADR-010). No profile exemption
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

    /**
     * An unset protocol is MEDIUM, a written insecure one HIGH: Kafka's default is PLAINTEXT, but the
     * protocol is often set outside these files, through an environment variable SCG can't see
     * (ARCHITECTURE.md, ADR-010).
     */
    private static final Severity ABSENT_PROTOCOL_SEVERITY = Severity.MEDIUM;
    private static final String ABSENCE_NOTE = "Reported as MEDIUM because the protocol may be set outside "
            + "these files, e.g. by an environment variable.";

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
        boolean springKafkaUnsetReported = false;

        // Step 1: Check for evidence of Spring Kafka usage
        if (RelaxedProperties.hasKeyWithPrefix(config.properties(), SPRING_KAFKA_PREFIX)) {

            // Step 2: Evaluate all 10 explicit target keys (common + client-specific)
            for (String key : buildTargetKeys()) {
                String raw = RelaxedProperties.get(config.properties(), key);
                if (raw != null && !raw.isBlank()) {
                    evaluateExplicitKey(config, key, raw, findings);
                }
            }

            // Step 3: Check if the COMMON protocol configuration is absent
            // A client-specific override (e.g. consumer) does NOT protect other clients (producer, etc.)
            // from defaulting to PLAINTEXT if no common protocol is set.
            if (!isCommonProtocolConfigured(config)) {
                springKafkaUnsetReported = true;
                findings.add(new Finding(
                        id(),
                        ABSENT_PROTOCOL_SEVERITY,
                        "Kafka is configured via 'spring.kafka.*' properties, but 'spring.kafka.security.protocol' " +
                                "is not explicitly set. Unless overridden per client, Kafka clients default to " +
                                "'PLAINTEXT' (unencrypted/unauthenticated). Set 'spring.kafka.security.protocol' " +
                                "to 'SSL' or 'SASL_SSL'. " + ABSENCE_NOTE,
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }

        // Step 4: the Spring Cloud Stream Kafka binders (ADR-009)
        checkBinders(config, springKafkaUnsetReported, findings);

        return findings;
    }

    /**
     * The Spring Cloud Stream Kafka and Kafka Streams binders build each client's configuration from
     * Spring Boot's {@code spring.kafka.*} properties, overridden by the binder's {@code configuration}
     * map, overridden by its {@code consumer-properties}/{@code producer-properties} maps. A named
     * binder's {@code environment} is a separate context on top of the main one (ADR-009).
     * <ul>
     *     <li>Every insecure value a context writes itself is reported once, under the key as written:
     *     the binder maps' {@code security.protocol}, and, inside a named binder's environment, the
     *     {@code spring.kafka.*} keys Step 2 checks at the top level. A top-level value inherited by
     *     several binders is reported once, in the main context.</li>
     *     <li>A binder in use with no protocol covering all its clients (its {@code configuration}
     *     map or Spring Boot's common keys; a per-client map doesn't protect the admin client or the
     *     other client type) is reported per context. Not in the main context when Step 3 already
     *     reported the same gap, or when named Kafka binders exist: the main context is then only
     *     inherited, not a binder of its own.</li>
     * </ul>
     */
    private void checkBinders(EffectiveConfig config, boolean springKafkaUnsetReported, List<Finding> findings) {
        List<KafkaBinderContexts.Context> contexts = KafkaBinderContexts.of(config);
        boolean namedKafkaBinders = contexts.stream()
                .filter(context -> context.binderName().isPresent())
                .anyMatch(context -> context.usesKafkaBinder() || context.usesKafkaStreamsBinder());

        for (KafkaBinderContexts.Context context : contexts) {
            boolean isMain = context.binderName().isEmpty();

            for (String key : binderTargetKeys(isMain)) {
                if (!context.owns(key)) {
                    continue;
                }
                String raw = context.get(key);
                if (raw != null && !raw.isBlank()) {
                    evaluateExplicitKey(config, context.writtenKey(key), raw, findings);
                }
            }

            if (isMain && (springKafkaUnsetReported || namedKafkaBinders)) {
                continue;
            }
            if (context.usesKafkaBinder() && !isBinderProtocolConfigured(context, KafkaBinderContexts.KAFKA_BINDER_PREFIX)) {
                findings.add(binderProtocolUnsetFinding(config, context, KafkaBinderContexts.KAFKA_BINDER_PREFIX));
            }
            if (context.usesKafkaStreamsBinder()
                    && !isBinderProtocolConfigured(context, KafkaBinderContexts.KAFKA_STREAMS_BINDER_PREFIX)) {
                findings.add(binderProtocolUnsetFinding(config, context, KafkaBinderContexts.KAFKA_STREAMS_BINDER_PREFIX));
            }
        }
    }

    /** The binder maps' protocol keys; inside a named binder's environment, Step 2's keys too. */
    private static List<String> binderTargetKeys(boolean isMain) {
        List<String> keys = new ArrayList<>();
        for (String prefix : List.of(KafkaBinderContexts.KAFKA_BINDER_PREFIX, KafkaBinderContexts.KAFKA_STREAMS_BINDER_PREFIX)) {
            for (String map : KafkaBinderContexts.CLIENT_MAPS) {
                keys.add(prefix + map + "security.protocol");
            }
        }
        if (!isMain) {
            keys.addAll(buildTargetKeys());
        }
        return keys;
    }

    private static boolean isBinderProtocolConfigured(KafkaBinderContexts.Context context, String binderPrefix) {
        List<String> coveringKeys = new ArrayList<>(List.of(
                binderPrefix + "configuration.security.protocol",
                "spring.kafka.security.protocol",
                "spring.kafka.properties.security.protocol"));
        if (binderPrefix.equals(KafkaBinderContexts.KAFKA_STREAMS_BINDER_PREFIX)) {
            coveringKeys.add("spring.kafka.streams.security.protocol");
            coveringKeys.add("spring.kafka.streams.properties.security.protocol");
        }
        return coveringKeys.stream()
                .map(context::get)
                .anyMatch(value -> value != null && !value.isBlank());
    }

    private Finding binderProtocolUnsetFinding(EffectiveConfig config, KafkaBinderContexts.Context context, String binderPrefix) {
        String binderKind = binderPrefix.equals(KafkaBinderContexts.KAFKA_STREAMS_BINDER_PREFIX)
                ? "Kafka Streams binder" : "Kafka binder";
        return new Finding(
                id(),
                ABSENT_PROTOCOL_SEVERITY,
                ("Kafka is used through the Spring Cloud Stream %s (%s), but no security.protocol covers all its " +
                        "clients: neither '%sconfiguration.security.protocol' nor 'spring.kafka.security.protocol' " +
                        "is set. Kafka clients default to 'PLAINTEXT' (unencrypted/unauthenticated). Set one of them " +
                        "to 'SSL' or 'SASL_SSL'%s. " + ABSENCE_NOTE)
                        .formatted(binderKind, context.label(), binderPrefix,
                                context.binderName().isPresent() ? ", inside that binder's environment or at the top level" : ""),
                config.sourceFile().toString(),
                config.profileLabel()
        );
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