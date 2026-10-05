package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * SCG014 — detects insecure Kafka transport protocol configuration: {@code security.protocol}
 * set to {@code PLAINTEXT} or {@code SASL_PLAINTEXT} — or left entirely unset — across
 * {@code spring.kafka.security.protocol} (common), its per-client-type overrides
 * ({@code producer}/{@code consumer}/{@code admin}/{@code streams}), and each one's
 * {@code properties.security.protocol} pass-through alias.
 * <p>
 * The protocol is resolved per client (producer, consumer, admin, streams) as Spring Boot does,
 * highest precedence first: the client's {@code properties} map, its typed key, the common
 * {@code spring.kafka.properties} map, the common typed key
 * ({@link #evaluateEffectiveProtocols}). Only the value a client actually gets is reported: an
 * insecure value overridden for every client by a secure one isn't, since no client uses it.
 * <p>
 * Unlike this project's other enum-matching rules, absence is not safe here: Kafka's own default
 * for {@code security.protocol} is {@code PLAINTEXT}. {@link #check(EffectiveConfig)} stays
 * silent only when no {@code spring.kafka.*} key exists at all; if Kafka is in use and a client
 * gets no protocol, that is reported, naming the clients. The streams client counts even without
 * a {@code spring.kafka.streams.*} key: a Kafka Streams application can rely on
 * {@code spring.application.name} for its application id, and the classpath isn't visible here.
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
 * protocol may be set outside the scanned files (ARCHITECTURE.md, ADR-010). Either is
 * {@link Severity#INFO} when every Kafka broker address the file writes, literally, is a loopback
 * address ({@link ConnectionHosts}). No profile exemption (Zero-Trust). Plain {@link Rule}: the
 * protocol values are fixed facts of the Kafka wire protocol, not organization-specific.
 */
public final class KafkaInsecureProtocolRule implements Rule {

    private static final String RULE_NAME = "SCG014";

    private static final String SPRING_KAFKA_PREFIX = "spring.kafka";

    /** The Kafka clients Spring Boot builds from {@code spring.kafka.*}, in report order. */
    private static final List<String> CLIENTS = List.of("producer", "consumer", "admin", "streams");

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

            // Steps 2 and 3: the protocol each client actually gets, and the clients that get none
            List<String> uncovered = evaluateEffectiveProtocols(config,
                    key -> RelaxedProperties.get(config.properties(), key), key -> true, key -> key, findings);
            if (!uncovered.isEmpty()) {
                springKafkaUnsetReported = true;
                findings.add(new Finding(
                        id(),
                        ABSENT_PROTOCOL_SEVERITY,
                        ("Kafka is configured via 'spring.kafka.*' properties, but 'spring.kafka.security.protocol' " +
                                "is not explicitly set and no client-specific protocol covers the %s client%s. " +
                                "Kafka clients default to 'PLAINTEXT' (unencrypted/unauthenticated). Set " +
                                "'spring.kafka.security.protocol' to 'SSL' or 'SASL_SSL'. " + ABSENCE_NOTE)
                                .formatted(String.join(", ", uncovered), uncovered.size() == 1 ? "" : "s"),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }

        // Step 4: the Spring Cloud Stream Kafka binders (ADR-009)
        checkBinders(config, springKafkaUnsetReported, findings);

        return writesOnlyLoopbackBrokers(config)
                ? findings.stream().map(ConnectionHosts::onLoopback).toList()
                : findings;
    }

    /**
     * Whether the file writes at least one broker address and every one it writes, in any context
     * ({@code bootstrap-servers}, a {@code bootstrap.servers} map entry, a binder's {@code brokers}),
     * is a loopback address. Deliberately not per client or per binder: one remote address anywhere
     * keeps every finding as it is. An unwritten address doesn't count, though Spring Boot's default
     * is {@code localhost:9092}: it is usually set outside the files.
     */
    private static boolean writesOnlyLoopbackBrokers(EffectiveConfig config) {
        boolean written = false;
        for (Map.Entry<String, String> entry : config.properties().entrySet()) {
            String key = RelaxedProperties.canonicalRoot(RelaxedProperties.canonicalize(entry.getKey()));
            if (!isBrokerKey(key)) {
                continue;
            }
            String raw = entry.getValue();
            if (raw == null || raw.isBlank()) {
                continue;
            }
            if (!ConnectionHosts.allLoopback(raw)) {
                return false; // a remote, unreadable or placeholder address
            }
            written = true;
        }
        return written;
    }

    /** A Spring Kafka or Spring Cloud Stream Kafka broker key, at the top level or in a binder's environment. */
    private static boolean isBrokerKey(String canonicalKey) {
        int environment = canonicalKey.indexOf(".environment.");
        String key = canonicalKey.startsWith("spring.cloud.stream.binders.") && environment >= 0
                ? canonicalKey.substring(environment + ".environment.".length())
                : canonicalKey;
        boolean kafkaKey = key.startsWith(SPRING_KAFKA_PREFIX + ".") || key.startsWith("spring.cloud.stream.kafka.");
        return kafkaKey && (key.endsWith(".bootstrapservers") || key.endsWith(".bootstrap.servers")
                || key.endsWith(".binder.brokers"));
    }

    /**
     * Resolves {@code security.protocol} for each client as Spring Boot's {@code KafkaProperties}
     * does, from the highest precedence down: the client's {@code properties} map, the client's typed
     * key, the common {@code spring.kafka.properties} map, the common typed key (confirmed by binding
     * Spring Boot 4.1.1's {@code KafkaProperties} and building each client's configuration). Only the
     * value a client actually gets is evaluated, once per key: an insecure value overridden by a
     * higher-precedence one isn't used, and an unresolved placeholder always resolves at runtime or
     * the application doesn't start, so it overrides whatever is below it too.
     *
     * @param reportable whether a supplying key may be reported here (a named binder's environment
     *                   reports only its own keys; inherited ones are reported in the main context)
     * @return the clients no key covers
     */
    private List<String> evaluateEffectiveProtocols(EffectiveConfig config, Function<String, String> get,
                                                    Predicate<String> reportable, Function<String, String> written,
                                                    List<Finding> findings) {
        Set<String> supplyingKeys = new LinkedHashSet<>();
        List<String> uncovered = new ArrayList<>();
        for (String client : CLIENTS) {
            Optional<String> supplying = protocolChain(client).stream()
                    .filter(key -> {
                        String value = get.apply(key);
                        return value != null && !value.isBlank();
                    })
                    .findFirst();
            if (supplying.isPresent()) {
                supplyingKeys.add(supplying.get());
            } else {
                uncovered.add(client);
            }
        }
        for (String key : supplyingKeys) {
            if (reportable.test(key)) {
                evaluateExplicitKey(config, written.apply(key), get.apply(key), findings);
            }
        }
        return uncovered;
    }

    /** The keys that can set a client's {@code security.protocol}, highest precedence first. */
    private static List<String> protocolChain(String client) {
        return List.of(
                "spring.kafka." + client + ".properties.security.protocol",
                "spring.kafka." + client + ".security.protocol",
                "spring.kafka.properties.security.protocol",
                "spring.kafka.security.protocol");
    }

    /**
     * The Spring Cloud Stream Kafka and Kafka Streams binders build each client's configuration from
     * Spring Boot's {@code spring.kafka.*} properties, overridden by the binder's {@code configuration}
     * map, overridden by its {@code consumer-properties}/{@code producer-properties} maps. A named
     * binder's {@code environment} is a separate context on top of the main one (ADR-009).
     * <ul>
     *     <li>Every insecure value a context writes itself is reported once, under the key as written:
     *     the binder maps' {@code security.protocol}, and, inside a named binder's environment, the
     *     {@code spring.kafka.*} keys its clients actually get, resolved as at the top level. A
     *     top-level value inherited by several binders is reported once, in the main context.</li>
     *     <li>A binder in use with no protocol covering all its clients (its {@code configuration}
     *     map or Spring Boot's common keys; a per-client map doesn't protect the admin client or the
     *     other client type) is reported per context. Not in the main context when the
     *     {@code spring.kafka.*} check already reported the same gap, or when named Kafka binders exist: the main context is then only
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

            if (!isMain) {
                evaluateEffectiveProtocols(config, context::get, context::owns, context::writtenKey, findings);
            }
            for (String key : binderTargetKeys()) {
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

    /**
     * The binder maps' protocol keys. Each is evaluated as written: the {@code configuration} map
     * always reaches the admin client, and the per-client maps have the highest precedence.
     */
    private static List<String> binderTargetKeys() {
        List<String> keys = new ArrayList<>();
        for (String prefix : List.of(KafkaBinderContexts.KAFKA_BINDER_PREFIX, KafkaBinderContexts.KAFKA_STREAMS_BINDER_PREFIX)) {
            for (String map : KafkaBinderContexts.CLIENT_MAPS) {
                keys.add(prefix + map + "security.protocol");
            }
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

    private static String canonicalize(String value) {
        StringBuilder canonical = new StringBuilder(value.length());
        value.chars()
                .filter(Character::isLetterOrDigit)
                .map(Character::toLowerCase)
                .forEach(c -> canonical.append((char) c));
        return canonical.toString();
    }
}