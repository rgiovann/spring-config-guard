package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.RelaxedProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The Spring Cloud Stream Kafka binder contexts of one {@link EffectiveConfig}, as the binder
 * resolves them (see ARCHITECTURE.md, ADR-009): the main context, and one context per
 * {@code spring.cloud.stream.binders.<name>}, where that binder's {@code environment} map is the
 * highest-precedence source and the main context is inherited below it, unless
 * {@code inherit-environment} is false. Confirmed in Spring Cloud Stream's
 * {@code DefaultBinderFactory}, which adds the environment map with {@code addFirst} and merges the
 * parent environment when inheriting.
 * <p>
 * Keys are stored canonicalized ({@link RelaxedProperties#canonicalize}), with the key as written
 * in the file kept for messages, so a finding names the property the user can find and fix.
 */
final class KafkaBinderContexts {

    static final String KAFKA_BINDER_PREFIX = "spring.cloud.stream.kafka.binder.";
    static final String KAFKA_STREAMS_BINDER_PREFIX = "spring.cloud.stream.kafka.streams.binder.";

    /** The binder maps whose entries are passed to Kafka clients as-is. */
    static final List<String> CLIENT_MAPS = List.of("configuration.", "consumer-properties.", "producer-properties.");

    private static final String BINDERS_PREFIX = RelaxedProperties.canonicalize("spring.cloud.stream.binders.");
    private static final String ENVIRONMENT_SEGMENT = ".environment.";
    private static final Set<String> STREAMS_BINDER_TYPES = Set.of("kstream", "ktable", "globalktable");

    /**
     * One context. {@code binderName} is empty for the main context. {@code properties} maps
     * canonical keys to values; {@code writtenKeys} maps each canonical key to the key as written;
     * {@code ownKeys} holds the canonical keys this context defines itself (for a named binder, its
     * environment entries), as opposed to the ones it inherits from the main context.
     */
    record Context(Optional<String> binderName, Optional<String> binderType, Map<String, String> properties,
                   Map<String, String> writtenKeys, Set<String> ownKeys) {

        String get(String key) {
            return properties.get(RelaxedProperties.canonicalize(key));
        }

        String writtenKey(String key) {
            String canonical = RelaxedProperties.canonicalize(key);
            return writtenKeys.getOrDefault(canonical, key);
        }

        boolean owns(String key) {
            return ownKeys.contains(RelaxedProperties.canonicalize(key));
        }

        boolean usesKafkaBinder() {
            return hasPrefix(KAFKA_BINDER_PREFIX) || binderType.filter("kafka"::equals).isPresent();
        }

        boolean usesKafkaStreamsBinder() {
            return hasPrefix(KAFKA_STREAMS_BINDER_PREFIX) || binderType.filter(STREAMS_BINDER_TYPES::contains).isPresent();
        }

        boolean hasPrefix(String prefix) {
            String canonical = RelaxedProperties.canonicalize(prefix);
            return properties.keySet().stream().anyMatch(key -> key.startsWith(canonical));
        }

        String label() {
            return binderName.map(name -> "binder '" + name + "'").orElse("the default binder");
        }
    }

    private KafkaBinderContexts() {
    }

    /** The main context first, then one per named binder, in the order the binders appear. */
    static List<Context> of(EffectiveConfig config) {
        Map<String, String> mainProperties = new LinkedHashMap<>();
        Map<String, String> mainWritten = new LinkedHashMap<>();
        Map<String, Map<String, String>> environments = new LinkedHashMap<>();
        Map<String, Map<String, String>> environmentsWritten = new LinkedHashMap<>();
        Map<String, String> binderTypes = new LinkedHashMap<>();
        Map<String, String> writtenNames = new LinkedHashMap<>();
        Set<String> notInheriting = new LinkedHashSet<>();

        config.properties().forEach((key, value) -> {
            String canonical = RelaxedProperties.canonicalize(key);
            if (!canonical.startsWith(BINDERS_PREFIX)) {
                mainProperties.put(canonical, value);
                mainWritten.put(canonical, key);
                return;
            }
            String rest = canonical.substring(BINDERS_PREFIX.length());
            int dot = rest.indexOf('.');
            if (dot < 0) {
                return;
            }
            String name = rest.substring(0, dot);
            String setting = rest.substring(dot);
            writtenNames.putIfAbsent(name, writtenBinderName(key, name));
            if (setting.startsWith(ENVIRONMENT_SEGMENT)) {
                String environmentKey = setting.substring(ENVIRONMENT_SEGMENT.length());
                environments.computeIfAbsent(name, n -> new LinkedHashMap<>()).put(environmentKey, value);
                environmentsWritten.computeIfAbsent(name, n -> new LinkedHashMap<>()).put(environmentKey, key);
            } else if (setting.equals(".type") && value != null) {
                binderTypes.put(name, value.strip().toLowerCase(Locale.ROOT));
            } else if (setting.equals(".inheritenvironment") && "false".equalsIgnoreCase(String.valueOf(value).strip())) {
                notInheriting.add(name);
            }
        });

        List<Context> contexts = new ArrayList<>();
        contexts.add(new Context(Optional.empty(), Optional.empty(), mainProperties, mainWritten, mainProperties.keySet()));

        Set<String> names = new LinkedHashSet<>(binderTypes.keySet());
        names.addAll(environments.keySet());
        for (String name : names) {
            Map<String, String> environment = environments.getOrDefault(name, Map.of());
            Map<String, String> properties = new LinkedHashMap<>();
            Map<String, String> written = new LinkedHashMap<>();
            if (!notInheriting.contains(name)) {
                properties.putAll(mainProperties);
                written.putAll(mainWritten);
            }
            properties.putAll(environment);
            written.putAll(environmentsWritten.getOrDefault(name, Map.of()));
            contexts.add(new Context(Optional.of(writtenNames.getOrDefault(name, name)), Optional.ofNullable(binderTypes.get(name)),
                    properties, written, environment.keySet()));
        }
        return contexts;
    }

    /** The binder's name as written, when the key spells the prefix plainly; the canonical name otherwise. */
    private static String writtenBinderName(String writtenKey, String canonicalName) {
        String plainPrefix = "spring.cloud.stream.binders.";
        if (writtenKey.toLowerCase(Locale.ROOT).startsWith(plainPrefix)) {
            int end = writtenKey.indexOf('.', plainPrefix.length());
            if (end > plainPrefix.length()) {
                return writtenKey.substring(plainPrefix.length(), end);
            }
        }
        return canonicalName;
    }

    /**
     * The key with a leading {@code spring.cloud.stream.binders.<name>.environment.} removed, so a
     * property set inside a binder's environment is matched like the same property at the top
     * level. Expects and returns a canonical key.
     */
    static String withoutBinderEnvironment(String canonicalKey) {
        if (!canonicalKey.startsWith(BINDERS_PREFIX)) {
            return canonicalKey;
        }
        int environment = canonicalKey.indexOf(ENVIRONMENT_SEGMENT, BINDERS_PREFIX.length());
        return environment < 0 ? canonicalKey : canonicalKey.substring(environment + ENVIRONMENT_SEGMENT.length());
    }
}
