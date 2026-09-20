package dev.scg.core;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Optional;

/**
 * Compares and searches for property keys while respecting Spring Boot's
 * relaxed binding: kebab-case, camelCase, and snake_case within the same
 * segment (between dots) are treated as the same property. Confirmed in the
 * official wiki (Relaxed Binding 2.0): the actual comparison removes '-'/ '_'
 * and converts to lowercase — it does NOT reconstruct kebab-case, avoiding any
 * ambiguity about where to insert hyphens in acronyms (e.g., apiURL).
 * <p>
 * Deliberate scope: does not handle the env var rule (underscore becomes a dot),
 * which is exclusive to OS environment variables — ConfigLoader only reads
 * .properties/.yml files, never env vars.
 */
public final class RelaxedProperties {

    private RelaxedProperties() {}

    public static String canonicalize(String key) {
        if (key == null) return null;
        StringBuilder result = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c == '-' || c == '_') continue;
            if (c == '.') {
                result.append('.');
            } else {
                result.append(Character.toLowerCase(c));
            }
        }
        return result.toString();
    }

    /** Busca exata de uma chave, tolerante a kebab-case/camelCase/snake_case. */
    public static String get(Map<String, String> properties, String canonicalKey) {
        String target = canonicalize(canonicalKey);
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            if (canonicalize(entry.getKey()).equals(target)) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Values of a key OR of its indexed children (key[0], key[1]...),
     * tolerant of relaxed binding. Used by rules that need to check both
     * the scalar and the YAML list form of a property.
     */
    public static List<String> valuesForKeyOrListChildren(Map<String, String> properties, String canonicalKey) {
        String target = canonicalize(canonicalKey);
        String bracketPrefix = target + "[";
        List<String> values = new ArrayList<>();
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            String actual = canonicalize(entry.getKey());
            if (actual.equals(target) || actual.startsWith(bracketPrefix)) {
                values.add(entry.getValue());
            }
        }
        return values;
    }

    /**
     * Strips a trailing list-index suffix ("[0]", "[1]", ...) from an already-canonicalized
     * key, if present — the same bracket-detection rule valuesForKeyOrListChildren() uses
     * internally for its bracketPrefix check. Exposed for rules that iterate
     * properties.entrySet() directly (needing the actual key/value pair together, not just
     * the collected values) and must still match a canonical target correctly whether the
     * property was written as a scalar or as one item of a YAML list — a raw equals() against
     * the target would silently miss every indexed item. This is exactly the gap that let
     * EmbeddedConnectionCredentialsRule (SCG007) miss credentials in
     * spring.elasticsearch.uris/spring.rabbitmq.addresses when written as real YAML lists
     * instead of a single scalar (see BACKLOG.md).
     */
    public static String canonicalRoot(String canonicalKey) {
        if (canonicalKey == null) return null;
        int bracketIdx = canonicalKey.indexOf('[');
        return bracketIdx >= 0 ? canonicalKey.substring(0, bracketIdx) : canonicalKey;
    }

    /** Retorna a chave real presente no mapa que canonicaliza para canonicalKey, se houver. */
    public static Optional<String> findActualKey(Map<String, String> properties, String canonicalKey) {
        String target = canonicalize(canonicalKey);
        for (String actualKey : properties.keySet()) {
            if (canonicalize(actualKey).equals(target)) {
                return Optional.of(actualKey);
            }
        }
        return Optional.empty();
    }


    /**
     * Check if there is any key in the property map that starts with the given canonical
     * prefix (e.g., "springdoc"), matching either the prefix itself or a "prefix.*" segment —
     * a raw startsWith would also match unrelated keys like "springdocument.path".
     */
    public static boolean hasKeyWithPrefix(Map<String, String> properties, String canonicalPrefix) {
        if (properties == null || properties.isEmpty() || canonicalPrefix == null) {
            return false;
        }
        String targetPrefix = canonicalize(canonicalPrefix);
        String dottedPrefix = targetPrefix + ".";
        for (String actualKey : properties.keySet()) {
            String actual = canonicalize(actualKey);
            if (actual.equals(targetPrefix) || actual.startsWith(dottedPrefix)) {
                return true;
            }
        }
        return false;
    }
}