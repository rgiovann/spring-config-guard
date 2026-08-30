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
     * Valores de uma chave OU de seus filhos indexados (key[0], key[1]...),
     * tolerante a relaxed binding. Usado por regras que precisam checar
     * tanto a forma escalar quanto a forma de lista YAML de uma propriedade.
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
}