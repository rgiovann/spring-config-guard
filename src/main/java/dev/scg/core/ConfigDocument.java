package dev.scg.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A single YAML document within a file (delimited by "---").
 * For .properties files, or .yml files without "---", there is always
 * exactly one ConfigDocument per file, with an empty profile.
 * <p>
 * This is the "raw" document — not yet merged with anything. ProfileMerger
 * consumes a list of ConfigDocument objects (all from the same file) and
 * produces an EffectiveConfig (the already-merged result, ready for the rules).
 * <p>
 * ConfigFileGrouper can fold multiple physical sources of the same precedence
 * tier together before ProfileMerger ever sees them, and an explicit-null
 * override resolves immediately as part of that fold (not deferrable — see
 * {@code ProfileMerger.mergeWithoutStrippingSentinels}), to an empty string,
 * as Spring Boot loads a YAML null. A plain unmodifiable copy is used rather
 * than {@code Map.copyOf}, which would reject a {@code null} value from any
 * caller.
 */
public record ConfigDocument(
        Optional<String> profile,
        Map<String, String> properties
) {
    public ConfigDocument {
        Objects.requireNonNull(profile, "profile cannot be null (use Optional.empty())");
        Objects.requireNonNull(properties, "properties cannot be null");
        properties = Collections.unmodifiableMap(new LinkedHashMap<>(properties));
    }
}