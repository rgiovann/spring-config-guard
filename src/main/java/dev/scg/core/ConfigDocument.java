package dev.scg.core;

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
 */
public record ConfigDocument(
        Optional<String> profile,
        Map<String, String> properties
) {
    public ConfigDocument {
        Objects.requireNonNull(profile, "profile cannot be null (use Optional.empty())");
        Objects.requireNonNull(properties, "properties cannot be null");
        properties = Map.copyOf(properties);
    }
}