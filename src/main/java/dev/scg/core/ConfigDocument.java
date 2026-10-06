package dev.scg.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A single document within a file: a YAML document (delimited by "---") or a
 * {@code .properties} document (delimited by "#---" or "!---"). A file without
 * separators has exactly one.
 * <p>
 * {@code activation} is the document's {@code spring.config.activate.on-profile}
 * condition, parsed; empty when the document has none (or a null or empty one),
 * so it applies whatever profiles are active. The key itself is removed from
 * {@code properties}.
 * <p>
 * This is the "raw" document, not yet merged with anything: ProfileMerger folds
 * the documents that apply to a set of active profiles, in Spring Boot's source
 * order, into an EffectiveConfig. A plain unmodifiable copy is used rather than
 * {@code Map.copyOf}, which would reject a {@code null} value from any caller.
 */
public record ConfigDocument(
        Optional<ProfileExpression> activation,
        Map<String, String> properties
) {
    public ConfigDocument {
        Objects.requireNonNull(activation, "activation cannot be null (use Optional.empty())");
        Objects.requireNonNull(properties, "properties cannot be null");
        properties = Collections.unmodifiableMap(new LinkedHashMap<>(properties));
    }
}
