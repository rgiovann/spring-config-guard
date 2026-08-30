package dev.scg.core;

import java.nio.file.Path;
import java.util.Map;

/**
 * The result of merging the base document(s) of a file with a
 * specific named profile (or the base alone, when profileLabel
 * is "base"). This is what the rules (Rule) actually evaluate — never
 * a raw ConfigDocument in isolation, because a profile document
 * by itself may not reflect the actual configuration (some keys only
 * exist in the base and remain in effect).
 <p>
 * profileLabel is never null or empty: for the "no active profile"
 * scenario, the value is the literal String "base" — never null, never
 * Optional. This simplifies every rule and message formatting,
 * since they never need to check for absence.
 */
public record EffectiveConfig(
        Path sourceFile,
        String profileLabel,
        Map<String, String> properties
) {
}