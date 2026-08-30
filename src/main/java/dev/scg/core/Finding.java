package dev.scg.core;

import java.util.Comparator;

/**
 * Represents an issue found by a rule.
 * <p>
 * profileLabel identifies which effective configuration the finding occurred in
 * ("base", "dev", "prod", etc.) — never null or empty, following the same
 * convention as EffectiveConfig.profileLabel(). This allows the same rule,
 * when run against the same file, to report different issues in different
 * profiles
 * without ambiguity in the final message.
 */
public record Finding(
        String ruleId,
        Severity severity,
        String message,
        String sourceFile,
        String profileLabel

) {
    public static final Comparator<Finding> DEFAULT_ORDER =
            Comparator.comparing(Finding::severity)
                    .thenComparing(Finding::sourceFile)
                    .thenComparing(Finding::profileLabel);
    @Override
    public String toString() {
        return "[%s] %s (%s) [profile: %s] — %s".formatted(severity, ruleId, sourceFile, profileLabel, message);
    }
}
