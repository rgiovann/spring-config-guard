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
        // BASE_PROFILE_LABEL is an internal sentinel, not a real Spring profile name (see its
        // Javadoc in ProfileMerger) -- printing it raw here would read as if a profile literally
        // named "__spring_config_guard_base__" existed. Translated only for this human-facing
        // rendering; JsonReporter intentionally keeps the raw sentinel (round-trip fidelity for
        // machine consumers, see JsonReporterTest), so this substitution must stay local to
        // toString() and not move into the Finding record's actual data.
        String profileDisplay = ProfileMerger.BASE_PROFILE_LABEL.equals(profileLabel)
                ? "base"
                : "profile: " + profileLabel;
        return "[%s] %s (%s) [%s] - %s".formatted(severity, ruleId, sourceFile, profileDisplay, message);
    }
}
