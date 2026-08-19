package dev.scg.cli;

import dev.scg.core.Finding;
import dev.scg.core.Severity;

import java.util.List;
import java.util.Optional;

public final class ExitCodeResolver {

    public static final int SUCCESS = 0;
    public static final int THRESHOLD_EXCEEDED = 1;
    public static final int USAGE_ERROR = 2;

    public int resolve(List<Finding> findings, Optional<Severity> failOnSeverity) {
        if (failOnSeverity.isEmpty()) {
            return SUCCESS;
        }
        Severity threshold = failOnSeverity.get();
        boolean exceedsThreshold = findings.stream()
                .anyMatch(finding -> finding.severity().ordinal() <= threshold.ordinal());
        return exceedsThreshold ? THRESHOLD_EXCEEDED : SUCCESS;
    }
}