package dev.scg.cli;

import dev.scg.core.Severity;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/**
 * @param failOnSeverity Optional.empty() means "--fail-on=NONE": never fails the exit code,
 *                        regardless of findings.
 * @param policyFile Optional.empty() means no suppression policy (current behavior, no
 *                    filtering). See {@code dev.scg.policy.Policy}.
 */
public record CliOptions(
        Path directory,
        boolean jsonOutput,
        Optional<Severity> failOnSeverity,
        Optional<Path> policyFile
) {
    public CliOptions {
        Objects.requireNonNull(directory, "directory must not be null");
        Objects.requireNonNull(failOnSeverity, "failOnSeverity must not be null (use Optional.empty())");
        Objects.requireNonNull(policyFile, "policyFile must not be null (use Optional.empty())");
    }
}