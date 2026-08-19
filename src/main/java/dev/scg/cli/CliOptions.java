package dev.scg.cli;

import dev.scg.core.Severity;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/**
 * @param failOnSeverity Optional.empty() significa "--fail-on=NONE": nunca falha o exit code,
 *                        independentemente dos Findings encontrados.
 */
public record CliOptions(
        Path directory,
        boolean jsonOutput,
        Optional<Severity> failOnSeverity
) {
    public CliOptions {
        Objects.requireNonNull(directory, "directory não pode ser null");
        Objects.requireNonNull(failOnSeverity, "failOnSeverity não pode ser null (use Optional.empty())");
    }
}