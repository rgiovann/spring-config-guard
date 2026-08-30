package dev.scg.report;

import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


class ConsoleReporterTest {

    private final ConsoleReporter reporter = new ConsoleReporter();

    private String captureReport(List<Finding> findings) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        reporter.report(findings, out);
        return buffer.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("Should print a no violations message when the list is empty")
    void shouldPrintNoViolationsMessageWhenListIsEmpty() {
        String output = captureReport(List.of());

        assertThat(output).contains("no violations found");
    }

    @Test
    @DisplayName("Should sort Findings by severity, then file, then profile")
    void shouldSortFindingsBySeverityThenFileThenProfile() {
        Finding low = new Finding("SCG010", Severity.LOW, "msg low", "b.yml", "prod");
        Finding high = new Finding("SCG001", Severity.HIGH, "msg high", "a.yml", "prod");
        Finding medium = new Finding("SCG005", Severity.MEDIUM, "msg medium", "a.yml", "dev");

        // Intentionally passed out of order — the reporter is responsible for sorting, not the caller.
        String output = captureReport(List.of(low, medium, high));

        int highIndex = output.indexOf("SCG001");
        int mediumIndex = output.indexOf("SCG005");
        int lowIndex = output.indexOf("SCG010");

        assertThat(highIndex).isLessThan(mediumIndex);
        assertThat(mediumIndex).isLessThan(lowIndex);
    }

    @Test
    @DisplayName("Should print a summary with count by severity")
    void shouldPrintSummaryWithCountBySeverity() {
        Finding high1 = new Finding("SCG001", Severity.HIGH, "msg", "a.yml", "prod");
        Finding high2 = new Finding("SCG002", Severity.HIGH, "msg", "a.yml", "prod");
        Finding low = new Finding("SCG010", Severity.LOW, "msg", "b.yml", "dev");

        String output = captureReport(List.of(high1, high2, low));

        assertThat(output)
                .contains("3 violation(s)")
                .contains("HIGH: 2")
                .contains("MEDIUM: 0")
                .contains("LOW: 1");
    }
}

