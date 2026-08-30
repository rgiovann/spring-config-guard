package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;


class FindingTest {

    private Finding findingOf(Severity severity, String sourceFile, String profileLabel) {
        return new Finding("SCGxxx", severity, "message", sourceFile, profileLabel);
    }

    @Test
    @DisplayName("Default order should sort by severity first")
    void defaultOrderShouldSortBySeverityFirst() {
        Finding low = findingOf(Severity.LOW, "a.yml", "prod");
        Finding high = findingOf(Severity.HIGH, "z.yml", "prod");

        List<Finding> sorted = Stream.of(low, high).sorted(Finding.DEFAULT_ORDER).toList();

        assertThat(sorted).containsExactly(high, low);
    }

    @Test
    @DisplayName("Default order should break ties by source file when severity is equal")
    void defaultOrderShouldBreakTiesBySourceFileWhenSeverityIsEqual() {
        Finding fromB = findingOf(Severity.HIGH, "b.yml", "prod");
        Finding fromA = findingOf(Severity.HIGH, "a.yml", "prod");

        List<Finding> sorted = Stream.of(fromB, fromA).sorted(Finding.DEFAULT_ORDER).toList();

        assertThat(sorted).containsExactly(fromA, fromB);
    }

    @Test
    @DisplayName("Default order should break ties by profile label when severity and source file are equal")
    void defaultOrderShouldBreakTiesByProfileLabelWhenSeverityAndSourceFileAreEqual() {
        Finding prod = findingOf(Severity.HIGH, "a.yml", "prod");
        Finding dev = findingOf(Severity.HIGH, "a.yml", "dev");

        List<Finding> sorted = Stream.of(prod, dev).sorted(Finding.DEFAULT_ORDER).toList();

        assertThat(sorted).containsExactly(dev, prod); // "dev" < "prod" alphabetically
    }

    @Test
    @DisplayName("Default order should be stable for an already sorted list")
    void defaultOrderShouldBeStableForAlreadySortedList() {
        Finding first = findingOf(Severity.HIGH, "a.yml", "dev");
        Finding second = findingOf(Severity.MEDIUM, "a.yml", "dev");
        Finding third = findingOf(Severity.LOW, "a.yml", "dev");

        List<Finding> sorted = Stream.of(first, second, third).sorted(Finding.DEFAULT_ORDER).toList();

        assertThat(sorted).containsExactly(first, second, third);
    }
}

