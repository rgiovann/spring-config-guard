package dev.scg.report;

import dev.scg.core.Finding;
import dev.scg.core.Severity;

import java.io.PrintStream;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class ConsoleReporter implements Reporter {

    @Override
    public void report(List<Finding> findings, PrintStream out) {
        if (findings.isEmpty()) {
            out.println("spring-config-guard: nenhuma violação encontrada.");
            return;
        }

        findings.stream()
                .sorted(Comparator.comparing(Finding::severity)
                        .thenComparing(Finding::sourceFile)
                        .thenComparing(Finding::profileLabel))
                .forEach(out::println);

        Map<Severity, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(Finding::severity, Collectors.counting()));

        out.println();
        out.println("Resumo: %d violação(ões) — HIGH: %d, MEDIUM: %d, LOW: %d".formatted(
                findings.size(),
                counts.getOrDefault(Severity.HIGH, 0L),
                counts.getOrDefault(Severity.MEDIUM, 0L),
                counts.getOrDefault(Severity.LOW, 0L)
        ));
    }
}