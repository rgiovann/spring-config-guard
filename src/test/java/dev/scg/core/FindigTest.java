package dev.scg.core;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class FindingTest {

    private Finding findingOf(Severity severity, String sourceFile, String profileLabel) {
        return new Finding("SCGxxx", severity, "mensagem", sourceFile, profileLabel);
    }

    @Test
    void defaultOrderDeveOrdenarPorSeveridadePrimeiro() {
        Finding low = findingOf(Severity.LOW, "a.yml", "prod");
        Finding high = findingOf(Severity.HIGH, "z.yml", "prod");

        List<Finding> sorted = Stream.of(low, high).sorted(Finding.DEFAULT_ORDER).toList();

        assertThat(sorted).containsExactly(high, low);
    }

    @Test
    void defaultOrderDeveDesempatarPorSourceFileQuandoSeveridadeIgual() {
        Finding fromB = findingOf(Severity.HIGH, "b.yml", "prod");
        Finding fromA = findingOf(Severity.HIGH, "a.yml", "prod");

        List<Finding> sorted = Stream.of(fromB, fromA).sorted(Finding.DEFAULT_ORDER).toList();

        assertThat(sorted).containsExactly(fromA, fromB);
    }

    @Test
    void defaultOrderDeveDesempatarPorProfileLabelQuandoSeveridadeESourceFileIguais() {
        Finding prod = findingOf(Severity.HIGH, "a.yml", "prod");
        Finding dev = findingOf(Severity.HIGH, "a.yml", "dev");

        List<Finding> sorted = Stream.of(prod, dev).sorted(Finding.DEFAULT_ORDER).toList();

        assertThat(sorted).containsExactly(dev, prod); // "dev" < "prod" alfabeticamente
    }

    @Test
    void defaultOrderDeveSerEstavelParaListaJaOrdenada() {
        Finding first = findingOf(Severity.HIGH, "a.yml", "dev");
        Finding second = findingOf(Severity.MEDIUM, "a.yml", "dev");
        Finding third = findingOf(Severity.LOW, "a.yml", "dev");

        List<Finding> sorted = Stream.of(first, second, third).sorted(Finding.DEFAULT_ORDER).toList();

        assertThat(sorted).containsExactly(first, second, third);
    }
}