package dev.scg.report;

import dev.scg.core.Finding;
import dev.scg.core.Severity;
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
    void deveImprimirMensagemDeNenhumaViolacaoQuandoListaVazia() {
        String output = captureReport(List.of());

        assertThat(output).contains("nenhuma violação encontrada");
    }

    @Test
    void deveOrdenarFindingsPorSeveridadeDepoisArquivoDepoisProfile() {
        Finding low = new Finding("SCG010", Severity.LOW, "msg low", "b.yml", "prod");
        Finding high = new Finding("SCG001", Severity.HIGH, "msg high", "a.yml", "prod");
        Finding medium = new Finding("SCG005", Severity.MEDIUM, "msg medium", "a.yml", "dev");

        // Passados fora de ordem de propósito — o reporter é quem deve ordenar, não quem chama.
        String output = captureReport(List.of(low, medium, high));

        int highIndex = output.indexOf("SCG001");
        int mediumIndex = output.indexOf("SCG005");
        int lowIndex = output.indexOf("SCG010");

        assertThat(highIndex).isLessThan(mediumIndex);
        assertThat(mediumIndex).isLessThan(lowIndex);
    }

    @Test
    void deveImprimirResumoComContagemPorSeveridade() {
        Finding high1 = new Finding("SCG001", Severity.HIGH, "msg", "a.yml", "prod");
        Finding high2 = new Finding("SCG002", Severity.HIGH, "msg", "a.yml", "prod");
        Finding low = new Finding("SCG010", Severity.LOW, "msg", "b.yml", "dev");

        String output = captureReport(List.of(high1, high2, low));

        assertThat(output)
                .contains("3 violação(ões)")
                .contains("HIGH: 2")
                .contains("MEDIUM: 0")
                .contains("LOW: 1");
    }
}