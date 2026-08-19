package dev.scg.report;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JsonReporterTest {

    private final JsonReporter reporter = new JsonReporter();
    private final ObjectMapper mapper = new ObjectMapper();

    private String captureReport(List<Finding> findings) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        reporter.report(findings, out);
        return buffer.toString(StandardCharsets.UTF_8);
    }

    @Test
    void deveSerializarEDesserializarPreservandoTodosOsCampos() throws Exception {
        List<Finding> original = List.of(
                new Finding("SCG001", Severity.HIGH, "mensagem de teste", "application-prod.yml", "prod"),
                new Finding("SCG002", Severity.LOW, "outra mensagem", "application.yml", "__spring_config_guard_base__")
        );

        String json = captureReport(original);
        List<Finding> deserialized = mapper.readValue(json, new TypeReference<List<Finding>>() {});

        assertThat(deserialized).isEqualTo(original);
    }

    @Test
    void deveProduzirListaJsonVaziaQuandoNaoHaFindings() throws Exception {
        String json = captureReport(List.of());
        List<Finding> deserialized = mapper.readValue(json, new TypeReference<List<Finding>>() {});

        assertThat(deserialized).isEmpty();
    }
}