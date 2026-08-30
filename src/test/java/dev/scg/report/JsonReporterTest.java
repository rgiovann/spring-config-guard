package dev.scg.report;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
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
    @DisplayName("Should serialize and deserialize while preserving all fields")
    void shouldSerializeAndDeserializePreservingAllFields() throws Exception {
        List<Finding> original = List.of(
                new Finding("SCG001", Severity.HIGH, "test message", "application-prod.yml", "prod"),
                new Finding("SCG002", Severity.LOW, "another message", "application.yml", "__spring_config_guard_base__")
        );

        String json = captureReport(original);
        List<Finding> deserialized = mapper.readValue(json, new TypeReference<List<Finding>>() {});

        assertThat(deserialized).isEqualTo(original);
    }

    @Test
    @DisplayName("Should produce an empty JSON list when there are no Findings")
    void shouldProduceEmptyJsonListWhenThereAreNoFindings() throws Exception {
        String json = captureReport(List.of());
        List<Finding> deserialized = mapper.readValue(json, new TypeReference<List<Finding>>() {});

        assertThat(deserialized).isEmpty();
    }

    @Test
    @DisplayName("Should always serialize in the same order regardless of input order")
    void shouldAlwaysSerializeInSameOrderRegardlessOfInputOrder() throws Exception {
        Finding low = new Finding("SCG010", Severity.LOW, "msg", "b.yml", "dev");
        Finding high = new Finding("SCG001", Severity.HIGH, "msg", "a.yml", "prod");
        Finding medium = new Finding("SCG005", Severity.MEDIUM, "msg", "a.yml", "dev");

        // Intentionally passed out of order, just as we already did in ConsoleReporterTest —
        // specific regression for execution-order instability that
        // ConfigFileGrouper/Files.walk could introduce in the JSON output.
        String json = captureReport(List.of(low, medium, high));
        List<Finding> deserialized = mapper.readValue(json, new TypeReference<List<Finding>>() {});

        assertThat(deserialized).containsExactly(high, medium, low);
    }
}

