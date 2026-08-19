package dev.scg.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.scg.core.Finding;

import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.util.List;

public final class JsonReporter implements Reporter {

    private final ObjectMapper mapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    public void report(List<Finding> findings, PrintStream out) {
        try {
            out.println(mapper.writeValueAsString(findings));
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao serializar findings para JSON", e);
        }
    }
}