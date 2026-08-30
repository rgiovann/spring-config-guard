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
        List<Finding> sorted = findings.stream().sorted(Finding.DEFAULT_ORDER).toList();
        try {
            out.println(mapper.writeValueAsString(sorted));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to serialize findings to JSON", e);
        }
    }
}