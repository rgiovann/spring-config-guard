package dev.scg.cli;

import dev.scg.core.Severity;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;

public final class CliArgumentParser {

    private static final String FAIL_ON_PREFIX = "--fail-on=";
    private static final String JSON_FLAG = "--json";
    private static final String NONE = "NONE";

    public CliOptions parse(String[] args) {
        if (args.length == 0) {
            throw new CliUsageException(
                    "Uso: spring-config-guard <diretorio> [--json] [--fail-on=HIGH|MEDIUM|LOW|NONE]"
            );
        }

        Path directory = Path.of(args[0]);
        boolean jsonOutput = false;
        Optional<Severity> failOnSeverity = Optional.of(Severity.HIGH); // default

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (JSON_FLAG.equals(arg)) {
                jsonOutput = true;
            } else if (arg.startsWith(FAIL_ON_PREFIX)) {
                failOnSeverity = parseFailOn(arg.substring(FAIL_ON_PREFIX.length()));
            } else {
                throw new CliUsageException("Argumento desconhecido: " + arg);
            }
        }

        return new CliOptions(directory, jsonOutput, failOnSeverity);
    }

    private Optional<Severity> parseFailOn(String rawValue) {
        String value = rawValue.strip().toUpperCase(Locale.ROOT);
        if (NONE.equals(value)) {
            return Optional.empty();
        }
        try {
            return Optional.of(Severity.valueOf(value));
        } catch (IllegalArgumentException e) {
            throw new CliUsageException(
                    "Valor inválido para --fail-on: '%s' (esperado HIGH, MEDIUM, LOW ou NONE)".formatted(rawValue)
            );
        }
    }
}