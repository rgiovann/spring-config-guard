package dev.scg.cli;

import dev.scg.core.Severity;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;

public final class CliArgumentParser {

    private static final String FAIL_ON_PREFIX = "--fail-on=";
    private static final String JSON_FLAG = "--json";
    private static final String POLICY_PREFIX = "--policy=";
    private static final String CONFIG_SERVER_FLAG = "--config-server";
    private static final String NONE = "NONE";

    public static final String HELP_FLAG = "--help";
    public static final String HELP_SHORT_FLAG = "-h";
    public static final String VERSION_FLAG = "--version";

    public static final String HELP_TEXT = """
            Usage: spring-config-guard <directory> [options]

            Analyzes application.{properties,yml,yaml} files of a Spring Boot project for
            security misconfigurations, and signals the result via exit code.

            Positional argument:
              <directory>          Root directory of the Spring Boot project to analyze.

            Options:
              --json               Emit the report as JSON instead of the console format.
              --config-server      Treat <directory> as a Spring Cloud Config Server
                                   repository instead of a single Spring Boot project:
                                   application*.{yml,yaml,properties} is the Global config
                                   shared by every client, and every other .yml/.yaml/
                                   .properties file directly in <directory> (not recursive)
                                   is one service's own config, named after the file.
              --fail-on=<level>    Minimum severity that makes the process exit with an
                                   error code: HIGH, MEDIUM, LOW, or NONE. Default: HIGH.
                                   NONE never fails the build, regardless of findings.
              --policy=<file>      YAML file suppressing findings by rule + profile
                                   (e.g. 'SCG002: [dev]'). Without this flag, no
                                   suppression is applied.
              --help, -h           Show this message and exit.
              --version            Show the version and exit.

            Examples:
              java -jar spring-config-guard.jar ./my-project
              java -jar spring-config-guard.jar ./my-project --fail-on=MEDIUM
              java -jar spring-config-guard.jar ./my-project --json --policy=scg-policy.yml
              java -jar spring-config-guard.jar ./my-config-repo --config-server

            Exit codes:
              0   Success - no finding at or above --fail-on's severity (or --fail-on=NONE).
              1   One or more findings at or above the configured severity.
              2   Usage error - invalid argument, missing directory, missing or malformed
                  policy file.
            """;

    public CliOptions parse(String[] args) {
        if (args.length == 0) {
            throw new CliUsageException(
                    "Usage: spring-config-guard <directory> [--json] [--config-server] " +
                            "[--fail-on=HIGH|MEDIUM|LOW|NONE] [--policy=<path>]"
            );
        }

        Path directory = Path.of(args[0]);
        boolean jsonOutput = false;
        boolean configServerMode = false;
        Optional<Severity> failOnSeverity = Optional.of(Severity.HIGH); // default
        Optional<Path> policyFile = Optional.empty();

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (JSON_FLAG.equals(arg)) {
                jsonOutput = true;
            } else if (CONFIG_SERVER_FLAG.equals(arg)) {
                configServerMode = true;
            } else if (arg.startsWith(FAIL_ON_PREFIX)) {
                failOnSeverity = parseFailOn(arg.substring(FAIL_ON_PREFIX.length()));
            } else if (arg.startsWith(POLICY_PREFIX)) {
                policyFile = Optional.of(Path.of(arg.substring(POLICY_PREFIX.length())));
            } else {
                throw new CliUsageException("Unknown argument: " + arg);
            }
        }

        return new CliOptions(directory, jsonOutput, configServerMode, failOnSeverity, policyFile);
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
                    "Invalid value for --fail-on: '%s' (expected HIGH, MEDIUM, LOW, or NONE)".formatted(rawValue)
            );
        }
    }
}