package dev.scg;

import dev.scg.cli.CliArgumentParser;
import dev.scg.cli.CliOptions;
import dev.scg.cli.CliUsageException;
import dev.scg.cli.ExitCodeResolver;
import dev.scg.core.*;
import dev.scg.report.ConsoleReporter;
import dev.scg.report.JsonReporter;
import dev.scg.report.Reporter;
import dev.scg.rules.ActuatorExposureRule;
import dev.scg.rules.H2ConsoleExposedRule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class Main {

    public static void main(String[] args) {
        System.exit(run(args));
    }

    // Separado de main() para ser testável sem matar a JVM do processo de teste.
    static int run(String[] args) {
        CliOptions options;
        try {
            options = new CliArgumentParser().parse(args);
        } catch (CliUsageException e) {
            System.err.println("Erro de uso: " + e.getMessage());
            return ExitCodeResolver.USAGE_ERROR;
        }

        if (!Files.isDirectory(options.directory())) {
            System.err.println("Erro: '%s' não é um diretório válido.".formatted(options.directory()));
            return ExitCodeResolver.USAGE_ERROR;
        }

        List<EffectiveConfig> effectiveConfigs;
        try {
            effectiveConfigs = loadEffectiveConfigs(options.directory());
        } catch (IOException e) {
            System.err.println("Erro ao ler configurações: " + e.getMessage());
            return ExitCodeResolver.USAGE_ERROR;
        }

        RuleEngine engine = new RuleEngine(defaultRules());
        List<Finding> findings = engine.run(effectiveConfigs);

        Reporter reporter = options.jsonOutput() ? new JsonReporter() : new ConsoleReporter();
        reporter.report(findings, System.out);

        return new ExitCodeResolver().resolve(findings, options.failOnSeverity());
    }

    private static List<EffectiveConfig> loadEffectiveConfigs(Path directory) throws IOException {
        ConfigLoader loader = new ConfigLoader();
        ProfileMerger merger = new ProfileMerger();

        List<EffectiveConfig> result = new ArrayList<>();
        for (ConfigFile configFile : loader.loadDirectory(directory)) {
            result.addAll(merger.merge(configFile));
        }
        return result;
    }

    private static List<Rule> defaultRules() {
        return List.of(
                new ActuatorExposureRule(),
                new H2ConsoleExposedRule()
        );
    }
}