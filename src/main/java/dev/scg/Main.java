package dev.scg;

import dev.scg.cli.CliArgumentParser;
import dev.scg.cli.CliOptions;
import dev.scg.cli.CliUsageException;
import dev.scg.cli.ExitCodeResolver;
import dev.scg.cli.Version;
import dev.scg.core.*;
import dev.scg.policy.Policy;
import dev.scg.report.ConsoleReporter;
import dev.scg.report.JsonReporter;
import dev.scg.report.Reporter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public final class Main {

    public static void main(String[] args) {
        System.exit(run(args));
    }

    // Separate from main() so it's testable without killing the test process's JVM.
    static int run(String[] args) {
        if (requestsHelp(args)) {
            System.out.print(CliArgumentParser.HELP_TEXT);
            return ExitCodeResolver.SUCCESS;
        }
        if (hasArgument(args, CliArgumentParser.VERSION_FLAG)) {
            System.out.println(Version.describe());
            return ExitCodeResolver.SUCCESS;
        }

        CliOptions options;
        try {
            options = new CliArgumentParser().parse(args);
        } catch (CliUsageException e) {
            System.err.println("Usage error: " + e.getMessage());
            return ExitCodeResolver.USAGE_ERROR;
        }

        if (!Files.isDirectory(options.directory())) {
            System.err.printf("Error: '%s' is not a valid directory.%n", options.directory());
            return ExitCodeResolver.USAGE_ERROR;
        }

        List<EffectiveConfig> effectiveConfigs;
        try {
            effectiveConfigs = options.configServerMode()
                    ? new ConfigServerAssembler().assemble(options.directory())
                    : loadEffectiveConfigs(options.directory());
        } catch (IOException e) {
            System.err.println("Error reading configuration: " + e.getMessage());
            return ExitCodeResolver.USAGE_ERROR;
        }

        int unfollowedImportCount = ConfigImportCoverage.filesWithUnfollowedImport(effectiveConfigs).size();
        if (unfollowedImportCount > 0) {
            System.err.printf(
                    "spring-config-guard: %d file(s) import external configuration via spring.config.import that was not scanned.%n",
                    unfollowedImportCount);
        }

        int multiLocationCount = ConfigLocationCoverage.modulesWithMultipleLocations(effectiveConfigs).size();
        if (multiLocationCount > 0) {
            System.err.printf(
                    "spring-config-guard: %d application(s) have config files in more than one Spring config location, evaluated independently -- risks split across locations are not detected.%n",
                    multiLocationCount);
        }

        List<Rule> rules = RuleRegistry.discoverRules();
        if (rules.isEmpty()) {
            System.err.println(
                    "Error: no rules found via ServiceLoader " +
                            "(META-INF/services/dev.scg.core.Rule). Check whether the service " +
                            "file exists on the classpath and lists valid implementations."
            );
            return ExitCodeResolver.USAGE_ERROR;
        }

        RuleEngine engine;
        try {
            engine = new RuleEngine(rules);
        } catch (IllegalStateException e) {
            System.err.println("Startup error: " + e.getMessage());
            return ExitCodeResolver.USAGE_ERROR;
        }

        Policy policy = Policy.none();
        if (options.policyFile().isPresent()) {
            Path policyFile = options.policyFile().get();
            if (!Files.exists(policyFile)) {
                System.err.printf("Error: policy file '%s' not found.%n", policyFile);
                return ExitCodeResolver.USAGE_ERROR;
            }
            try {
                policy = Policy.load(policyFile, rules.stream().map(Rule::id).collect(Collectors.toSet()));
            } catch (IOException e) {
                System.err.println("Error reading policy file: " + e.getMessage());
                return ExitCodeResolver.USAGE_ERROR;
            } catch (IllegalArgumentException e) {
                System.err.println("Policy error: " + e.getMessage());
                return ExitCodeResolver.USAGE_ERROR;
            }
        }

        List<Finding> allFindings = engine.run(effectiveConfigs);
        List<Finding> findings = policy.apply(allFindings);
        int suppressedCount = allFindings.size() - findings.size();
        if (suppressedCount > 0) {
            System.err.printf("spring-config-guard: %d finding(s) suppressed by policy.%n", suppressedCount);
        }

        Reporter reporter = options.jsonOutput() ? new JsonReporter() : new ConsoleReporter();
        reporter.report(findings, System.out);

        return new ExitCodeResolver().resolve(findings, options.failOnSeverity());
    }

    private static boolean requestsHelp(String[] args) {
        return hasArgument(args, CliArgumentParser.HELP_FLAG) || hasArgument(args, CliArgumentParser.HELP_SHORT_FLAG);
    }

    private static boolean hasArgument(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    private static List<EffectiveConfig> loadEffectiveConfigs(Path directory) throws IOException {
        ConfigLoader loader = new ConfigLoader();
        ConfigFileGrouper grouper = new ConfigFileGrouper();
        ProfileMerger merger = new ProfileMerger();

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(directory));

        List<EffectiveConfig> result = new ArrayList<>();
        for (GroupedConfigFile group : groups) {
            for (EffectiveConfig effectiveConfig : merger.merge(group.mergedFile())) {
                Path correctedSource = group.sourceByProfileLabel()
                        .getOrDefault(effectiveConfig.profileLabel(), group.mergedFile().path());

                result.add(new EffectiveConfig(
                        correctedSource,
                        effectiveConfig.profileLabel(),
                        effectiveConfig.properties()
                ));
            }
        }
        return result;
    }


}