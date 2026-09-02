package dev.scg.core;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Runs a set of rules against a list of config files and aggregates
 * the findings. It knows nothing about YAML, CLI, or Maven — it only orchestrates.
 * This separation (dumb engine + specific rules) is what will allow,
 * later on, the same engine to be reused both in the CLI and in a
 * Maven/Gradle plugin: the logic for "running rules" does not change;
 * only the caller changes.
 */
public final class RuleEngine  {

    private final List<Rule> rules;

    public RuleEngine(List<Rule> rules) {
        // 1. Ensures the list is neither null nor mutable
        List<Rule> immutableRules = List.copyOf(rules);

        // 2. Fail-fast: Initializes and validates each rule at Engine startup
        Yaml yaml = new Yaml();
        for (Rule rule : immutableRules) {
            initializeRule(rule, yaml);
        }

        this.rules = immutableRules;
    }

    public List<Rule> rules() {
        return rules;
    }

    public List<Finding> run(List<EffectiveConfig> effectiveConfigs) {
        List<Finding> findings = new ArrayList<>();
        for (EffectiveConfig effectiveConfig : effectiveConfigs) {
            for (Rule rule : rules) {
                findings.addAll(rule.check(effectiveConfig));
            }
        }
        return findings;
    }

    private static void initializeRule(Rule rule, Yaml yaml) {
        if (rule instanceof ConfigurableRule configurableRule) {
            String resourcePath = configurableRule.metadataResource();
            InputStream is = RuleEngine.class.getClassLoader().getResourceAsStream(resourcePath);

            if (is == null) {
                throw new IllegalStateException(
                        "FATAL: Required metadata file '%s' for rule '%s' was not found in classpath."
                                .formatted(resourcePath, rule.id())
                );
            }

            Map<String, List<String>> metadata;
            try (is) {
                metadata = yaml.load(is);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "FATAL: Failed to parse metadata file '%s' for rule '%s': %s"
                                .formatted(resourcePath, rule.id(), e.getMessage()), e
                );
            }

            if (metadata == null || metadata.isEmpty()) {
                throw new IllegalStateException(
                        "FATAL: Metadata file '%s' for rule '%s' is empty or malformed."
                                .formatted(resourcePath, rule.id())
                );
            }

            // Unifies internal validation exceptions into IllegalStateException
            try {
                configurableRule.configure(metadata);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "FATAL: Invalid metadata structure in '%s' for rule '%s': %s"
                                .formatted(resourcePath, rule.id(), e.getMessage()), e
                );
            }
        }
    }
}
