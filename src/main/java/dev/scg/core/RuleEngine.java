package dev.scg.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs a set of rules against a list of config files and aggregates
 * the findings. It knows nothing about YAML, CLI, or Maven — it only orchestrates.
 * This separation (dumb engine + specific rules) is what will allow,
 * later on, the same engine to be reused both in the CLI and in a
 * Maven/Gradle plugin: the logic for "running rules" does not change;
 * only the caller changes.
 */
public final class RuleEngine {

    private final List<Rule> rules;

    public RuleEngine(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    public List<Finding> run(List<EffectiveConfig> effectiveConfigs){
        List<Finding> findings = new ArrayList<>();
        for (EffectiveConfig effectiveConfig : effectiveConfigs) {
            for (Rule rule : rules) {
                findings.addAll(rule.check(effectiveConfig));
            }
        }
        return findings;
    }

    public List<Rule> rules() {
        return rules;
    }
}
