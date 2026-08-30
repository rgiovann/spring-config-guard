package dev.scg.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Discovers Rule implementations via ServiceLoader
 * (META-INF/services/dev.scg.core.Rule), allowing third-party rules
 * to be plugged in without editing Main or any central project class —
 * they only need to be on the classpath with the correct service file.
 *
 * Deterministic order: ServiceLoader does not guarantee stable ordering across
 * different modules/JARs, which would become significant once third-party
 * rules are added to the classpath alongside ours.
 * We explicitly sort by Rule.id() after discovery, ensuring
 * that the same set of rules always produces the same execution/reporting
 * order, regardless of how the classpath was assembled.
 */
public final class RuleRegistry {

    private RuleRegistry() {}

    public static List<Rule> discoverRules() {
        List<Rule> rules = new ArrayList<>();
        for (Rule rule : ServiceLoader.load(Rule.class)) {
            rules.add(rule);
        }
        rules.sort(Comparator.comparing(Rule::id));
        return List.copyOf(rules);
    }
}