package dev.scg.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Roda um conjunto de regras contra uma lista de arquivos de config e agrega
 * os achados. Não sabe nada sobre YAML, CLI ou Maven — só orquestra.
 *
 * Essa separação (engine burro + regras específicas) é o que vai permitir,
 * mais pra frente, reaproveitar o mesmo engine tanto no CLI quanto num plugin
 * Maven/Gradle: a lógica de "rodar regras" não muda, só muda quem chama.
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
