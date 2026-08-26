package dev.scg.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Descobre implementações de Rule via ServiceLoader
 * (META-INF/services/dev.scg.core.Rule), permitindo que regras de terceiros
 * sejam plugadas sem editar Main nem qualquer classe central do projeto —
 * basta estar no classpath com o arquivo de serviço correto.
 *
 * Ordem determinística: ServiceLoader não garante ordem estável entre
 * módulos/JARs diferentes, o que passaria a importar de verdade no momento
 * em que regras de terceiros entrarem no classpath junto com as nossas.
 * Ordenamos explicitamente por Rule.id() depois da descoberta, garantindo
 * que o mesmo conjunto de regras produz sempre a mesma ordem de execução/
 * relatório, independente de como o classpath foi montado.
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