package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Rule;
import dev.scg.core.Severity;

import java.util.*;

/**
 * SCG002 — detecta spring.h2.console.enabled=true fora de profiles de
 * dev/test. O H2 console é uma UI web que permite rodar SQL arbitrário
 * contra o banco da aplicação — extremamente útil em dev, extremamente
 * perigoso se for parar em produção (é um dos achados mais comuns em
 * relatórios de pentest de apps Spring Boot).
 *
 * TODO 1: decida a chave a checar. Dica: mesma lógica de EXPOSURE_KEY
 * no ActuatorExposureRule, mas pra "spring.h2.console.enabled".
 *
 * TODO 2: decida como identificar "isso é um profile de dev/test".
 * Pergunta pra te guiar: o `sourceFile` que chega no método check()
 * já contém o nome do arquivo. Que substring nesse nome indicaria
 * "isso é seguro, pula a checagem"?
 *
 * TODO 3: monte o Finding. Reaproveite a estrutura de ActuatorExposureRule
 * como referência de estilo (severidade, mensagem clara, sugestão de correção).
 */
public final class H2ConsoleExposedRule implements Rule {

    private static final String H2_ENABLED_KEY = "spring.h2.console.enabled";

    private static final Set<String> SAFE_PROFILES = Set.of(
            "dev", "development", "test", "testing", "local"
    );

    @Override
    public String id() {
        return "SCG002";
    }

    @Override
    public String description() {
        return "H2 console habilitada fora de profile de dev/test";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        String currentProfile = config.profileLabel().toLowerCase(Locale.ROOT);
        if (SAFE_PROFILES.contains(currentProfile)) {
            return findings; // Ignora perfis seguros/locais
        }

        String enabledValue = config.properties().get(H2_ENABLED_KEY);
        if ("true".equalsIgnoreCase(enabledValue)) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    "H2 console habilitado (%s=true) no perfil '%s'. "
                            .formatted(H2_ENABLED_KEY, config.profileLabel())
                            + "Risco elevado de execução remota de código (RCE) e exposição de dados. "
                            + "Desabilite via 'spring.h2.console.enabled=false' fora de ambientes locais.",
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }

        return findings;
    }
}