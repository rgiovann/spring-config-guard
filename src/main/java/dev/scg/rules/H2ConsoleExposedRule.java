package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Rule;
import dev.scg.core.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

    private static final String H2_ENABLED_KEY = ""; // TODO 1

    @Override
    public String id() {
        return "SCG002";
    }

    @Override
    public String description() {
        return "H2 console habilitada fora de profile de dev/test";
    }

    @Override
    public List<Finding> check(EffectiveConfig config)  {
        List<Finding> findings = new ArrayList<>();

        // TODO 2: se o sourceFile indicar profile de dev/test, retorne
        // findings vazio aqui (early return, mesmo padrão do SCG001
        // quando exposure.include não continha "*").

        // TODO 1 (continuação): pegue o valor da chave H2_ENABLED_KEY
        // do config e verifique se é "true" (cuidado: comparação de
        // String ignorando maiúsculas/minúsculas, igual fizemos em
        // ActuatorExposureRule com equalsIgnoreCase).

        // TODO 3: se estiver habilitado, adicione o Finding com
        // Severity.HIGH e uma mensagem explicando o risco + sugestão.

        return findings;
    }
}