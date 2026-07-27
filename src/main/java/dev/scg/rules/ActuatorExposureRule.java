package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Rule;
import dev.scg.core.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SCG001 — detecta management.endpoints.web.exposure.include=* sem que os
 * endpoints sensíveis estejam explicitamente desabilitados.
 *
 * Por que essa é a primeira regra? Porque é o erro mais comum e mais caro:
 * alguém copia um exemplo de tutorial (que expõe tudo pra facilitar debug)
 * e esquece de restringir antes de ir pra produção. O Actuat0r e o
 * springbooter (ferramentas de pentest que pesquisei) existem justamente
 * porque esse erro é comum o bastante pra virar vetor de ataque conhecido.
 *
 * Endpoints sensíveis segundo a doc do Spring Boot: env, heapdump, threaddump,
 * shutdown, configprops, beans. Nem todo projeto precisa bloquear todos —
 * mas se nenhum estiver desabilitado, é sinal forte de config copiada sem
 * revisão.
 */
public final class ActuatorExposureRule implements Rule {

    private static final String EXPOSURE_KEY = "management.endpoints.web.exposure.include";

    private static final Set<String> SENSITIVE_ENDPOINTS = Set.of(
            "env", "heapdump", "threaddump", "shutdown", "configprops", "beans"
    );

    @Override
    public String id() {
        return "SCG001";
    }

    @Override
    public String description() {
        return "Actuator exposto via exposure.include=* sem desabilitar endpoints sensíveis";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        String exposure = config.properties().get(EXPOSURE_KEY);
        if (exposure == null || !exposure.contains("*")) {
            return findings; // não expõe tudo, nada a checar aqui
        }

        List<String> stillEnabled = new ArrayList<>();
        for (String endpoint : SENSITIVE_ENDPOINTS) {
            String enabledKey = "management.endpoint." + endpoint + ".enabled";
            // se a chave não existe, o Spring assume enabled=true por padrão
            String enabledValue = config.properties().get(enabledKey);
            boolean explicitlyDisabled = "false".equalsIgnoreCase(enabledValue);
            if (!explicitlyDisabled) {
                stillEnabled.add(endpoint);
            }
        }

        if (!stillEnabled.isEmpty()) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    "%s=* expõe todos os endpoints via HTTP, e estes seguem habilitados sem restrição explícita: %s. "
                            .formatted(EXPOSURE_KEY, String.join(", ", stillEnabled))
                            + "Considere management.endpoint.<nome>.enabled=false para cada um, ou trocar '*' por uma lista explícita.",
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }

        return findings;
    }
}
