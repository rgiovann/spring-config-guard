package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Rule;
import dev.scg.core.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * SCG001 — detecta management.endpoints.web.exposure.include=* sem que os
 * endpoints sensíveis estejam explicitamente restritos.
 *
 * Endpoints sensíveis segundo a doc do Spring Boot: env, heapdump, threaddump,
 * shutdown, configprops, beans.
 *
 * A partir do Spring Boot 3.4, o controle de acesso por endpoint migrou de
 * management.endpoint.<id>.enabled (booleano, deprecated) para
 * management.endpoint.<id>.access (none | read-only | unrestricted).
 * Confirmado no Spring Boot 3.4 Configuration Changelog (wiki oficial do
 * repositório spring-projects/spring-boot) que a maioria dos endpoints tem
 * access=unrestricted por padrão — MAS shutdown (default=none desde a 3.4) e
 * heapdump (default=none desde a 3.5) são exceção. Confirmado também
 * empiricamente contra uma aplicação Spring Boot 4.1 real: heapdump só
 * aparece no discovery page depois de access=unrestricted explícito, mesmo
 * com exposure.include=*.
 */
public final class ActuatorExposureRule implements Rule {

    private static final String EXPOSURE_KEY = "management.endpoints.web.exposure.include";

    private static final Set<String> SENSITIVE_ENDPOINTS = Set.of(
            "env", "heapdump", "threaddump", "shutdown", "configprops", "beans"
    );

    // Confirmado: management.endpoint.shutdown.access e
    // management.endpoint.heapdump.access têm default "none" (restrito),
    // diferente dos outros endpoints sensíveis (default "unrestricted").
    // Sem essa distinção a regra gera falso positivo pra esses dois quando
    // nenhuma config explícita existe (BL-11).
    private static final Set<String> RESTRICTED_BY_DEFAULT = Set.of("shutdown", "heapdump");

    private static final String RESTRICTED_ACCESS_VALUE = "none";

    @Override
    public String id() {
        return "SCG001";
    }

    @Override
    public String description() {
        return "Actuator exposto via exposure.include=* sem restringir endpoints sensíveis";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        boolean hasWildcardExposure = config.properties().entrySet().stream()
                .filter(entry -> entry.getKey().equals(EXPOSURE_KEY)
                        || entry.getKey().startsWith(EXPOSURE_KEY + "["))
                .anyMatch(entry -> entry.getValue() != null && entry.getValue().contains("*"));

        if (!hasWildcardExposure) {
            return findings;
        }

        List<String> stillEnabled = new ArrayList<>();
        for (String endpoint : SENSITIVE_ENDPOINTS) {
            if (!isRestricted(config, endpoint)) {
                stillEnabled.add(endpoint);
            }
        }

        if (!stillEnabled.isEmpty()) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    "%s contém * e expõe todos os endpoints via HTTP, e estes seguem sem restrição de acesso: %s. "
                            .formatted(EXPOSURE_KEY, String.join(", ", stillEnabled))
                            + "Considere management.endpoint.<nome>.access=none para cada um, ou trocar '*' por uma lista explícita.",
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }

        return findings;
    }

    /**
     * Um endpoint é considerado restrito (não exposto na prática) quando:
     * 1. management.endpoint.<id>.access = "none" (mecanismo atual, 3.4+), OU
     * 2. management.endpoint.<id>.enabled = "false" (mecanismo legado), OU
     * 3. nenhuma das duas chaves está definida, e o endpoint é um dos que o
     *    próprio Spring Boot restringe por padrão (shutdown, heapdump).
     *
     * access tem precedência sobre enabled quando ambos estão presentes — é
     * o mecanismo mais novo dos dois. Essa ordem de precedência específica
     * (o que acontece se as duas chaves coexistirem com valores conflitantes)
     * não foi confirmada contra um cenário real; é a leitura mais razoável
     * da migração documentada, não um fato testado — registrar se algum dia
     * isso importar na prática.
     */
    private boolean isRestricted(EffectiveConfig config, String endpoint) {
        String accessValue = config.properties().get("management.endpoint." + endpoint + ".access");
        if (accessValue != null) {
            return RESTRICTED_ACCESS_VALUE.equalsIgnoreCase(accessValue.trim());
        }

        String enabledValue = config.properties().get("management.endpoint." + endpoint + ".enabled");
        if (enabledValue != null) {
            return "false".equalsIgnoreCase(enabledValue.trim());
        }

        return RESTRICTED_BY_DEFAULT.contains(endpoint);
    }
}