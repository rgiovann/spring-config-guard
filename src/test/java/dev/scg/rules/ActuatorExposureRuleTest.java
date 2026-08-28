package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ActuatorExposureRuleTest {

    private final ActuatorExposureRule rule = new ActuatorExposureRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    private EffectiveConfig configWith(Map<String, String> properties) {
        return new EffectiveConfig(Path.of("application-prod.yml"), "prod", properties);
    }

    @Test
    void naoDeveGerarFindingQuandoExposureIncludeAusente() {
        EffectiveConfig config = configWith(Map.of("server.port", "8080"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    void naoDeveGerarFindingQuandoExposureIncludeNaoContemAsterisco() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "health,info"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    void deveGerarFindingHighComEndpointsUnrestrictedPorPadraoQuandoAsteriscoENenhumaConfigExtra() {
        // Nenhuma config de enabled/access para nenhum endpoint — shutdown e
        // heapdump são restritos pelo próprio default do Spring (BL-11), os
        // outros quatro não são.
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("SCG001");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);

        assertThat(finding.message())
                .contains("env")
                .contains("threaddump")
                .contains("configprops")
                .contains("beans")
                .doesNotContain("shutdown")
                .doesNotContain("heapdump");
    }

    @Test
    void naoDeveGerarFindingQuandoAsteriscoETodosEndpointsSensiveisDesabilitadosViaEnabled() {
        EffectiveConfig config = configWith(Map.ofEntries(
                Map.entry("management.endpoints.web.exposure.include", "*"),
                Map.entry("management.endpoint.env.enabled", "false"),
                Map.entry("management.endpoint.heapdump.enabled", "false"),
                Map.entry("management.endpoint.threaddump.enabled", "false"),
                Map.entry("management.endpoint.shutdown.enabled", "false"),
                Map.entry("management.endpoint.configprops.enabled", "false"),
                Map.entry("management.endpoint.beans.enabled", "false")
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    void deveListarApenasEndpointsAindaHabilitadosQuandoDesabilitacaoParcial() {
        // heapdump não aparece aqui de propósito: sem config explícita, ele
        // já é restrito por padrão — não deveria estar em stillEnabled.
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*",
                "management.endpoint.env.enabled", "false",
                "management.endpoint.shutdown.access", "none"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        String message = findings.get(0).message();
        assertThat(message)
                .doesNotContain("env")
                .doesNotContain("shutdown")
                .doesNotContain("heapdump")
                .contains("threaddump")
                .contains("configprops")
                .contains("beans");
    }

    @Test
    void deveGerarFindingQuandoHeapdumpDesbloqueadoExplicitamenteViaAccessUnrestricted() {
        // Cenário real testado empiricamente: access=unrestricted é o único
        // jeito de expor heapdump — se alguém fizer isso, a regra precisa
        // continuar acusando, não silenciar por causa do default restrito.
        EffectiveConfig config = configWith(Map.ofEntries(
                Map.entry("management.endpoints.web.exposure.include", "*"),
                Map.entry("management.endpoint.env.enabled", "false"),
                Map.entry("management.endpoint.threaddump.enabled", "false"),
                Map.entry("management.endpoint.shutdown.enabled", "false"),
                Map.entry("management.endpoint.configprops.enabled", "false"),
                Map.entry("management.endpoint.beans.enabled", "false"),
                Map.entry("management.endpoint.heapdump.access", "unrestricted")
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).message()).contains("heapdump");
    }

    @Test
    void deveGerarFindingQuandoShutdownDesbloqueadoExplicitamenteViaAccessUnrestricted() {
        EffectiveConfig config = configWith(Map.ofEntries(
                Map.entry("management.endpoints.web.exposure.include", "*"),
                Map.entry("management.endpoint.env.enabled", "false"),
                Map.entry("management.endpoint.threaddump.enabled", "false"),
                Map.entry("management.endpoint.heapdump.enabled", "false"),
                Map.entry("management.endpoint.configprops.enabled", "false"),
                Map.entry("management.endpoint.beans.enabled", "false"),
                Map.entry("management.endpoint.shutdown.access", "unrestricted")
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).message()).contains("shutdown");
    }

    @Test
    void deveReconhecerListaDeIndicesYamlComWildcard() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include[0]", "health",
                "management.endpoints.web.exposure.include[1]", "*"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @Test
    void naoDeveLancarExcecaoQuandoValorDeExposureENull() {
        Map<String, String> properties = new java.util.HashMap<>();
        properties.put("management.endpoints.web.exposure.include", null);

        assertThat(rule.check(configWith(properties))).isEmpty();
    }

    @Test
    void naoDeveGerarFindingQuandoEndpointNormalmenteUnrestrictedForaDesabilitadoViaAccessNone() {
        // Confirmado empiricamente: access=none remove o endpoint do contexto,
        // mesmo em endpoints cujo default é unrestricted (ex: env). Testado
        // contra Spring Boot 4.0.7 real — env desaparece do discovery page com
        // essa config, mesmo com exposure.include=health,*.
        EffectiveConfig config = configWith(Map.ofEntries(
                Map.entry("management.endpoints.web.exposure.include", "health,*"),
                Map.entry("management.endpoint.env.access", "none"),
                Map.entry("management.endpoint.threaddump.enabled", "false"),
                Map.entry("management.endpoint.configprops.enabled", "false"),
                Map.entry("management.endpoint.beans.enabled", "false")
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Deve disparar violação quando exposure.include usa placeholder com fallback '*'")
    void deveDispararViolacaoQuandoActuatorExposureUsaPlaceholderComFallbackWildcard() {
        Map<String, String> props = Map.of("management.endpoints.web.exposure.include", "${ACTUATOR_EXPOSURE:*}");
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", props);

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        assertEquals("SCG001", findings.getFirst().ruleId());
    }
}