package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ActuatorExposureRuleTest {

    private final ActuatorExposureRule rule = new ActuatorExposureRule();

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
    void deveGerarFindingHighQuandoAsteriscoENenhumEndpointSensivelDesabilitado() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("SCG001");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.sourceFile()).isEqualTo("application-prod.yml");
        assertThat(finding.profileLabel()).isEqualTo("prod");

        // Set.of() não garante ordem de iteração estável entre execuções da JVM —
        // checamos cada endpoint isoladamente, nunca a frase inteira numa ordem fixa.
        assertThat(finding.message())
                .contains("env")
                .contains("heapdump")
                .contains("threaddump")
                .contains("shutdown")
                .contains("configprops")
                .contains("beans");
    }

    @Test
    void naoDeveGerarFindingQuandoAsteriscoETodosEndpointsSensiveisDesabilitados() {
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
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*",
                "management.endpoint.env.enabled", "false",
                "management.endpoint.shutdown.enabled", "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        String message = findings.get(0).message();
        assertThat(message)
                .doesNotContain("env")
                .doesNotContain("shutdown")
                .contains("heapdump")
                .contains("threaddump")
                .contains("configprops")
                .contains("beans");
    }

    @Test
    void deveTratarDesabilitacaoComoCaseInsensitive() {
        // "FALSE" em vez de "false" — a regra usa equalsIgnoreCase, coerente
        // com o relaxed binding do Spring pra valores booleanos.
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*",
                "management.endpoint.env.enabled", "FALSE"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).message()).doesNotContain("env");
    }

    @Test
    void deveConsiderarValorDiferenteDeFalseComoAindaHabilitado() {
        // Qualquer valor que não seja literalmente "false" (ex: typo "flase")
        // deve contar como enabled=true — é o comportamento padrão do Spring
        // quando a chave existe mas não desabilita explicitamente.
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*",
                "management.endpoint.env.enabled", "flase"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).message()).contains("env");
    }

    @Test
    void deveGerarFindingQuandoAsteriscoEstiverEmFormatoDeListaYaml() {
        // Representação achatada de:
        // management.endpoints.web.exposure.include:
        //   - health
        //   - "*"
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include[0]", "health",
                "management.endpoints.web.exposure.include[1]", "*"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void deveGerarFindingQuandoAsteriscoEstiverMisturadoNaMesmaString() {
        // Casos como "health,*" ou "*,prometheus"
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "health,*"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @Test
    void naoDeveLancarExcecaoNemGerarFindingQuandoExposureIncludeForNulo() {
        // HashMap permite valores null (diferente de Map.of / Map.entry)
        Map<String, String> properties = new java.util.HashMap<>();
        properties.put("management.endpoints.web.exposure.include", null);

        EffectiveConfig config = configWith(properties);

        assertThat(rule.check(config)).isEmpty();
    }

}