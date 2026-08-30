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
    @DisplayName("Should NOT generate a finding when exposure.include is absent")
    void shouldNotGenerateFindingWhenExposureIncludeIsAbsent() {
        EffectiveConfig config = configWith(Map.of("server.port", "8080"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should NOT generate a finding when exposure.include does not contain a wildcard")
    void shouldNotGenerateFindingWhenExposureIncludeDoesNotContainWildcard() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "health,info"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should generate a HIGH finding with endpoints unrestricted by default " +
                 "when a wildcard is used without additional configuration")
    void shouldGenerateHighFindingWithEndpointsUnrestrictedByDefaultWhenWildcardIsUsedWithoutAdditionalConfig() {
        // No enabled/access configuration for any endpoint — shutdown and heapdump are
        // restricted by Spring's own default (BL-11), while the other four are not.

        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
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
    @DisplayName("Should NOT generate a Finding when a wildcard is used and all " +
                 "sensitive endpoints are disabled via enabled")
    void shouldNotGenerateFindingWhenWildcardIsUsedAndAllSensitiveEndpointsAreDisabledViaEnabled() {
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
    @DisplayName("Should list only endpoints still enabled after partial disabling")
    void shouldListOnlyEndpointsStillEnabledAfterPartialDisabling() {
        // heapdump is intentionally omitted here: without explicit configuration,
        // it is already restricted by default — it should not be included in stillEnabled.
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*",
                "management.endpoint.env.enabled", "false",
                "management.endpoint.shutdown.access", "none"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        String message = findings.getFirst().message();
        assertThat(message)
                .doesNotContain("env")
                .doesNotContain("shutdown")
                .doesNotContain("heapdump")
                .contains("threaddump")
                .contains("configprops")
                .contains("beans");
    }

    @Test
    @DisplayName("Should generate a finding when heapdump is explicitly unrestricted via access")
    void shouldGenerateFindingWhenHeapdumpIsExplicitlyUnrestrictedViaAccess() {
        // Cenário real testado empiricamente: access=unrestricted é o único jeito de expor
        // heapdump — se alguém fizer isso, a regra precisa continuar acusando, não silenciar
        // por causa do default restrito.
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
        assertThat(findings.getFirst().message()).contains("heapdump");
    }

    @Test
    @DisplayName("Should generate a finding when shutdown is explicitly unrestricted via access")
    void shouldGenerateFindingWhenShutdownIsExplicitlyUnrestrictedViaAccess() {
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
        assertThat(findings.getFirst().message()).contains("shutdown");
    }

    @Test
    @DisplayName("Should recognize a YAML indexed list with a wildcard")
    void shouldRecognizeYamlIndexedListWithWildcard() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include[0]", "health",
                "management.endpoints.web.exposure.include[1]", "*"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @Test
    @DisplayName("Should NOT throw an exception when the exposure value is null")
    void shouldNotThrowExceptionWhenExposureValueIsNull() {
        Map<String, String> properties = new java.util.HashMap<>();
        properties.put("management.endpoints.web.exposure.include", null);

        assertThat(rule.check(configWith(properties))).isEmpty();
    }

    @Test
    @DisplayName("Should NOT generate a finding when a normally unrestricted endpoint is disabled via access=none")
    void shouldNotGenerateFindingWhenNormallyUnrestrictedEndpointIsDisabledViaAccessNone() {
        // Empirically confirmed: access=none removes the endpoint from the context,
        // even for endpoints whose default is unrestricted (e.g., env). Tested against
        // a real Spring Boot 4.0.7 instance — env disappears from the discovery page
        // with this configuration, even with exposure.include=health,*.
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
    @DisplayName("Should generate a violation when Actuator exposure uses a placeholder with a wildcard fallback")
    void shouldGenerateViolationWhenActuatorExposureUsesPlaceholderWithWildcardFallback() {
        Map<String, String> props = Map.of("management.endpoints.web.exposure.include", "${ACTUATOR_EXPOSURE:*}");
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", props);

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        assertEquals("SCG001", findings.getFirst().ruleId());
    }

    @Test
    @DisplayName("Should flag when exposure.include is a dynamic placeholder without a default")
    void shouldFlagWhenExposureIncludeIsDynamicPlaceholderWithoutDefault() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "${EXPOSURE_ENDPOINTS}"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should NOT flag when exposure.include is a placeholder with a safe default")
    void shouldNotFlagWhenExposureIncludeIsPlaceholderWithSafeDefault() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "${EXPOSURE_ENDPOINTS:health,info}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should treat the endpoint as unrestricted when access is a dynamic placeholder without a default")
    void shouldTreatEndpointAsUnrestrictedWhenAccessIsDynamicPlaceholderWithoutDefault() {
        EffectiveConfig config = configWith(Map.ofEntries(
                Map.entry("management.endpoints.web.exposure.include", "*"),
                Map.entry("management.endpoint.env.enabled", "false"),
                Map.entry("management.endpoint.threaddump.enabled", "false"),
                Map.entry("management.endpoint.configprops.enabled", "false"),
                Map.entry("management.endpoint.beans.enabled", "false"),
                Map.entry("management.endpoint.heapdump.access", "${HEAPDUMP_ACCESS}")
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("heapdump");
    }
}