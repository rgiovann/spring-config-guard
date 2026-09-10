package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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

    // new tests added

    @ParameterizedTest
    @ValueSource(strings = {"always", "ALWAYS", "when_authorized", "WHEN_AUTHORIZED", "when-authorized", "WHEN-AUTHORIZED"})
    @DisplayName("Should report HIGH when show-values is risky and endpoint is exposed explicitly without wildcard")
    void shouldReportHighWhenShowValuesIsRiskyAndEndpointExposedExplicitly(String showValues) {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "health,env,configprops",
                "management.endpoint.env.show-values", showValues
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG001");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message())
                .contains("management.endpoint.<id>.show-values")
                .contains("env");
    }

    @Test
    @DisplayName("Should report one single HIGH finding when both env and configprops have risky show-values")
    void shouldReportSingleHighFindingListingBothEndpointsWhenBothHaveRiskyShowValues() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "health,env,configprops",
                "management.endpoint.env.show-values", "always",
                "management.endpoint.configprops.show-values", "when-authorized"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message())
                .contains("env")
                .contains("configprops");
    }

    @Test
    @DisplayName("Should NOT report finding when show-values is safe (never)")
    void shouldNotReportFindingWhenShowValuesIsNever() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "env,configprops",
                "management.endpoint.env.show-values", "never",
                "management.endpoint.configprops.show-values", "NEVER"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should NOT report show-values finding if the endpoint is not reachable via exposure.include")
    void shouldNotReportShowValuesFindingWhenEndpointIsNotReachable() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "health,info",
                "management.endpoint.env.show-values", "always"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should NOT report show-values finding if the endpoint is restricted via access=none")
    void shouldNotReportShowValuesFindingWhenEndpointIsRestrictedViaAccessNone() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "env",
                "management.endpoint.env.access", "none",
                "management.endpoint.env.show-values", "always"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report INFO when show-values relies on an unresolved placeholder")
    void shouldReportInfoWhenShowValuesReliesOnUnresolvedPlaceholder() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "env",
                "management.endpoint.env.show-values", "${ENV_SHOW_VALUES}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message())
                .contains("management.endpoint.env.show-values")
                .contains("unresolved environment placeholder");
    }

    @Test
    @DisplayName("Should NOT false-positive on endpoint sharing a prefix with target endpoint (exact token match)")
    void shouldNotFalsePositiveOnEndpointSharingPrefixWithTarget() {
        // "environment" contém "env" como substring, mas não deve disparar o check do "env"
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "health,environment",
                "management.endpoint.env.show-values", "always"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should evaluate show-values correctly when exposure.include uses YAML list syntax")
    void shouldEvaluateShowValuesWhenExposureIncludeUsesYamlListSyntax() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include[0]", "health",
                "management.endpoints.web.exposure.include[1]", "configprops",
                "management.endpoint.configprops.show-values", "always"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("configprops");
    }

    @Test
    @DisplayName("Should respect relaxed binding for the compound-word show-values segment")
    void shouldSupportRelaxedBindingForShowValues() {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "env",
                "management.endpoint.env.showValues", "always"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should report both the wildcard-exposure finding and the show-values finding independently")
    void shouldReportBothWildcardAndShowValuesFindingsIndependently() {
        // heapdump and shutdown stay restricted by their own Spring default; threaddump and beans
        // are explicitly disabled here, leaving env and configprops as the wildcard finding's
        // stillEnabled list. env also has a risky show-values, so both blocks in check() must
        // fire independently in the same run.
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "*",
                "management.endpoint.threaddump.enabled", "false",
                "management.endpoint.beans.enabled", "false",
                "management.endpoint.env.show-values", "always"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.severity() == Severity.HIGH);
        assertThat(findings).anyMatch(f -> f.message().contains("contains * and exposes all endpoints"));
        assertThat(findings).anyMatch(f -> f.message().contains("management.endpoint.<id>.show-values"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"invalid", "sometimes", "true"})
    @DisplayName("Should stay silent for unrecognized show-values values (never/always/when-authorized only)")
    void shouldStaySilentForUnrecognizedShowValues(String unrecognizedValue) {
        EffectiveConfig config = configWith(Map.of(
                "management.endpoints.web.exposure.include", "env",
                "management.endpoint.env.show-values", unrecognizedValue
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should NOT throw an exception when show-values value is null")
    void shouldNotThrowExceptionWhenShowValuesIsNull() {
        Map<String, String> properties = new java.util.HashMap<>();
        properties.put("management.endpoints.web.exposure.include", "env");
        properties.put("management.endpoint.env.show-values", null);

        assertThat(rule.check(configWith(properties))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should report show-values finding regardless of active profile (Zero-Trust)")
    void shouldReportShowValuesFindingRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of(
                "management.endpoints.web.exposure.include", "env",
                "management.endpoint.env.show-values", "always"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }
}