package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SwaggerOpenApiExposedRuleTest {

    private final SwaggerOpenApiExposedRule rule = new SwaggerOpenApiExposedRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    @Test
    @DisplayName("Should stay silent when there is no springdoc.* key at all (no evidence of the dependency)")
    void shouldStaySilentWhenNoSpringdocKeyIsPresent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of("server.port", "8080"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should NOT be fooled by an unrelated key that merely starts with the same characters (prefix boundary)")
    void shouldIgnoreUnrelatedKeyWithSimilarPrefix() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of("springdocument.path", "/docs"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report MEDIUM when a springdoc.* key is present but neither enabled flag is disabled (default exposure)")
    void shouldReportMediumWhenSpringdocIsUsedWithoutDisablingEndpoints() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of("springdoc.swagger-ui.path", "/docs"));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG008");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("Both OpenAPI docs")
                .contains("Swagger UI");
    }

    @Test
    @DisplayName("Should stay silent when both api-docs and swagger-ui are explicitly disabled")
    void shouldStaySilentWhenBothFlagsAreExplicitlyFalse() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.api-docs.enabled", "false",
                "springdoc.swagger-ui.enabled", "false"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report MEDIUM when only api-docs is disabled but swagger-ui remains exposed")
    void shouldReportMediumWhenOnlyApiDocsIsDisabled() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.api-docs.enabled", "false",
                "springdoc.swagger-ui.enabled", "true"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("Swagger UI").doesNotContain("Both OpenAPI docs");
    }

    @Test
    @DisplayName("Should report MEDIUM when only swagger-ui is disabled but api-docs remains exposed")
    void shouldReportMediumWhenOnlySwaggerUiIsDisabled() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.api-docs.enabled", "true",
                "springdoc.swagger-ui.enabled", "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("OpenAPI docs").doesNotContain("Both OpenAPI docs");
    }

    @Test
    @DisplayName("Should treat a non-boolean value (e.g. '1') as not disabled, and therefore still exposed")
    void shouldTreatOtherValueAsStillExposed() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.api-docs.enabled", "1",
                "springdoc.swagger-ui.enabled", "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should escalate the message when show-actuator is enabled alongside the exposure")
    void shouldEscalateMessageWhenShowActuatorIsEnabled() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.swagger-ui.enabled", "true",
                "springdoc.show-actuator", "true"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("AGGRAVATING FACTOR");
    }

    @Test
    @DisplayName("Should NOT escalate the message when show-actuator is absent")
    void shouldNotEscalateMessageWhenShowActuatorIsAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of("springdoc.swagger-ui.enabled", "true"));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).doesNotContain("AGGRAVATING FACTOR");
    }

    @Test
    @DisplayName("Should report INFO when api-docs.enabled is a dynamic placeholder without a default")
    void shouldReportInfoForUnresolvedPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.api-docs.enabled", "${ENABLE_SWAGGER}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("unresolved environment placeholder");
    }

    @Test
    @DisplayName("Should report INFO when swagger-ui.enabled resolves to an empty placeholder default")
    void shouldReportInfoForEmptyFallback() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.swagger-ui.enabled", "${ENABLE_SWAGGER:}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("Should stay silent when a flag resolves to false through a placeholder default")
    void shouldStaySilentWhenPlaceholderDefaultResolvesToFalse() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.api-docs.enabled", "${ENABLE_API_DOCS:false}",
                "springdoc.swagger-ui.enabled", "${ENABLE_SWAGGER_UI:false}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should not throw when a springdoc property value is null, and treat it as NOT_SET (default exposure)")
    void shouldNotThrowWhenValueIsNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("springdoc.api-docs.enabled", null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "test", "local", "prod", "qa"})
    @DisplayName("Should report the exposure regardless of the profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of("springdoc.swagger-ui.enabled", "true"));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().ruleId()).isEqualTo("SCG008");
    }

    @Test
    @DisplayName("Should respect relaxed binding conventions (camelCase and snake_case within dot segments)")
    void shouldSupportRelaxedBindingFormats() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.apiDocs.enabled", "false",       // camelCase no segmento
                "springdoc.swagger_ui.enabled", "false"     // snake_case no segmento
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should return INFO on unresolved placeholder even if show-actuator is true")
    void shouldPrioritizeInfoSeverityOnUncertaintyEvenWithShowActuator() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "springdoc.api-docs.enabled", "${ENABLE_SWAGGER}",
                "springdoc.show-actuator", "true"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }
}
