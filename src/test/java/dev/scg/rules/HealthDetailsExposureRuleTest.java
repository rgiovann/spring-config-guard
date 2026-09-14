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

class HealthDetailsExposureRuleTest {

    private final HealthDetailsExposureRule rule = new HealthDetailsExposureRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");
    private static final String KEY = "management.endpoint.health.show-details";

    @Test
    @DisplayName("Should stay silent when show-details is absent")
    void shouldStaySilentWhenAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of());

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when show-details is explicitly set to the safe default")
    void shouldStaySilentWhenNever() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, "never"));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "always", "ALWAYS",
            "when-authorized", "WHEN-AUTHORIZED",
            "when_authorized", "WHEN_AUTHORIZED",
            "whenAuthorized", "WHENAUTHORIZED"
    })
    @DisplayName("Should report MEDIUM severity when show-details is set to a risky value, any separator/casing style")
    void shouldReportMediumOnRiskyValue(String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, value));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG013");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains(KEY + "=" + value);
    }

    @ParameterizedTest
    @ValueSource(strings = {"when.authorized", "when authorized"})
    @DisplayName("Should report MEDIUM even for atypical separators, proving canonicalize() strips any non-alphanumeric char")
    void shouldReportMediumOnAtypicalSeparators(String value) {
        // "when.authorized" (dot) and "when authorized" (internal space, which raw.strip() does not
        // touch since it only trims leading/trailing) are not real Spring Boot authoring styles, but
        // they prove canonicalize() is not secretly hardcoded to just '-'/'_' the way the old
        // Set<String>+toUpperCase() approach was.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, value));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    @DisplayName("Should not throw and stay silent when show-details is present but blank")
    void shouldStaySilentWhenValueIsBlank(String blankValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, blankValue));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when show-details receives an unrecognized value")
    void shouldStaySilentOnUnrecognizedValue() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, "sometimes"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report INFO severity when show-details relies on an unresolved placeholder")
    void shouldReportInfoOnUnresolvedPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, "${SHOW_DETAILS}"));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder '${SHOW_DETAILS}'");
    }

    @Test
    @DisplayName("Should report MEDIUM severity when placeholder resolves to a risky value via its default")
    void shouldReportMediumOnResolvedRiskyPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, "${SHOW_DETAILS:always}"));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should stay silent when placeholder resolves to a safe value via its default")
    void shouldStaySilentOnResolvedSafePlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, "${SHOW_DETAILS:never}"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when placeholder resolves to an empty default")
    void shouldStaySilentWhenPlaceholderResolvesToEmptyDefault() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(KEY, "${SOME_VAR:}"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should respect relaxed binding case-folding across segments")
    void shouldSupportRelaxedBinding() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "MANAGEMENT.ENDPOINT.HEALTH.SHOW-DETAILS", "ALWAYS"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should not throw and stay silent when the property value is null")
    void shouldNotThrowWhenPropertyIsNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put(KEY, null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should report regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of(KEY, "always"));

        assertThat(rule.check(config)).hasSize(1);
    }
}
