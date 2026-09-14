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

class VerboseErrorResponseRuleTest {

    private final VerboseErrorResponseRule rule = new VerboseErrorResponseRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");

    @Test
    @DisplayName("Should stay silent when all server.error.* properties are safe or absent")
    void shouldStaySilentWhenSafeOrAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", "never",
                "server.error.include-exception", "false",
                "server.error.include-message", "never",
                "server.error.include-binding-errors", "never"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "always", "ALWAYS",
            "on_param", "ON_PARAM",
            "on-param", "ON-PARAM",
            "onParam", "ONPARAM"
    })
    @DisplayName("Should report HIGH severity when include-stacktrace is set to risky enum values")
    void shouldReportHighOnRiskyIncludeStacktrace(String enumValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", enumValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG010");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("server.error.include-stacktrace=" + enumValue);
    }

    @ParameterizedTest
    @ValueSource(strings = {"on.param", "on param"})
    @DisplayName("Should report HIGH even for atypical separators, proving canonicalize() strips any non-alphanumeric char")
    void shouldReportHighOnAtypicalSeparators(String enumValue) {
        // Not real Spring Boot authoring styles, but they prove the canonicalize() comparison
        // (shared approach with SCG001/SCG013) isn't secretly hardcoded to just '-'/'_' the way
        // the old Set<String> + toUpperCase() approach was -- that older approach missed
        // "onParam" specifically because it has no separator to match a Set entry written with one.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", enumValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "yes", "1"})
    @DisplayName("Should stay silent when enum properties receive boolean values that fail binding at startup")
    void shouldStaySilentOnInvalidEnumValuesForIncludeStacktrace(String invalidValue) {
        // "true"/"yes"/"1" are not valid IncludeAttribute values — Spring Boot itself would fail
        // to bind this at startup, so it does not behave like "always". The rule must stay silent
        // instead of raising a false finding.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", invalidValue
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "yes", "on", "1"})
    @DisplayName("Should report MEDIUM severity when include-exception boolean property is truthy")
    void shouldReportMediumOnTruthyIncludeException(String truthyValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-exception", truthyValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG010");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("server.error.include-exception=" + truthyValue);
    }

    @ParameterizedTest
    @ValueSource(strings = {"always", "ON_PARAM"})
    @DisplayName("Should report MEDIUM severity when include-message is set to risky enum values")
    void shouldReportMediumOnRiskyIncludeMessage(String enumValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-message", enumValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"always", "ON_PARAM"})
    @DisplayName("Should report MEDIUM severity (not LOW) when include-binding-errors is set to risky enum values")
    void shouldReportMediumOnRiskyIncludeBindingErrors(String enumValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-binding-errors", enumValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should report INFO severity when property relies on an unresolved placeholder")
    void shouldReportInfoOnUnresolvedPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", "${SHOW_STACKTRACE}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder '${SHOW_STACKTRACE}'");
    }

    @Test
    @DisplayName("Should report HIGH severity when placeholder is resolved to a risky enum value")
    void shouldReportHighOnResolvedPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", "${SHOW_STACKTRACE:always}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should stay silent when placeholder is resolved to a safe value via its default")
    void shouldStaySilentOnResolvedSafePlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", "${SHOW_STACKTRACE:never}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "server.error.include-stacktrace",
            "server.error.include-exception",
            "server.error.include-message",
            "server.error.include-binding-errors"
    })
    @DisplayName("Should stay silent when a property resolves to an empty placeholder default")
    void shouldStaySilentWhenPlaceholderResolvesToEmptyDefault(String key) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(key, "${SOME_VAR:}"));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "server.error.include-stacktrace",
            "server.error.include-message",
            "server.error.include-binding-errors"
    })
    @DisplayName("Should stay silent when an enum property receives an unrecognized value")
    void shouldStaySilentOnUnrecognizedEnumValue(String key) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(key, "sometimes"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should respect relaxed binding case-folding across segments")
    void shouldSupportRelaxedBinding() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "SERVER.ERROR.INCLUDE-STACKTRACE", "ALWAYS"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should not throw and stay silent when property values are null")
    void shouldNotThrowWhenPropertiesAreNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("server.error.include-stacktrace", null);
        properties.put("server.error.include-exception", null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report four independent findings when all error properties are set to risky values")
    void shouldReportIndependentFindingsForEachTrigger() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", "always",
                "server.error.include-exception", "true",
                "server.error.include-message", "always",
                "server.error.include-binding-errors", "always"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(4);
        assertThat(findings.stream().map(Finding::severity))
                .containsExactlyInAnyOrder(Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should check rules regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of(
                "server.error.include-stacktrace", "always"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }
}