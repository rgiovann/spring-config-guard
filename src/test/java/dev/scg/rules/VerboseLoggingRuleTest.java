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

class VerboseLoggingRuleTest {

    private final VerboseLoggingRule rule = new VerboseLoggingRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");

    @Test
    @DisplayName("Should stay silent when no verbose logging properties are set or values are safe")
    void shouldStaySilentWhenSafeOrAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "logging.level.root", "INFO",
                "debug", "false",
                "trace", "off"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "yes", "on", "1"})
    @DisplayName("Should report MEDIUM severity when 'debug' is enabled with truthy values")
    void shouldReportMediumOnDebugEnabled(String truthyValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of("debug", truthyValue));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG009");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("debug=" + truthyValue);
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "yes", "on", "1"})
    @DisplayName("Should report MEDIUM severity when 'trace' is enabled with truthy values")
    void shouldReportMediumOnTraceEnabled(String truthyValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of("trace", truthyValue));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG009");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("trace=" + truthyValue);
    }

    @ParameterizedTest
    @ValueSource(strings = {"DEBUG", "TRACE", "debug", "trace"})
    @DisplayName("Should report MEDIUM severity when 'logging.level.root' is set to DEBUG or TRACE")
    void shouldReportMediumOnRootLoggerRiskyLevels(String level) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "logging.level.root", level
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG009");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("Root logger level set to '" + level.toUpperCase() + "'");
    }

    @Test
    @DisplayName("Should report INFO severity when 'debug' contains an unresolved placeholder")
    void shouldReportInfoOnUnresolvedDebugPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "debug", "${DEBUG_ENABLED}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder '${DEBUG_ENABLED}'");
    }

    @Test
    @DisplayName("Should report MEDIUM severity when placeholder is resolved to a truthy value")
    void shouldReportMediumOnResolvedTruthyPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "debug", "${DEBUG_ENABLED:true}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should stay silent when placeholder resolves to a safe value")
    void shouldStaySilentOnResolvedSafePlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "logging.level.root", "${LOG_LEVEL:INFO}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should respect relaxed binding conventions for logging properties")
    void shouldSupportRelaxedBinding() {
        // "logging.level.root" has no compound-word segment (unlike e.g. "api-docs"), so there is no
        // kebab/camel/snake_case variant to test here — only case-folding across segments is a valid
        // relaxed-binding dimension for this key. A key like "logging_level_root" (dots replaced by
        // underscores) would NOT match: RelaxedProperties.canonicalize() strips '-'/'_' within a segment
        // but does not turn '_' into '.' — that conversion is the OS-env-var rule, deliberately out of
        // scope since ConfigLoader never reads env vars, only files.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "LOGGING.LEVEL.ROOT", "DEBUG"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should check rules regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of("debug", "true"));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should not throw and stay silent when all three properties are null")
    void shouldNotThrowWhenPropertiesAreNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("debug", null);
        properties.put("trace", null);
        properties.put("logging.level.root", null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"debug", "trace", "logging.level.root"})
    @DisplayName("Should stay silent when a property resolves to an empty placeholder default")
    void shouldStaySilentWhenPlaceholderResolvesToEmptyDefault(String key) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(key, "${SOME_VAR:}"));

        // Unlike SCG006/007/008 (credentials), an empty default here has no CWE-258-style
        // significance of its own — an empty value is simply not truthy / not a risky log level,
        // so it stays silent rather than raising a separate INFO finding.
        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report three independent findings when debug, trace, and logging.level.root are all risky")
    void shouldReportIndependentFindingsForEachTrigger() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "debug", "true",
                "trace", "true",
                "logging.level.root", "DEBUG"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(3);
        assertThat(findings).allSatisfy(finding -> {
            assertThat(finding.ruleId()).isEqualTo("SCG009");
            assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"WARN", "ERROR", "OFF", "banana"})
    @DisplayName("Should stay silent for non-risky or invalid logging.level.root values")
    void shouldStaySilentForNonRiskyRootLoggerLevels(String level) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of("logging.level.root", level));

        assertThat(rule.check(config)).isEmpty();
    }
}