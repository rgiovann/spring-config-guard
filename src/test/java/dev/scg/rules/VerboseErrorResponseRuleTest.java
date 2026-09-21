package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VerboseErrorResponseRuleTest {

    private VerboseErrorResponseRule rule;
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");

    @BeforeEach
    void setUp() {
        rule = new VerboseErrorResponseRule();

        // Loads the SCG010.yml metadata directly from classpath resources, so the tests always
        // reflect the real shipped metadata instead of a hand-copied approximation.
        try (InputStream is = getClass().getResourceAsStream("/rules-metadata/SCG010.yml")) {
            if (is == null) {
                throw new IllegalStateException("Rule metadata file '/rules-metadata/SCG010.yml' not found in test classpath resources");
            }

            Yaml yaml = new Yaml();
            Map<String, List<String>> metadata = yaml.load(is);

            rule.configure(metadata);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load or parse SCG010.yml metadata", e);
        }
    }

    @Nested
    @DisplayName("Configuration Lifecycle and Validation")
    class LifecycleAndConfigurationTests {

        @Test
        @DisplayName("It should fail to execute check() without having called configure()")
        void shouldThrowExceptionWhenNotConfigured() {
            VerboseErrorResponseRule unconfiguredRule = new VerboseErrorResponseRule();
            EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "default", Map.of());

            assertThatThrownBy(() -> unconfiguredRule.check(config))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("must be configured before execution");
        }
    }

    @Nested
    @DisplayName("Spring Boot 4.0 spring.web.error.* key aliases")
    class SpringWebErrorAliasTests {

        // Sourced dynamically from the shipped SCG010.yml rather than hand-copied, so this test
        // keeps covering every alias even if more are added later (per this project's
        // ConfigurableRule testing convention -- see EmbeddedConnectionCredentialsRuleTest).
        // Loads the YAML itself instead of relying on the outer class's @BeforeEach: @MethodSource
        // factories are invoked while resolving test invocations, which happens before per-test
        // lifecycle callbacks run, so the shared `metadata` field can't be trusted to be populated
        // yet at this point.
        static Stream<String> newPrefixKeys() throws Exception {
            Map<String, List<String>> yamlMetadata;
            try (InputStream is = VerboseErrorResponseRuleTest.class.getResourceAsStream("/rules-metadata/SCG010.yml")) {
                yamlMetadata = new Yaml().load(is);
            }

            return Stream.of(
                    "include-stacktrace-keys",
                    "include-exception-keys",
                    "include-message-keys",
                    "include-binding-errors-keys"
            ).map(metadataKey -> yamlMetadata.get(metadataKey).stream()
                    .filter(key -> key.startsWith("spring.web.error."))
                    .findFirst()
                    .orElseThrow());
        }

        @ParameterizedTest
        @MethodSource("newPrefixKeys")
        @DisplayName("Should report a finding when the spring.web.error.* alias is set to a risky value")
        void shouldReportOnSpringWebErrorPrefix(String key) {
            String riskyValue = key.endsWith("include-exception") ? "true" : "always";
            EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(key, riskyValue));

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().message()).contains(key + "=" + riskyValue);
        }

        @Test
        @DisplayName("Should report two independent findings when both the old and new prefix are set on the same property")
        void shouldReportBothPrefixesIndependently() {
            EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                    "server.error.include-stacktrace", "always",
                    "spring.web.error.include-stacktrace", "always"
            ));

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(2);
            assertThat(findings).allMatch(f -> f.severity() == Severity.HIGH);
        }
    }

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