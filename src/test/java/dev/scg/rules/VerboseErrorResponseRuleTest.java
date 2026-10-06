package dev.scg.rules;

import dev.scg.core.ConfigLoader;
import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ConfigFileGrouper;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
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
            assertThat(findings).allMatch(f -> f.severity() == Severity.MEDIUM);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "server.error.include-stacktrace",
                "server.error.include-exception",
                "server.error.include-message",
                "server.error.include-binding-errors"
        })
        @DisplayName("O1, O2, F4, T1, T3: each prefix is read by one Spring Boot major only, so every message says which and that removing the key is the fix")
        void shouldNameTheVersionsThatReadEachPrefix(String key) {
            // Spring Boot 4.1.1 ignored every server.error.* key (O1, O2, F4) and 3.5.16 every
            // spring.web.error.* key (T3), while 3.5.16 read server.error.* (T1). Static analysis
            // can't tell the version, so both are reported at the same severity, with a note.
            String value = key.endsWith("include-exception") ? "true" : "always";
            EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                    key, value,
                    key.replace("server.error.", "spring.web.error."), value
            ));

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(2);
            assertThat(findings).allMatch(f -> f.severity() == Severity.MEDIUM);
            assertThat(findings).allSatisfy(f -> assertThat(f.message())
                    .contains("Spring Boot reads server.error.* before 4.0 and spring.web.error.* from 4.0 on")
                    .contains("remove it"));
        }
    }

    @Test
    @DisplayName("D0, S7, X5: silent when every property is absent or safe")
    void shouldStaySilentWhenSafeOrAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-stacktrace", "never",
                "spring.web.error.include-exception", "false",
                "spring.web.error.include-message", "never",
                "spring.web.error.include-binding-errors", "never"
        ));

        assertThat(rule.check(config)).isEmpty();
        assertThat(rule.check(new EffectiveConfig(FAKE_PATH, "prod", Map.of()))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"server.error.include-stacktrace", "spring.web.error.include-stacktrace"})
    @DisplayName("S8: silent when include-stacktrace is empty: the app returned no stack trace")
    void shouldStaySilentOnEmptyIncludeStacktrace(String key) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(key, ""));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "always", "ALWAYS",
            "on_param", "ON_PARAM",
            "on-param", "ON-PARAM",
            "onParam", "ONPARAM"
    })
    @DisplayName("S1-S6: include-stacktrace=always or on-param, in any spelling Spring binds, is MEDIUM")
    void shouldReportMediumOnRiskyIncludeStacktrace(String enumValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-stacktrace", enumValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG010");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("spring.web.error.include-stacktrace=" + enumValue);
    }

    @ParameterizedTest
    @ValueSource(strings = {"on.param", "on param"})
    @DisplayName("S5: reported even for atypical separators, proving canonicalize() strips any non-alphanumeric char")
    void shouldReportOnAtypicalSeparators(String enumValue) {
        // Not usual Spring Boot authoring styles, but Spring binds them (S5: on.param), and they prove the canonicalize() comparison
        // (shared approach with SCG001/SCG013) isn't secretly hardcoded to just '-'/'_' the way
        // the old Set<String> + toUpperCase() approach was -- that older approach missed
        // "onParam" specifically because it has no separator to match a Set entry written with one.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-stacktrace", enumValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "on", "yes", "1"})
    @DisplayName("S9, S10: silent when an enum property receives a boolean value, which stops the app from starting")
    void shouldStaySilentOnInvalidEnumValuesForIncludeStacktrace(String invalidValue) {
        // "true"/"yes"/"1" are not valid IncludeAttribute values — Spring Boot itself would fail
        // to bind this at startup, so it does not behave like "always". The rule must stay silent
        // instead of raising a false finding.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-stacktrace", invalidValue
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "yes", "on", "1", "YES"})
    @DisplayName("X1-X4: include-exception set to any literal Spring reads as true is MEDIUM")
    void shouldReportMediumOnTruthyIncludeException(String truthyValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-exception", truthyValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG010");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("spring.web.error.include-exception=" + truthyValue);
    }

    @ParameterizedTest
    @ValueSource(strings = {"always", "ON_PARAM"})
    @DisplayName("M1, M2: include-message=always or on-param is MEDIUM")
    void shouldReportMediumOnRiskyIncludeMessage(String enumValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-message", enumValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"always", "ON_PARAM"})
    @DisplayName("B1, B2: include-binding-errors=always or on-param is MEDIUM (not LOW)")
    void shouldReportMediumOnRiskyIncludeBindingErrors(String enumValue) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-binding-errors", enumValue
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

    @ParameterizedTest
    @ValueSource(strings = {"${EXC}", "${EXC:${OTHER}}"})
    @DisplayName("include-exception with an unresolved placeholder is INFO, not MEDIUM: the value is resolved before it is read as a boolean")
    void shouldReportInfoOnUnresolvedIncludeException(String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-exception", value
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("Should report MEDIUM severity when placeholder is resolved to a risky enum value")
    void shouldReportMediumOnResolvedPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", "${SHOW_STACKTRACE:always}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
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
            "spring.web.error.include-stacktrace",
            "spring.web.error.include-message",
            "spring.web.error.include-binding-errors"
    })
    @DisplayName("S11: silent when an enum property receives an unrecognized value, which stops the app from starting")
    void shouldStaySilentOnUnrecognizedEnumValue(String key) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(key, "sometimes"));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"SERVER.ERROR.INCLUDE-STACKTRACE", "spring.web.error.includeStacktrace", "spring.web.error.include_stacktrace"})
    @DisplayName("Should respect relaxed binding: case, camelCase and underscores")
    void shouldSupportRelaxedBinding(String key) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(key, "ALWAYS"));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "always", "never", ""})
    @DisplayName("X5, X6, X7: silent when include-exception is false, or a value that stops the app from starting")
    void shouldStaySilentOnFalseOrUnbindableIncludeException(String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.web.error.include-exception", value
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Nested
    @DisplayName("Values YAML parses itself, loaded through ConfigLoader and ProfileMerger")
    class YamlValues {

        private List<Finding> checkYaml(Path dir, String yaml) throws IOException {
            Files.writeString(dir.resolve("application.yml"), yaml);
            return new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(dir)).stream()
                    .flatMap(group -> new ProfileMerger().merge(group).stream())
                    .flatMap(config -> rule.check(config).stream())
                    .toList();
        }

        @Test
        @DisplayName("Y1: an unquoted 'on' for include-exception is a YAML boolean true, which Spring reads, so it is MEDIUM")
        void unquotedOnForIncludeExceptionIsReported(@TempDir Path dir) throws IOException {
            List<Finding> findings = checkYaml(dir, """
                    spring.web.error:
                      include-exception: on
                    """);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("Y2: an unquoted 'on' for include-stacktrace is a YAML boolean, which stops the app from starting, so it is silent")
        void unquotedOnForIncludeStacktraceIsSilent(@TempDir Path dir) throws IOException {
            assertThat(checkYaml(dir, """
                    spring.web.error:
                      include-stacktrace: on
                    """)).isEmpty();
        }
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
    @DisplayName("T1: four independent findings when all four server.error.* properties are set to risky values")
    void shouldReportIndependentFindingsForEachTrigger() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", "always",
                "server.error.include-exception", "true",
                "server.error.include-message", "always",
                "server.error.include-binding-errors", "always"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(4);
        assertThat(findings).allMatch(f -> f.severity() == Severity.MEDIUM);
    }

    @Test
    @DisplayName("T2: server.error.include-stacktrace=on-param, which Spring Boot 3.5.16 reads, is MEDIUM")
    void shouldReportOnParamUnderTheOldPrefix() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.error.include-stacktrace", "on-param"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
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