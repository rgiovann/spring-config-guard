package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SCG006 - HardcodedSecretsRule Unit Tests")
class HardcodedSecretsRuleTest {

    private static final Path FAKE_PATH = Path.of("application.yml");
    private HardcodedSecretsRule rule;

    @BeforeEach
    void setUp() {
        rule = new HardcodedSecretsRule();

        // Loads the SCG006.yml file directly from the resources in the test classpath.
        try (InputStream is = getClass().getResourceAsStream("/rules-metadata/SCG006.yml")) {
            if (is == null) {
                throw new IllegalStateException("Rule metadata file '/rules-metadata/SCG006.yml' not found in test classpath resources");
            }

            Yaml yaml = new Yaml();
            Map<String, List<String>> metadata = yaml.load(is);

            rule.configure(metadata);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load or parse SCG006.yml metadata", e);
        }
    }

    @Nested
    @DisplayName("High-Risk Keys and Relaxed Binding Detection")
    class HighRiskKeyTests {

        @ParameterizedTest(name = "Should trigger HIGH finding for high-risk key: {0}")
        @MethodSource("provideHighRiskKeys")
        @DisplayName("Detects hardcoded secrets in high-risk property keys dynamically from YAML")
        void shouldDetectHighRiskKeys(String propertyKey) {
            EffectiveConfig config = createConfig(Map.of(propertyKey, "supersecret123"));

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .satisfies(finding -> {
                        assertThat(finding.ruleId()).isEqualTo("SCG006");
                        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                        assertThat(finding.message()).contains(propertyKey);
                        assertThat(finding.message()).contains("core Spring Boot property");
                        assertThat(finding.message()).doesNotContain("static placeholder default");
                    });
        }

        private static Stream<String> provideHighRiskKeys() throws Exception {
            try (InputStream is = HardcodedSecretsRuleTest.class.getResourceAsStream("/rules-metadata/SCG006.yml")) {
                if (is == null) {
                    throw new IllegalStateException("Metadata file '/rules-metadata/SCG006.yml' not found in test resources");
                }
                Yaml yaml = new Yaml();
                Map<String, List<String>> metadata = yaml.load(is);
                return metadata.get("high-risk-keys").stream();
            }
        }

        @ParameterizedTest(name = "Should detect relaxed binding variation: {0}")
        @ValueSource(strings = {
                "SPRING_DATASOURCE_PASSWORD",
                "springDatasourcePassword",
                "spring-datasource-password",
                "SPRING.DATASOURCE.PASSWORD"
        })
        @DisplayName("Detects high-risk keys using Spring Relaxed Binding conventions")
        void shouldDetectRelaxedBindingVariations(String relaxedKey) {
            EffectiveConfig config = createConfig(Map.of(relaxedKey, "my-plaintext-pass"));

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        }
    }

    @Nested
    @DisplayName("Custom Secret Key Patterns Detection")
    class SecretKeyPatternTests {

        @ParameterizedTest(name = "Should ignore custom secret pattern for ''{0}'' with primitive value ''{1}''")
        @CsvSource({
                "jwt.token-validity-in-seconds, 86400",
                "jwt.token-validity-in-seconds, 2592000",
                "jwt.token-validity-in-seconds, 0",
                "app.security.token-remember-me-enabled, true",
                "app.security.token-remember-me-enabled, TRUE",
                "app.security.token-remember-me-enabled, false"
        })
        @DisplayName("Silently ignores custom key matches with numeric or boolean primitive values")
        void shouldIgnoreCustomSecretKeyPatternForPrimitiveValues(String propertyKey, String primitiveValue) {
            Map<String, String> props = Map.of(propertyKey, primitiveValue);
            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @ParameterizedTest(name = "Should ignore custom secret pattern for ''{0}'' with primitive value behind placeholder ''{1}''")
        @CsvSource({
                "jwt.token-validity-in-seconds, ${TOKEN_TTL:86400}",
                "jwt.token-validity-in-seconds, ${TOKEN_TTL:0}",
                "app.security.token-remember-me-enabled, ${REMEMBER_ME:true}",
                "app.security.token-remember-me-enabled, ${REMEMBER_ME:FALSE}"
        })
        @DisplayName("Silently ignores custom key matches when the placeholder's static default is a numeric or boolean primitive")
        void shouldIgnoreCustomSecretKeyPatternForPrimitiveValuesBehindPlaceholder(String propertyKey, String placeholderValue) {
            Map<String, String> props = Map.of(propertyKey, placeholderValue);
            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @ParameterizedTest(name = "Should detect custom property matching pattern: {0}")
        @ValueSource(strings = {
                "app.jwt.token",
                "custom.service.api-key",
                "payment.gateway.secret",
                "aws.access-key",
                "db.client.credential",
                "MY_SERVICE_APIKEY",
                "auth.user-password"
        })
        @DisplayName("Detects custom property keys containing configured secret patterns")
        void shouldDetectCustomPatternKeys(String customKey) {
            EffectiveConfig config = createConfig(Map.of(customKey, "raw-token-value-99"));

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .satisfies(finding -> {
                        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                        assertThat(finding.message()).contains("custom key pattern");
                        assertThat(finding.message()).doesNotContain("core Spring Boot property");
                    });
        }
    }

    @Nested
    @DisplayName("Value Exclusions and Encryption Prefix Handling")
    class ValueExclusionTests {

        @ParameterizedTest(name = "Should ignore value starting with prefix: {0}")
        @ValueSource(strings = {
                "{cipher}FK2049SFKSL204920SLFK",
                "{vault}secret/data/db#password",
                "   {cipher}WITH_LEADING_SPACES"
        })
        @DisplayName("Ignores encrypted or managed values starting with configured prefixes")
        void shouldIgnoreEncryptedValues(String encryptedValue) {
            EffectiveConfig config = createConfig(Map.of("spring.datasource.password", encryptedValue));

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @ParameterizedTest(name = "Should generate INFO for blank core key with value: ''{0}''")
        @NullAndEmptySource
        @ValueSource(strings = {"  ", "\t", "\n"})
        @DisplayName("Generates INFO finding for blank high-risk keys (CWE-258)")
        void shouldGenerateInfoForBlankHighRiskKeys(String blankValue) {
            // null is what SnakeYAML produces for "password:" with nothing after it (see
            // ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX) — the most realistic real-world shape,
            // not just a synthetic whitespace string.
            Map<String, String> props = new HashMap<>();
            props.put("spring.datasource.password", blankValue);
            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.INFO);
            assertThat(finding.message()).contains("Core Spring Boot sensitive property 'spring.datasource.password' is declared blank");
        }

        @Test
        @DisplayName("Ignores null or blank values for custom secret key patterns silently")
        void shouldIgnoreBlankValuesForCustomPatterns() {
            Map<String, String> props = new HashMap<>();
            props.put("app.secret.key", null);
            props.put("app.custom.token", "   ");

            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @Test
        @DisplayName("Should ignore sensitive keys when encrypted prefix is declared inside placeholder fallback")
        void shouldIgnoreSensitiveKeyWhenEncryptedPrefixIsInsidePlaceholderFallback() {
            EffectiveConfig config = createConfig(
                    Map.of("spring.datasource.password", "${DB_PASSWORD:{cipher}FKJ39847239487}")
            );

            List<Finding> findings = rule.check(config);

            assertTrue(findings.isEmpty(), "Values with ignored prefixes inside placeholder fallbacks must not trigger findings");
        }
    }

    @Nested
    @DisplayName("Environment Placeholder Resolution")
    class PlaceholderResolutionTests {

        @ParameterizedTest(name = "Should detect static fallback inside placeholder: {0}")
        @ValueSource(strings = {
                "${DB_PASSWORD:hardcoded_fallback_123}",
                "${APP_SECRET:   default_secret   }"
        })
        @DisplayName("Flags static default values inside placeholders as HIGH severity")
        void shouldFlagStaticFallbackInPlaceholders(String rawPlaceholder) {
            EffectiveConfig config = createConfig(Map.of("spring.datasource.password", rawPlaceholder));

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .satisfies(finding -> {
                        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                        assertThat(finding.message()).contains("static placeholder default");
                    });
        }

        @Test
        @DisplayName("Also appends the static placeholder default clause for custom-pattern keys, not just high-risk keys")
        void shouldAppendPlaceholderDefaultClauseForCustomPatternKeyToo() {
            EffectiveConfig config = createConfig(Map.of("app.jwt.token", "${JWT_SECRET:hardcoded_default}"));

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .satisfies(finding -> {
                        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                        assertThat(finding.message()).contains("custom key pattern");
                        assertThat(finding.message()).contains("static placeholder default");
                    });
        }

        @ParameterizedTest(name = "Should report INFO severity for unresolved placeholder: {0}")
        @ValueSource(strings = {
                "${DB_PASSWORD}",
                "${app.security.token}"
        })
        @DisplayName("Flags placeholders without a default as INFO severity for SecOps visibility")
        void shouldFlagUnresolvedPlaceholdersAsInfo(String rawPlaceholder) {
            EffectiveConfig config = createConfig(Map.of("spring.datasource.password", rawPlaceholder));

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .satisfies(finding -> {
                        assertThat(finding.severity()).isEqualTo(Severity.INFO);
                        assertThat(finding.message()).contains("unresolved environment placeholder");
                    });
        }

        @Test
        @DisplayName("Flags a placeholder with an explicit empty default fallback as INFO, distinct from an unresolved placeholder")
        void shouldFlagEmptyDefaultFallbackAsInfo() {
            EffectiveConfig config = createConfig(Map.of("spring.datasource.password", "${UNRESOLVED_ENV_VAR:}"));

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .satisfies(finding -> {
                        assertThat(finding.severity()).isEqualTo(Severity.INFO);
                        assertThat(finding.message()).contains("empty default fallback");
                        assertThat(finding.message()).doesNotContain("unresolved environment placeholder");
                    });
        }
    }

    @Nested
    @DisplayName("Happy Path — Ordinary Configuration Without Secrets")
    class HappyPathTests {

        @Test
        @DisplayName("Does not flag common non-sensitive Spring Boot properties")
        void shouldNotFlagOrdinaryNonSensitiveProperties() {
            Map<String, String> props = new HashMap<>();
            props.put("server.port", "8080");
            props.put("spring.application.name", "demo-service");
            props.put("management.endpoints.web.exposure.include", "health,info");
            props.put("spring.datasource.url", "jdbc:postgresql://localhost:5432/app");
            props.put("spring.datasource.username", "app_user");

            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @Test
        @DisplayName("Flags only the sensitive keys when mixed with ordinary properties in the same config")
        void shouldFlagOnlySensitiveKeysAmongMixedProperties() {
            Map<String, String> props = new HashMap<>();
            props.put("server.port", "8080");
            props.put("spring.application.name", "demo-service");
            props.put("spring.datasource.username", "app_user");
            props.put("spring.datasource.password", "supersecret123");
            props.put("custom.service.api-key", "raw-api-key-value");

            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(2)
                    .extracting(Finding::message)
                    .anySatisfy(message -> assertThat(message).contains("spring.datasource.password"))
                    .anySatisfy(message -> assertThat(message).contains("custom.service.api-key"));
        }
   }

    @Nested
    @DisplayName("Configuration and Fail-Fast Invariants")
    class ConfigurationInvariantsTests {

        @Test
        @DisplayName("Throws IllegalStateException if check() is called before configure()")
        void shouldThrowExceptionWhenUnconfigured() {
            HardcodedSecretsRule unconfiguredRule = new HardcodedSecretsRule();
            EffectiveConfig config = createConfig(Map.of("spring.datasource.password", "secret"));

            assertThatThrownBy(() -> unconfiguredRule.check(config))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("must be configured before execution");
        }

        @Test
        @DisplayName("Throws IllegalArgumentException if metadata contains placeholder prefix '${'")
        void shouldRejectPlaceholderInIgnoredPrefixes() {
            Map<String, List<String>> invalidMetadata = Map.of(
                    "high-risk-keys", List.of("spring.datasource.password"),
                    "secret-key-patterns", List.of("password"),
                    "ignored-value-prefixes", List.of("${")
            );

            assertThatThrownBy(() -> new HardcodedSecretsRule().configure(invalidMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Cannot include placeholder prefix '${' in 'ignored-value-prefixes'");
        }

        @Test
        @DisplayName("Throws IllegalArgumentException if required metadata keys are missing")
        void shouldFailWhenRequiredKeysAreMissing() {
            Map<String, List<String>> incompleteMetadata = Map.of(
                    "high-risk-keys", List.of()
            );

            assertThatThrownBy(() -> new HardcodedSecretsRule().configure(incompleteMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("initialization failed");
        }
    }
    private EffectiveConfig createConfig(Map<String, String> properties) {
        return new EffectiveConfig(FAKE_PATH, "prod", properties);
    }

}