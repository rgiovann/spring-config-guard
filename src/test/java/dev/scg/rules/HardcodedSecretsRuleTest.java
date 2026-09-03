package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SCG006 - HardcodedSecretsRule Unit Tests")
class HardcodedSecretsRuleTest {

    private static final Path FAKE_PATH = Path.of("application.yml");
    private HardcodedSecretsRule rule;

    @BeforeEach
    void setUp() {
        rule = new HardcodedSecretsRule();
        Map<String, List<String>> validMetadata = Map.of(
                "high-risk-keys", List.of(
                        "spring.datasource.password",
                        "spring.r2dbc.password",
                        "spring.flyway.password",
                        "spring.liquibase.password",
                        "spring.data.redis.password",
                        "spring.rabbitmq.password",
                        "spring.mail.password",
                        "spring.security.user.password",
                        "spring.neo4j.authentication.password"
                ),
                "secret-key-patterns", List.of(
                        "password", "secret", "private-key", "api-key",
                        "apikey", "token", "credential", "access-key"
                ),
                "ignored-value-prefixes", List.of("{cipher}", "{vault}")
        );
        rule.configure(validMetadata);
    }

    @Nested
    @DisplayName("High-Risk Keys and Relaxed Binding Detection")
    class HighRiskKeyTests {

        @ParameterizedTest(name = "Should trigger HIGH finding for high-risk key: {0}")
        @ValueSource(strings = {
                "spring.datasource.password",
                "spring.r2dbc.password",
                "spring.flyway.password",
                "spring.liquibase.password",
                "spring.data.redis.password",
                "spring.rabbitmq.password",
                "spring.mail.password",
                "spring.security.user.password",
                "spring.neo4j.authentication.password"
        })
        @DisplayName("Detects hardcoded secrets in high-risk property keys")
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
                    .extracting(Finding::severity)
                    .isEqualTo(Severity.HIGH);
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

        @ParameterizedTest(name = "Should ignore blank or null values for key: {0}")
        @ValueSource(strings = {"  ", "\t", "\n"})
        @DisplayName("Ignores empty or blank values without throwing exceptions")
        void shouldIgnoreBlankValues(String blankValue) {
            Map<String, String> props = new HashMap<>();
            props.put("spring.datasource.password", blankValue);
            props.put("app.secret.key", null);

            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
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