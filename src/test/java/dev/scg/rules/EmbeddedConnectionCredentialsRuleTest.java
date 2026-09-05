package dev.scg.rules;

import dev.scg.core.*;
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

class EmbeddedConnectionCredentialsRuleTest {

    private EmbeddedConnectionCredentialsRule rule;
    private final Path mockPath = Path.of("src/main/resources/application.yml");

    @BeforeEach
    void setUp() {
        rule = new EmbeddedConnectionCredentialsRule();

        // Loads the SCG007.yml file directly from the resources in the test classpath, so the
        // tests always reflect the real shipped metadata instead of a hand-copied approximation.
        try (InputStream is = getClass().getResourceAsStream("/rules-metadata/SCG007.yml")) {
            if (is == null) {
                throw new IllegalStateException("Rule metadata file '/rules-metadata/SCG007.yml' not found in test classpath resources");
            }

            Yaml yaml = new Yaml();
            Map<String, List<String>> metadata = yaml.load(is);

            rule.configure(metadata);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load or parse SCG007.yml metadata", e);
        }
    }

    @Nested
    @DisplayName("Configuration Lifecycle and Validation")
    class LifecycleTests {

        @Test
        @DisplayName("It should fail to execute check() without having called configure().")
        void shouldThrowExceptionWhenNotConfigured() {
            EmbeddedConnectionCredentialsRule unconfiguredRule = new EmbeddedConnectionCredentialsRule();
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", Map.of());

            assertThatThrownBy(() -> unconfiguredRule.check(config))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("must be configured before execution");
        }

        @Test
        @DisplayName("Initialization should fail if required metadata is null or empty.")
        void shouldThrowExceptionOnInvalidMetadata() {
            EmbeddedConnectionCredentialsRule newRule = new EmbeddedConnectionCredentialsRule();

            assertThatThrownBy(() -> newRule.configure(Map.of("uri-based", List.of())))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("initialization failed");
        }

        @Test
        @DisplayName("Initialization should fail if 'uri-based' metadata is missing or empty.")
        void shouldThrowExceptionWhenUriBasedMetadataIsInvalid() {
            EmbeddedConnectionCredentialsRule newRule = new EmbeddedConnectionCredentialsRule();
            Map<String, List<String>> invalidMetadata = Map.of(
                    "jaas-based", List.of("spring.kafka.properties.sasl.jaas.config")
                    // uri-based ausente
            );

            assertThatThrownBy(() -> newRule.configure(invalidMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'uri-based' is missing or empty");
        }

        @Test
        @DisplayName("Initialization should fail if 'jaas-based' metadata is missing or empty.")
        void shouldThrowExceptionWhenJaasBasedMetadataIsInvalid() {
            EmbeddedConnectionCredentialsRule newRule = new EmbeddedConnectionCredentialsRule();
            Map<String, List<String>> invalidMetadata = Map.of(
                    "uri-based", List.of("spring.datasource.url")
                    // jaas-based ausente
            );

            assertThatThrownBy(() -> newRule.configure(invalidMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'jaas-based' is missing or empty");
        }
    }

    @Nested
    @DisplayName("Positive Cases - Embedded Credential Violations (HIGH)")
    class PositiveViolations {

        @ParameterizedTest
        @ValueSource(strings = {
                "jdbc:postgresql://user:secret123@localhost:5432/mydb",
                "mongodb://admin:p%40ssword@db1.example.com:27017,db2.example.com:27017/admin",
                "redis://:mySuperSecretPass@redis-server:6379",
                "amqp://guest:secretPass@rabbitmq.internal:5672",
                "r2dbc:pool:postgres://dbuser:hardcodedPass@127.0.0.1:5432/db"
        })
        @DisplayName("You should report HIGH for URIs with passwords embedded in clear text (Zero-Trust)")
        void shouldDetectEmbeddedCredentialsInUri(String connectionUri) {
            Map<String, String> properties = Map.of("spring.datasource.url", connectionUri);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.ruleId()).isEqualTo("SCG007");
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message()).contains("Embedded plaintext credential detected");
        }

        @Test
        @DisplayName("It should report HIGH when the embedded password comes from the static fallback of a placeholder.")
        void shouldDetectCredentialOriginatingFromPlaceholderDefault() {
            String rawProperty = "jdbc:mysql://root:${DB_PASS:fallbackHardcoded123}@localhost:3306/db";
            Map<String, String> properties = Map.of("spring.datasource.url", rawProperty);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
            assertThat(findings.getFirst().message()).contains("originates from a static placeholder default");
        }

        @Test
        @DisplayName("It should report HIGH when the embedded JAAS password comes from the static fallback of a placeholder.")
        void shouldDetectJaasCredentialOriginatingFromPlaceholderDefault() {
            String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required " +
                    "username=\"admin\" password=\"${KAFKA_SECRET:hardcodedFallback123}\";";
            Map<String, String> properties = Map.of("spring.kafka.properties.sasl.jaas.config", jaasConfig);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
            assertThat(findings.getFirst().message()).contains("originates from a static placeholder default");
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"admin\" password='SingleQuotedSecret123';",
                "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"admin\" PASSWORD=\"UpperCaseKeySecret123\";",
                "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"admin\" password = \"SpacedAroundEqualsSecret123\";"
        })
        @DisplayName("Detects embedded JAAS passwords regardless of quote style, key case, or whitespace around '='")
        void shouldDetectJaasCredentialsWithVariedSyntax(String jaasConfig) {
            Map<String, String> properties = Map.of("spring.kafka.properties.sasl.jaas.config", jaasConfig);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .extracting(Finding::severity)
                    .isEqualTo(Severity.HIGH);
        }

        @ParameterizedTest(name = "Should detect embedded credential for uri-based key from SCG007.yml")
        @MethodSource("provideUriBasedKeys")
        @DisplayName("Detects an embedded credential for every uri-based key configured in SCG007.yml")
        void shouldDetectEmbeddedCredentialForEveryConfiguredUriBasedKey(String propertyKey) {
            String connectionUri = "protocol:generic://app_user:S3cr3tPass123@db-host:5432/appdb";
            Map<String, String> properties = Map.of(propertyKey, connectionUri);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .satisfies(finding -> {
                        assertThat(finding.ruleId()).isEqualTo("SCG007");
                        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                        assertThat(finding.message()).contains(propertyKey);
                    });
        }

        @ParameterizedTest(name = "Should detect embedded credential for jaas-based key from SCG007.yml")
        @MethodSource("provideJaasBasedKeys")
        @DisplayName("Detects an embedded credential for every jaas-based key configured in SCG007.yml")
        void shouldDetectEmbeddedCredentialForEveryConfiguredJaasBasedKey(String propertyKey) {
            String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required " +
                    "username=\"admin\" password=\"S3cr3tKafkaPass\";";
            Map<String, String> properties = Map.of(propertyKey, jaasConfig);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings)
                    .hasSize(1)
                    .first()
                    .satisfies(finding -> {
                        assertThat(finding.ruleId()).isEqualTo("SCG007");
                        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                        assertThat(finding.message()).contains(propertyKey);
                    });
        }

        /**
         * SCG007.yml only lists property KEYS, never example values — the YAML has no notion of
         * "a URI with a credential embedded in it". So key names are sourced dynamically from
         * the real file (avoiding drift), but the complex credential-bearing string for each key
         * has to be built here, per category (uri-based vs. jaas-based) rather than per
         * individual key: the rule's detection regex is shape-based, not scheme-specific, so one
         * representative template per category is enough to exercise every currently-configured
         * key.
         */
        private static Stream<String> provideKeysFromYaml(String metadataKey) throws Exception {
            try (InputStream is = EmbeddedConnectionCredentialsRuleTest.class.getResourceAsStream("/rules-metadata/SCG007.yml")) {
                if (is == null) {
                    throw new IllegalStateException("Rule metadata file '/rules-metadata/SCG007.yml' not found in test classpath resources");
                }
                Yaml yaml = new Yaml();
                Map<String, List<String>> metadata = yaml.load(is);
                return metadata.get(metadataKey).stream();
            }
        }

        private static Stream<String> provideUriBasedKeys() throws Exception {
            return provideKeysFromYaml("uri-based");
        }

        private static Stream<String> provideJaasBasedKeys() throws Exception {
            return provideKeysFromYaml("jaas-based");
        }
    }

    @Nested
    @DisplayName("Negative Cases - Valid and Secure Settings")
    class ValidConfigurations {

        @ParameterizedTest
        @ValueSource(strings = {
                "jdbc:postgresql://localhost:5432/mydb",
                "mongodb://db1.example.com:27017/admin",
                "redis://redis-server:6379",
                "jdbc:postgresql://user:@localhost:5432/mydb", // With empty password slot
                "jdbc:postgresql://onlyuser@localhost:5432/mydb" // User without password separator (without ':')
        })
        @DisplayName("Do not trigger a violation for URIs without embedded passwords.")
        void shouldIgnoreUrisWithoutCredentials(String connectionUri) {
            Map<String, String> properties = Map.of("spring.datasource.url", connectionUri);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @Test
        @DisplayName("A violation should not be triggered when the password in the URI is injected via a clean placeholder without a static default")
        void shouldIgnoreUriWithCleanPlaceholder() {
            String rawProperty = "jdbc:postgresql://app_user:${DB_PASSWORD}@db.internal:5432/mydb";
            Map<String, String> properties = Map.of("spring.datasource.url", rawProperty);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            // Injeção limpa gera INFO de observabilidade sobre placeholder irresolvível, não HIGH.
            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
            assertThat(findings.getFirst().message()).contains("relies on an unresolved environment placeholder");
        }

        @Test
        @DisplayName("A violation should not be triggered for JAAS Config with a placeholder-injected password.")
        void shouldIgnoreJaasWithCleanPlaceholder() {
            String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required " +
                    "username=\"admin\" password=\"${KAFKA_SECRET}\";";

            Map<String, String> properties = Map.of("spring.kafka.properties.sasl.jaas.config", jaasConfig);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }

        @Test
        @DisplayName("Reports INFO when a URI-based property's entire value is a placeholder with an empty default fallback")
        void shouldReportInfoForUriWithEmptyDefaultFallback() {
            Map<String, String> properties = Map.of("spring.datasource.url", "${DB_URL:}");
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
            assertThat(findings.getFirst().message()).contains("empty default fallback");
            assertThat(findings.getFirst().message()).doesNotContain("unresolved environment placeholder");
        }

        @Test
        @DisplayName("Reports INFO when a JAAS-based property's entire value is a placeholder with an empty default fallback")
        void shouldReportInfoForJaasWithEmptyDefaultFallback() {
            Map<String, String> properties = Map.of("spring.kafka.properties.sasl.jaas.config", "${KAFKA_JAAS_CONFIG:}");
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
            assertThat(findings.getFirst().message()).contains("empty default fallback");
            assertThat(findings.getFirst().message()).doesNotContain("unresolved environment placeholder");
        }

        @Test
        @DisplayName("Reports INFO when only the credential fragment of a URI is a placeholder with an empty default fallback")
        void shouldReportInfoForUriWithEmptyDefaultFallbackInCredentialFragment() {
            String rawProperty = "jdbc:postgresql://app_user:${DB_PASSWORD:}@db.internal:5432/mydb";
            Map<String, String> properties = Map.of("spring.datasource.url", rawProperty);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
            assertThat(findings.getFirst().message()).contains("credential placeholder that resolves to an empty value");
        }

        @Test
        @DisplayName("Reports INFO when only the password field of a JAAS config is a placeholder with an empty default fallback")
        void shouldReportInfoForJaasWithEmptyDefaultFallbackInCredentialFragment() {
            String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required " +
                    "username=\"admin\" password=\"${KAFKA_SECRET:}\";";
            Map<String, String> properties = Map.of("spring.kafka.properties.sasl.jaas.config", jaasConfig);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
            assertThat(findings.getFirst().message()).contains("credential placeholder that resolves to an empty value");
        }

        @Test
        @DisplayName("Stays silent for a literal, permanently empty credential with no placeholder involved (unchanged behavior)")
        void shouldStaySilentForLiteralEmptyCredentialWithoutPlaceholder() {
            Map<String, String> properties = Map.of("spring.datasource.url", "jdbc:postgresql://user:@localhost:5432/mydb");
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @Test
        @DisplayName("Do not trigger a violation for a JAAS config with no plaintext password field (e.g. Kerberos keytab auth)")
        void shouldIgnoreJaasWithoutPasswordField() {
            String jaasConfig = "com.sun.security.auth.module.Krb5LoginModule required " +
                    "useKeyTab=true keyTab=\"/etc/security/keytabs/kafka_client.keytab\" " +
                    "principal=\"kafka-client@EXAMPLE.COM\";";

            Map<String, String> properties = Map.of("spring.kafka.properties.sasl.jaas.config", jaasConfig);
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @Test
        @DisplayName("You should ignore keys that do not belong to the SCG007 target group.")
        void shouldIgnoreNonTargetProperties() {
            Map<String, String> properties = Map.of(
                    "spring.application.name", "my-service",
                    "custom.connection.string", "postgres://user:pass@localhost/db"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "   ", " \t\n "})
        @DisplayName("Stays silent when a target property key has a null or blank value")
        void shouldStaySilentWhenTargetPropertyValueIsNullOrEmpty(String blankValue) {
            Map<String, String> properties = new HashMap<>();
            properties.put("spring.datasource.url", blankValue);
            properties.put("spring.kafka.properties.sasl.jaas.config", null);

            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }
    }
}