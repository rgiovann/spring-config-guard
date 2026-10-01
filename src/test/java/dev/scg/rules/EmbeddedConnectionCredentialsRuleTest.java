package dev.scg.rules;

import dev.scg.core.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
        @DisplayName("Initialization should fail if 'connection-keys' metadata is missing or empty.")
        void shouldThrowExceptionWhenConnectionKeysMetadataIsInvalid() {
            EmbeddedConnectionCredentialsRule newRule = new EmbeddedConnectionCredentialsRule();

            assertThatThrownBy(() -> newRule.configure(Map.of("other", List.of("x"))))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'connection-keys' is missing or empty");
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

        @ParameterizedTest(name = "Should detect embedded credential in connection key {0}")
        @MethodSource("provideConnectionKeys")
        @DisplayName("Detects an embedded URL credential for every connection key configured in SCG007.yml")
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

        @ParameterizedTest(name = "Should detect embedded JAAS credential in connection key {0}")
        @MethodSource("provideConnectionKeys")
        @DisplayName("Detects an embedded JAAS credential for every connection key configured in SCG007.yml")
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

        @ParameterizedTest
        @ValueSource(strings = {"spring.elasticsearch.uris", "spring.rabbitmq.addresses"})
        @DisplayName("Detects an embedded credential when a uri-based key is written as a real YAML list (regression)")
        void shouldDetectEmbeddedCredentialWhenUriBasedKeyIsWrittenAsYamlList(String baseKey) {
            // Both keys are genuinely List<String>-typed in Spring Boot's real binding, so the
            // idiomatic way to write them is an actual YAML list, not one joined scalar. Before
            // canonicalRoot(), ConfigLoader's "key[0]"/"key[1]" flattened form never matched the
            // plain canonical target -- this credential would have been silently missed.
            Map<String, String> properties = Map.of(
                    baseKey + "[0]", "https://safe-host:9200",
                    baseKey + "[1]", "https://user:S3cr3tPass123@other-host:9200"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message()).contains(baseKey + "[1]");
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

        private static Stream<String> provideConnectionKeys() throws Exception {
            return provideKeysFromYaml("connection-keys");
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

            // A clean injection produces an observability INFO about an unresolvable placeholder, not HIGH.
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
        @DisplayName("Detects a credential by the value's shape in any property, not only in connection keys")
        void shouldDetectCredentialInAnyProperty() {
            Map<String, String> properties = Map.of(
                    "spring.application.name", "my-service",
                    "custom.connection.string", "postgres://user:pass@localhost/db"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).singleElement().satisfies(finding -> {
                assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                assertThat(finding.message()).contains("custom.connection.string");
            });
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

    @Nested
    @DisplayName("Credential forms confirmed against the clients that read them (Spring Boot 4.1.1's versions)")
    class CredentialForms {

        @ParameterizedTest(name = "HIGH: {0} = {1}")
        @CsvSource(delimiter = '|', value = {
                // JDBC: each form read by its driver (VALIDATION.md, "SCG007 credential forms")
                "spring.datasource.url | jdbc:mysql://app:s3cr3t@db.example.com/app",
                "spring.datasource.url | jdbc:postgresql://db.example.com/app?user=app&password=s3cr3t",
                "spring.datasource.url | jdbc:mysql://db.example.com/app?user=app&password=s3cr3t",
                "spring.datasource.url | jdbc:sqlserver://db.example.com;databaseName=app;user=sa;password=s3cr3t",
                "spring.datasource.url | jdbc:h2:mem:app;USER=sa;PASSWORD=s3cr3t",
                "spring.datasource.url | jdbc:oracle:thin:scott/s3cr3t@db.example.com:1521/orcl",
                "spring.datasource.url | jdbc:mysql://db.example.com/app?trustCertificateKeyStorePassword=changeit",
                // Spring Boot 4.1.1's current names, missing from the old key list
                "spring.data.redis.url | redis://user:s3cr3t@redis.example.com:6379",
                "spring.mongodb.uri | mongodb://app:s3cr3t@mongo1.example.com,mongo2.example.com/app",
                "spring.flyway.url | jdbc:mysql://app:s3cr3t@db.example.com/app",
                "spring.datasource.hikari.jdbc-url | jdbc:mysql://app:s3cr3t@db.example.com/app",
                // Any node of a list, not only the first
                "spring.elasticsearch.uris | http://es1.example.com:9200,http://elastic:s3cr3t@es2.example.com:9200",
                // Spring Cloud and application keys
                "spring.cloud.config.uri | http://config:s3cr3t@config.example.com:8888",
                "eureka.client.service-url.defaultZone | http://eureka:s3cr3t@eureka.example.com:8761/eureka",
                // JAAS: unquoted and single-quoted values, OAuthBearer clientSecret, a per-client map
                "spring.kafka.properties.sasl.jaas.config | org.apache.kafka.common.security.plain.PlainLoginModule required username=u password=s3cr3t;",
                "spring.kafka.properties.sasl.jaas.config | org.apache.kafka.common.security.plain.PlainLoginModule required username='u' password='s3cr3t';",
                "spring.kafka.properties.sasl.jaas.config | org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required clientId=\"app\" clientSecret=\"s3cr3t\";",
                "spring.kafka.consumer.properties.sasl.jaas.config | org.apache.kafka.common.security.plain.PlainLoginModule required username=\"u\" password=\"s3cr3t\";",
                // A literal password next to a placeholder that can't be resolved statically
                "spring.datasource.url | jdbc:mysql://app:s3cr3t@${DB_HOST}/app"
        })
        @DisplayName("Reports HIGH for every credential form a client reads from the value")
        void shouldReportEveryCredentialForm(String key, String value) {
            assertThat(rule.check(new EffectiveConfig(mockPath, "default", Map.of(key, value))))
                    .singleElement().satisfies(finding -> {
                        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                        assertThat(finding.message()).contains("'" + key + "'");
                    });
        }

        @ParameterizedTest(name = "Silent: {0} = {1}")
        @CsvSource(delimiter = '|', value = {
                // '@' in a query parameter is not user-info (was a false positive)
                "spring.datasource.url | jdbc:postgresql://db.example.com:5432/app?ApplicationName=a@b",
                "spring.datasource.url | jdbc:mysql://db.example.com:3306/app?serverTimezone=UTC",
                "spring.datasource.url | jdbc:oracle:thin:@//db.example.com:1521/orcl",
                "spring.data.redis.url | redis://user@redis.example.com:6379",
                // Credential injected at runtime, in a key that isn't a connection key
                "app.legacy.url | jdbc:mysql://app:${DB_PASSWORD}@db.example.com/app",
                // Not a connection string or JAAS configuration
                "app.form.hint | password=at least 8 characters",
                "spring.kafka.properties.sasl.jaas.config | org.apache.kafka.common.security.plain.PlainLoginModule required username=\"u\" password=\"${KAFKA_PASSWORD}\";"
        })
        @DisplayName("Stays silent where no credential is written in the value")
        void shouldStaySilentWithoutWrittenCredential(String key, String value) {
            List<Finding> findings = rule.check(new EffectiveConfig(mockPath, "default", Map.of(key, value)));

            assertThat(findings).noneMatch(finding -> finding.severity() == Severity.HIGH);
        }
    }
}
