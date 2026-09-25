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
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InsecureDatabaseTransportRuleTest {

    private InsecureDatabaseTransportRule rule;
    private final Path mockPath = Path.of("src/main/resources/application.yml");

    @BeforeEach
    void setUp() {
        rule = new InsecureDatabaseTransportRule();

        // Loads the SCG012.yml metadata directly from classpath resources
        try (InputStream is = getClass().getResourceAsStream("/rules-metadata/SCG012.yml")) {
            if (is == null) {
                throw new IllegalStateException("Rule metadata file '/rules-metadata/SCG012.yml' not found in test classpath resources");
            }

            Yaml yaml = new Yaml();
            Map<String, List<String>> metadata = yaml.load(is);

            rule.configure(metadata);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load or parse SCG012.yml metadata", e);
        }
    }

    @Nested
    @DisplayName("Configuration Lifecycle and Validation")
    class LifecycleAndConfigurationTests {

        @Test
        @DisplayName("It should fail to execute check() without having called configure()")
        void shouldThrowExceptionWhenNotConfigured() {
            InsecureDatabaseTransportRule unconfiguredRule = new InsecureDatabaseTransportRule();
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", Map.of());

            assertThatThrownBy(() -> unconfiguredRule.check(config))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("must be configured before execution");
        }

        @Test
        @DisplayName("Initialization should fail if metadata map is null")
        void shouldThrowExceptionWhenMetadataIsNull() {
            InsecureDatabaseTransportRule newRule = new InsecureDatabaseTransportRule();

            assertThatThrownBy(() -> newRule.configure(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("metadata map cannot be null");
        }

        @Test
        @DisplayName("Initialization should fail if 'uri-based' metadata is missing or empty")
        void shouldThrowExceptionWhenUriBasedMetadataIsInvalid() {
            InsecureDatabaseTransportRule newRule = new InsecureDatabaseTransportRule();
            Map<String, List<String>> invalidMetadata = Map.of(
                    "risky-query-params", List.of("usessl=false"),
                    "no-verify-query-params", List.of("verifyservercertificate=false")
            );

            assertThatThrownBy(() -> newRule.configure(invalidMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'uri-based' is missing or empty");
        }

        @Test
        @DisplayName("Initialization should fail if 'risky-query-params' metadata is missing or empty")
        void shouldThrowExceptionWhenRiskyQueryParamsMetadataIsInvalid() {
            InsecureDatabaseTransportRule newRule = new InsecureDatabaseTransportRule();
            Map<String, List<String>> invalidMetadata = Map.of(
                    "uri-based", List.of("spring.datasource.url"),
                    "no-verify-query-params", List.of("verifyservercertificate=false")
            );

            assertThatThrownBy(() -> newRule.configure(invalidMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'risky-query-params' is missing or empty");
        }

        @Test
        @DisplayName("Initialization should fail if 'no-verify-query-params' metadata is missing or empty")
        void shouldThrowExceptionWhenNoVerifyQueryParamsMetadataIsInvalid() {
            InsecureDatabaseTransportRule newRule = new InsecureDatabaseTransportRule();
            Map<String, List<String>> invalidMetadata = Map.of(
                    "uri-based", List.of("spring.datasource.url"),
                    "risky-query-params", List.of("usessl=false"),
                    "risky-schemes", List.of("http://")
            );

            assertThatThrownBy(() -> newRule.configure(invalidMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'no-verify-query-params' is missing or empty");
        }

        @Test
        @DisplayName("Initialization should fail if 'risky-schemes' metadata is missing or empty")
        void shouldThrowExceptionWhenRiskySchemesMetadataIsInvalid() {
            InsecureDatabaseTransportRule newRule = new InsecureDatabaseTransportRule();
            Map<String, List<String>> invalidMetadata = Map.of(
                    "uri-based", List.of("spring.datasource.url"),
                    "risky-query-params", List.of("usessl=false"),
                    "no-verify-query-params", List.of("verifyservercertificate=false")
            );

            assertThatThrownBy(() -> newRule.configure(invalidMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("'risky-schemes' is missing or empty");
        }
    }

    @Nested
    @DisplayName("Disabled/Degraded TLS Detection (CWE-319)")
    class RiskyQueryParamsTests {

        @Test
        @DisplayName("Detects useSSL=false in JDBC MySQL connections")
        void shouldDetectDisabledSslInMysqlUri() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:mysql://localhost:3306/db?useSSL=false&serverTimezone=UTC"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.ruleId()).isEqualTo("SCG012");
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message())
                    .contains("spring.datasource.url")
                    .contains("usessl=false")
                    .contains("CWE-319");
        }

        @Test
        @DisplayName("Detects sslmode=disable in PostgreSQL connection URIs")
        void shouldDetectDisabledSslInPostgresUri() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:postgresql://localhost:5432/db?sslmode=disable"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().message())
                    .contains("sslmode=disable")
                    .contains("CWE-319");
        }

        @Test
        @DisplayName("Detects semicolon-separated query parameters (e.g., SQL Server format)")
        void shouldDetectInsecureParamsWithSemicolonDelimiter() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:sqlserver://localhost:1433;databaseName=db;encrypt=false"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().message()).contains("encrypt=false");
        }
    }

    @Nested
    @DisplayName("Disabled Certificate Validation Detection (CWE-295)")
    class NoVerifyQueryParamsTests {

        @Test
        @DisplayName("Detects verifyServerCertificate=false when TLS is enabled")
        void shouldDetectDisabledCertificateValidation() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:mysql://localhost:3306/db?useSSL=true&verifyServerCertificate=false"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message())
                    .contains("verifyservercertificate=false")
                    .contains("CWE-295");
        }

        @Test
        @DisplayName("Detects trustServerCertificate=true (SQL Server's inverted-polarity equivalent)")
        void shouldDetectTrustServerCertificateTrue() {
            // Unlike every other entry in no-verify-query-params, the risky value here is "true",
            // not "false" -- SQL Server's flag means "trust the server's certificate without
            // verifying it" when explicitly set to true.
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:sqlserver://localhost:1433;encrypt=true;trustServerCertificate=true"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message())
                    .contains("trustservercertificate=true")
                    .contains("CWE-295");
        }

        @ParameterizedTest
        @ValueSource(strings = {"tlsInsecure=true", "tlsAllowInvalidCertificates=true", "tlsAllowInvalidHostnames=true"})
        @DisplayName("Detects MongoDB's own certificate/hostname validation opt-outs")
        void shouldDetectMongoNoVerifyParameters(String queryParam) {
            Map<String, String> properties = Map.of(
                    "spring.data.mongodb.uri", "mongodb://user:pass@localhost:27017/db?" + queryParam
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message()).contains("CWE-295");
        }

        @Test
        @DisplayName("Detects Lettuce's verifyPeer=NONE on a Redis connection URI")
        void shouldDetectRedisVerifyPeerNone() {
            // Confirmed against RedisURI.java (Lettuce): verifyPeer is one of the few query
            // parameters its own string-URI parser actually recognizes (NONE|CA|FULL) --
            // unlike a made-up "sslInsecure", which it would silently ignore.
            Map<String, String> properties = Map.of(
                    "spring.redis.url", "rediss://localhost:6379?verifyPeer=NONE"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message())
                    .contains("verifypeer=none")
                    .contains("CWE-295");
        }

        @Test
        @DisplayName("Prioritizes CWE-319 when both disabled TLS and no-verify parameters are present")
        void shouldPrioritizeDisabledTlsOverNoVerifyWhenBothArePresent() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:mysql://localhost:3306/db?useSSL=false&verifyServerCertificate=false"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().message()).contains("CWE-319");
        }
    }

    @Nested
    @DisplayName("Insecure Scheme Detection (CWE-319, non-query-param tools)")
    class RiskySchemeTests {

        @Test
        @DisplayName("Detects http:// on an Elasticsearch URI with no query string at all")
        void shouldDetectHttpSchemeOnElasticsearch() {
            Map<String, String> properties = Map.of(
                    "spring.elasticsearch.uris", "http://localhost:9200"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message())
                    .contains("http://")
                    .contains("spring.elasticsearch.uris")
                    .contains("CWE-319");
        }

        @Test
        @DisplayName("Stays silent when Elasticsearch URI uses https://")
        void shouldStaySilentOnHttpsElasticsearch() {
            Map<String, String> properties = Map.of(
                    "spring.elasticsearch.uris", "https://localhost:9200"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Detects amqp:// on a RabbitMQ address written as a full AMQP URI")
        void shouldDetectAmqpSchemeOnRabbitMq() {
            Map<String, String> properties = Map.of(
                    "spring.rabbitmq.addresses", "amqp://guest:guest@localhost:5672/vhost"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("Stays silent when RabbitMQ address uses amqps://")
        void shouldStaySilentOnAmqpsRabbitMq() {
            Map<String, String> properties = Map.of(
                    "spring.rabbitmq.addresses", "amqps://guest:guest@localhost:5671/vhost"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Stays silent on the bare host:port RabbitMQ address form (no scheme to inspect)")
        void shouldStaySilentOnBareHostPortRabbitMq() {
            // Deliberate boundary, not a gap: "host:port" carries no TLS signal of its own --
            // that's spring.rabbitmq.ssl.enabled's job (SCG015, RabbitMqInsecureTransportRule).
            // This mechanism only catches the explicit amqp:///amqps:// URI authoring style.
            Map<String, String> properties = Map.of(
                    "spring.rabbitmq.addresses", "localhost:5672"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Detects tcp:// on an ActiveMQ broker URL")
        void shouldDetectTcpSchemeOnActiveMq() {
            Map<String, String> properties = Map.of(
                    "spring.activemq.broker-url", "tcp://localhost:61616"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("Stays silent when ActiveMQ broker URL uses ssl://")
        void shouldStaySilentOnSslActiveMq() {
            Map<String, String> properties = Map.of(
                    "spring.activemq.broker-url", "ssl://localhost:61617"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Detects ldap:// on an LDAP URL")
        void shouldDetectLdapScheme() {
            Map<String, String> properties = Map.of(
                    "spring.ldap.urls", "ldap://directory.internal:389"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("Stays silent when LDAP URL uses ldaps://")
        void shouldStaySilentOnLdaps() {
            Map<String, String> properties = Map.of(
                    "spring.ldap.urls", "ldaps://directory.internal:636"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "spring.cloud.aws.s3.endpoint",
                "spring.cloud.aws.sqs.endpoint",
                "spring.cloud.aws.sns.endpoint",
                "spring.cloud.aws.dynamodb.endpoint",
                "spring.cloud.aws.ses.endpoint"
        })
        @DisplayName("Detects http:// on a Spring Cloud AWS per-service endpoint override")
        void shouldDetectHttpSchemeOnAwsServiceEndpoint(String key) {
            Map<String, String> properties = Map.of(
                    key, "http://localhost:4566"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "spring.cloud.aws.s3.endpoint",
                "spring.cloud.aws.sqs.endpoint",
                "spring.cloud.aws.sns.endpoint",
                "spring.cloud.aws.dynamodb.endpoint",
                "spring.cloud.aws.ses.endpoint"
        })
        @DisplayName("Stays silent when a Spring Cloud AWS per-service endpoint override uses https://")
        void shouldStaySilentOnHttpsAwsServiceEndpoint(String key) {
            Map<String, String> properties = Map.of(
                    key, "https://s3.eu-west-1.amazonaws.com"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Reports INFO for an unresolved placeholder on a scheme-based key, same as query-param keys")
        void shouldReportInfoOnUnresolvedPlaceholderForSchemeBasedKey() {
            Map<String, String> properties = Map.of(
                    "spring.elasticsearch.uris", "${ES_URI}"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }
    }

    @Nested
    @DisplayName("Environment Placeholders and Resolution")
    class PlaceholderAndEnvironmentTests {

        @Test
        @DisplayName("Reports INFO finding for unresolved dynamic environment placeholders")
        void shouldReportInfoForUnresolvedPlaceholder() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "${DB_URL}"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.INFO);
            assertThat(finding.message()).contains("unresolved environment placeholder '${DB_URL}'");
        }

        @Test
        @DisplayName("Resolves static placeholder default and appends origin note to the finding message")
        void shouldDetectInsecureParamInPlaceholderDefaultAndAppendNote() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "${DB_URL:jdbc:mysql://localhost:3306/db?useSSL=false}"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message())
                    .contains("usessl=false")
                    .contains("The value originates from a static placeholder default");
        }

        @Test
        @DisplayName("Does not generate finding when resolved placeholder default is secure")
        void shouldNotFlagSecurePlaceholderDefault() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "${DB_URL:jdbc:mysql://localhost:3306/db?useSSL=true}"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }
    }

    @Nested
    @DisplayName("Edge Cases, Canonicalization, and Regressions")
    class EdgeCasesAndRegressionTests {

        @Test
        @DisplayName("Ignores connection URIs without query parameters")
        void shouldIgnoreUrisWithoutQueryParams() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:postgresql://localhost:5432/db"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Does NOT flag sslmode=prefer because it is driver default behavior")
        void shouldNotFlagSslModePrefer() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:postgresql://localhost:5432/db?sslmode=prefer"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Handles uppercase and mixed-case parameter names and values correctly")
        void shouldBeCaseInsensitiveForParamsAndValues() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:mysql://localhost:3306/db?USeSSL=FaLsE"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().message()).contains("usessl=false");
        }

        @ParameterizedTest
        @ValueSource(strings = {"spring.elasticsearch.uris", "spring.rabbitmq.addresses"})
        @DisplayName("Detects insecure TLS parameters when uri-based key is written as a real YAML list")
        void shouldDetectInsecureTlsWhenKeyIsWrittenAsYamlList(String baseKey) {
            Map<String, String> properties = Map.of(
                    baseKey + "[0]", "https://es-node1:9200?ssl=true",
                    baseKey + "[1]", "https://es-node2:9200?ssl=false"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            Finding finding = findings.getFirst();
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message())
                    .contains(baseKey + "[1]")
                    .contains("ssl=false");
        }

        @Test
        @DisplayName("Ignores non-uri-based properties even if they contain insecure query parameters")
        void shouldIgnoreNonUriProperties() {
            Map<String, String> properties = Map.of(
                    "custom.app.my-query", "http://localhost/search?useSSL=false"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Should respect relaxed binding for the compound-word broker-url segment")
        void shouldSupportRelaxedBindingForBrokerUrl() {
            // "spring.activemq.broker-url" is the one uri-based key with a real compound-word
            // segment among the seven configured in SCG012.yml -- written here as camelCase.
            Map<String, String> properties = Map.of(
                    "spring.activemq.brokerUrl", "tcp://localhost:61616?ssl=false"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("Should stay silent when placeholder resolves to an empty default")
        void shouldStaySilentWhenPlaceholderResolvesToEmptyDefault() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "${DB_URL:}"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Should stay silent when the raw property value is literally blank")
        void shouldStaySilentWhenRawValueIsLiterallyBlank() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "   "
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @ParameterizedTest
        @ValueSource(strings = {"ssl=maybe", "sslmode=verify-full", "tls=maybe"})
        @DisplayName("Should stay silent for recognized parameter names with unrecognized/unmapped values")
        void shouldStaySilentForUnrecognizedParameterValues(String queryParam) {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:postgresql://localhost:5432/db?" + queryParam
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @Test
        @DisplayName("Should not throw and stay silent when a targeted property's value is null")
        void shouldNotThrowWhenPropertyValueIsNull() {
            Map<String, String> properties = new HashMap<>();
            properties.put("spring.datasource.url", null);

            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            assertThat(rule.check(config)).isEmpty();
        }

        @ParameterizedTest
        @ValueSource(strings = {"dev", "staging", "prod"})
        @DisplayName("Should report findings regardless of active profile (Zero-Trust)")
        void shouldReportRegardlessOfProfile(String profile) {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:mysql://localhost:3306/db?useSSL=false"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, profile, properties);

            assertThat(rule.check(config)).hasSize(1);
        }

        @Test
        @DisplayName("Should report independent findings for multiple different insecure connection properties")
        void shouldReportIndependentFindingsAcrossDifferentProperties() {
            Map<String, String> properties = Map.of(
                    "spring.datasource.url", "jdbc:mysql://localhost:3306/db?useSSL=false",
                    "spring.data.mongodb.uri", "mongodb://localhost:27017/db?ssl=false"
            );
            EffectiveConfig config = new EffectiveConfig(mockPath, "default", properties);

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(2);
            assertThat(findings).allMatch(f -> f.severity() == Severity.HIGH);
        }
    }
}