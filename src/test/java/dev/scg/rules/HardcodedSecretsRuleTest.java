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

        @ParameterizedTest(name = "Should ignore ''{0}'' = ''{1}''")
        @CsvSource({
                "jwt.token-validity-in-seconds, 86400",
                "jwt.token-validity-in-seconds, 2592000",
                "jwt.token-validity-in-seconds, 0",
                "app.security.token-remember-me-enabled, true",
                "app.security.token-remember-me-enabled, TRUE",
                "app.security.token-remember-me-enabled, false",
                "app.require-password, TRUE",
                "management.endpoints.web.cors.allow-credentials, true"
        })
        @DisplayName("Ignores a key that only contains a pattern (a metric) and a boolean in a key that ends in one (a switch)")
        void shouldIgnoreCustomSecretKeyPatternForPrimitiveValues(String propertyKey, String primitiveValue) {
            Map<String, String> props = Map.of(propertyKey, primitiveValue);
            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @ParameterizedTest(name = "Should ignore ''{0}'' = ''{1}'' behind a placeholder")
        @CsvSource({
                "jwt.token-validity-in-seconds, ${TOKEN_TTL:86400}",
                "jwt.token-validity-in-seconds, ${TOKEN_TTL:0}",
                "app.security.token-remember-me-enabled, ${REMEMBER_ME:true}",
                "app.security.token-remember-me-enabled, ${REMEMBER_ME:FALSE}",
                "app.require-password, ${REQUIRE_PASSWORD:true}"
        })
        @DisplayName("Same as above when the value is a placeholder's static default")
        void shouldIgnoreCustomSecretKeyPatternForPrimitiveValuesBehindPlaceholder(String propertyKey, String placeholderValue) {
            Map<String, String> props = Map.of(propertyKey, placeholderValue);
            EffectiveConfig config = createConfig(props);

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @ParameterizedTest(name = "Should detect a numeric secret in ''{0}'' = ''{1}''")
        @CsvSource({
                // Found in spring-cloud-stream-samples (kafka-ssl-demo), missed before this check
                "spring.cloud.stream.kafka.binder.configuration.ssl.keystore.password, 123456",
                "spring.cloud.stream.kafka.binder.configuration.ssl.truststore.password, 123456",
                "spring.cloud.stream.kafka.binder.configuration.ssl.key.password, 123456",
                "app.payment.api-key, 99887766",
                "app.vault.secret, 0000",
                "app.db.password, ${DB_PASSWORD:1234}"
        })
        @DisplayName("Reports a numeric value when the key ends in a secret pattern, naming the secret itself")
        void shouldDetectNumericValueWhenKeyNamesTheSecret(String propertyKey, String value) {
            List<Finding> findings = rule.check(createConfig(Map.of(propertyKey, value)));

            assertThat(findings).singleElement().satisfies(finding ->
                    assertThat(finding.severity()).isEqualTo(Severity.HIGH));
        }

        @ParameterizedTest(name = "Should still ignore ''{0}'' = ''{1}''")
        @CsvSource({
                "app.security.password-min-length, 8",
                "app.security.password.encoder-strength, 10",
                "app.secret-rotation-days, 30",
                "app.require-password, true",
                "app.api-key, false"
        })
        @DisplayName("Ignores keys that don't end in a pattern, and booleans in keys that do")
        void shouldStillIgnoreMetricsAndSwitches(String propertyKey, String value) {
            assertThat(rule.check(createConfig(Map.of(propertyKey, value)))).isEmpty();
        }

        @ParameterizedTest(name = "Should detect custom property matching pattern: {0}")
        @ValueSource(strings = {
                "app.jwt.token",
                "custom.service.api-key",
                "payment.gateway.secret",
                "aws.access-key",
                "db.client.credential",
                "MY_SERVICE_APIKEY",
                "auth.user-password",
                "app.jwt.secret-key",
                "management.elastic.metrics.export.api-key-credentials"
        })
        @DisplayName("Detects custom property keys ending in a configured secret pattern")
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

        @ParameterizedTest(name = "Should ignore key ending in a location/endpoint suffix: {0}")
        @ValueSource(strings = {
                "spring.security.oauth2.authorizationserver.endpoint.token-uri",
                "spring.security.oauth2.authorizationserver.endpoint.token-revocation-uri",
                "spring.security.oauth2.authorizationserver.endpoint.token-introspection-uri",
                "app.security.token-url",
                "app.security.credential-endpoint"
        })
        @DisplayName("Ignores custom-pattern matches whose key ends in a location suffix (uri/url/endpoint) -- the property is a network address, not a value")
        void shouldIgnoreKeysEndingInLocationSuffix(String key) {
            // Real-world regression: spring-projects/spring-boot's own OAuth2 Authorization
            // Server smoke test names these "token-uri"/"token-revocation-uri"/
            // "token-introspection-uri", holding endpoint paths like "/token", not a token
            // value -- found via a corpus run against the real repository (session 2026-09-16).
            EffectiveConfig config = createConfig(Map.of(key, "/some/endpoint/path"));

            List<Finding> findings = rule.check(config);

            assertThat(findings).isEmpty();
        }

        @ParameterizedTest(name = "HIGH: ''{0}'' = ''{1}''")
        @CsvSource(delimiter = '|', value = {
                "app.security.token-url | https://user:s3cr3t@auth.example.com/token",
                "app.secret-endpoint | https://:s3cr3t@hooks.example.com/notify",
                "app.security.token-url | ${TOKEN_URL:https://user:s3cr3t@auth.example.com/token}"
        })
        @DisplayName("Reports HIGH for a password in the user-info of a URL in a location key")
        void shouldReportHighForUserInfoPasswordInLocationKey(String key, String value) {
            assertThat(rule.check(createConfig(Map.of(key, value)))).singleElement().satisfies(finding -> {
                assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                assertThat(finding.message()).contains("user-info of the URL in property '" + key + "'");
                assertThat(finding.message().contains("static placeholder default")).isEqualTo(value.startsWith("${"));
            });
        }

        @Test
        @DisplayName("Reports INFO for a query string in a URL in a location key, which may hold a token")
        void shouldReportInfoForQueryStringInLocationKey() {
            assertThat(rule.check(createConfig(Map.of("app.security.token-url", "https://auth.example.com/token?api_key=abc123"))))
                    .singleElement().satisfies(finding -> {
                        assertThat(finding.severity()).isEqualTo(Severity.INFO);
                        assertThat(finding.message()).contains("query string");
                    });
        }

        @ParameterizedTest(name = "Silent: ''{0}''")
        @ValueSource(strings = {
                "https://auth.example.com/oauth2/token",
                "/oauth2/token",
                "https://user@auth.example.com/token",
                "https://user:@auth.example.com/token",
                "https://auth.example.com:8443/token/@me",
                "https://auth.example.com/token?",
                "${TOKEN_URL}",
                "",
                // Accepted limitation: a secret in the path itself (webhook style)
                "https://hooks.example.com/services/T000/B000/XXXXXXXXXXXXXXXX"
        })
        @DisplayName("Stays silent for a location key whose URL has no password in its user-info and no query string")
        void shouldStaySilentForPlainUrlInLocationKey(String value) {
            assertThat(rule.check(createConfig(Map.of("app.security.token-url", value)))).isEmpty();
        }

        @Test
        @DisplayName("Still detects a genuine custom-pattern key that does NOT end in a location suffix (positive control for the key-suffix guard)")
        void shouldStillDetectCustomPatternKeyNotEndingInLocationSuffix() {
            // "app.jwt.token" is the same case already covered by
            // shouldDetectCustomPatternKeys above; repeated here, co-located with the
            // suffix-exclusion tests, to make the contrast with shouldIgnoreKeysEndingInLocationSuffix
            // explicit: only the location-suffixed keys are exempted, not "token" matches in general.
            EffectiveConfig config = createConfig(Map.of("app.jwt.token", "raw-token-value-99"));

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        }
    }

    @Nested
    @DisplayName("A pattern elsewhere in the key: INFO, since it may or may not name a secret")
    class PatternPositionTests {

        @ParameterizedTest(name = "INFO, not HIGH: ''{0}'' = ''{1}''")
        @CsvSource(delimiter = '|', value = {
                // Native Spring Boot 4.1.1 properties (OAuth2AuthorizationServerProperties.Token,
                // the resource server's opaquetoken, Hikari, embedded LDAP)
                "spring.security.oauth2.authorizationserver.client.web.token.access-token-time-to-live | 5m",
                "spring.security.oauth2.authorizationserver.client.web.token.refresh-token-time-to-live | PT1H",
                "spring.security.oauth2.authorizationserver.client.web.token.authorization-code-time-to-live | 10m",
                "spring.security.oauth2.authorizationserver.client.web.token.access-token-format | reference",
                "spring.security.oauth2.authorizationserver.client.web.token.id-token-signature-algorithm | RS256",
                "spring.security.oauth2.resourceserver.opaquetoken.client-id | resource-server",
                "spring.datasource.hikari.credentials-provider-class-name | com.example.Provider",
                "spring.ldap.embedded.credential.username | uid=admin",
                // Third-party namespaces, map keys and application properties
                "spring.cloud.kubernetes.secrets.namespace | default",
                "spring.cloud.kubernetes.secrets.name | db-secret",
                "spring.cloud.gcp.secretmanager.project-id | my-project",
                "spring.cloud.stream.bindings.tokenEvents-in-0.destination | token-events",
                "app.security.password-encoder | bcrypt",
                "app.jwt.token-prefix | Bearer",
                "app.jwt.token-validity | 1h"
        })
        @DisplayName("Reports INFO, not HIGH, where the pattern names a namespace, a map key or a nested object")
        void shouldReportInfoForPatternNotAtTheEnd(String key, String value) {
            // With the pattern matched anywhere, all of these were HIGH (v1.6.0). They can't fail a
            // build as INFO, yet a key like app.secret-key-base (below) still shows up.
            assertThat(rule.check(createConfig(Map.of(key, value))))
                    .singleElement().satisfies(this::assertAmbiguousKeyInfo);
        }

        @ParameterizedTest(name = "INFO: ''{0}''")
        @ValueSource(strings = {
                "app.secret-key-base",
                "app.password-hash",
                "app.api-keys"
        })
        @DisplayName("Reports INFO for a secret named with the word before another one or in the plural, instead of missing it")
        void shouldReportInfoForPatternFollowedByAnotherWord(String key) {
            assertThat(rule.check(createConfig(Map.of(key, "c2VjcmV0LXZhbHVl"))))
                    .singleElement().satisfies(this::assertAmbiguousKeyInfo);
        }

        @Test
        @DisplayName("Reports INFO for a placeholder's static default too, saying where the value comes from")
        void shouldReportInfoForPlaceholderDefaultInAmbiguousKey() {
            assertThat(rule.check(createConfig(Map.of("app.token-value", "${TOKEN_VALUE:tok-123}"))))
                    .singleElement().satisfies(finding -> {
                        assertAmbiguousKeyInfo(finding);
                        assertThat(finding.message()).contains("static placeholder default ('${TOKEN_VALUE:tok-123}')");
                    });
        }

        @ParameterizedTest(name = "Silent: ''{0}''")
        @ValueSource(strings = {"true", "FALSE", "86400", "", "   ", "${TOKEN_VALUE}", "${TOKEN_VALUE:}",
                "${TOKEN_TTL:3600}", "file:/etc/keys/app.key", "{cipher}AQB0"})
        @DisplayName("Stays silent in an ambiguous key for values that can't be a hardcoded secret")
        void shouldStaySilentForNonSecretValuesInAmbiguousKey(String value) {
            assertThat(rule.check(createConfig(Map.of("app.token-value", value)))).isEmpty();
        }

        private void assertAmbiguousKeyInfo(Finding finding) {
            assertThat(finding.severity()).isEqualTo(Severity.INFO);
            assertThat(finding.message()).contains("doesn't end in it");
        }

        @ParameterizedTest(name = "Should ignore ''{0}''")
        @ValueSource(strings = {
                "logging.level.org.springframework.security.oauth2.server.authorization.token",
                "logging.level.com.example.PasswordResetService",
                "logging.group.secret"
        })
        @DisplayName("Ignores logging.level and logging.group, whose last segment is a logger or group name")
        void shouldIgnoreLoggingKeys(String key) {
            assertThat(rule.check(createConfig(Map.of(key, "DEBUG")))).isEmpty();
        }

        @Test
        @DisplayName("The logging prefix is matched on a '.' boundary: a key merely starting with the same text is still checked")
        void shouldMatchIgnoredPrefixOnSegmentBoundary() {
            assertThat(rule.check(createConfig(Map.of("logging.levelx.password", "s3cr3t")))).hasSize(1);
        }

        @Test
        @DisplayName("Accepted limitation: a key naming a secret that holds a plain file path is reported")
        void shouldReportPlainPathInKeyNamingASecret() {
            // Only classpath:/file: values are recognized as locations; spring.ssl.bundle.pem.*.private-key
            // also accepts the PEM content itself, so a bare path can't be told apart safely.
            assertThat(rule.check(createConfig(Map.of("server.ssl.certificate-private-key", "/etc/tls/server.key"))))
                    .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.HIGH));
        }
    }

    @Nested
    @DisplayName("Value Exclusions and Encryption Prefix Handling")
    class ValueExclusionTests {

        @ParameterizedTest(name = "Should ignore value starting with prefix: {0}")
        @ValueSource(strings = {
                "{cipher}FK2049SFKSL204920SLFK",
                "{vault}secret/data/db#password",
                "   {cipher}WITH_LEADING_SPACES",
                "ENC(AQBvZ2VyZmFrZQ==)"
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

        @ParameterizedTest(name = "Silent, public material: ''{0}'' = ''{1}''")
        @CsvSource(delimiter = '|', value = {
                "spring.security.saml2.relyingparty.registration.one.signing.credentials[0].certificate-location | classpath:saml/certificate.txt",
                "spring.security.saml2.relyingparty.registration.one.assertingparty.verification.credentials[0].certificate-location | /etc/saml/idp.crt",
                "app.credentials.client-certificate | -----BEGIN CERTIFICATE-----"
        })
        @DisplayName("Stays silent for a certificate or its location in a key that only contains a pattern: a certificate is public")
        void shouldStaySilentForPublicMaterial(String key, String value) {
            assertThat(rule.check(createConfig(Map.of(key, value)))).isEmpty();
        }

        @Test
        @DisplayName("Still reports a key naming a secret even when it mentions a certificate (certificate-private-key)")
        void shouldStillReportPrivateKeyOfCertificate() {
            assertThat(rule.check(createConfig(Map.of("server.ssl.certificate-private-key", "classpath:server.key"))))
                    .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.INFO));
        }

        @Test
        @DisplayName("Ignores a file: reference, which points to secret material outside the application")
        void shouldIgnoreFileReference() {
            EffectiveConfig config = createConfig(
                    Map.of("spring.ssl.bundle.pem.default.keystore.private-key", "file:/etc/secrets/server.key"));

            assertThat(rule.check(config)).isEmpty();
        }

        @ParameterizedTest(name = "INFO for packaged material: ''{0}'' = ''{1}''")
        @CsvSource(delimiter = '|', value = {
                // The PEM SSL bundle's bare private-key holds a reference, not the key (found via a
                // corpus run against spring-projects/spring-boot, session 2026-09-16): not HIGH, but
                // the key ships inside the jar, so not silent either.
                "spring.ssl.bundle.pem.default.keystore.private-key | classpath:default/server.key",
                "spring.ssl.bundle.pem.default.keystore.private-key | classpath*:keys/server.key",
                "spring.datasource.password | classpath:db-password.txt",
                "app.jwt.secret | ${JWT_SECRET_FILE:classpath:jwt.key}",
                // A key that only contains a pattern (SAML's private-key-location, a GCP credentials file)
                "spring.security.saml2.relyingparty.registration.one.signing.credentials[0].private-key-location | classpath:saml/privatekey.txt",
                "spring.cloud.gcp.credentials.location | classpath:gcp-service-account.json"
        })
        @DisplayName("Reports INFO, not HIGH, for a classpath: reference: the secret is packaged with the application")
        void shouldReportInfoForClasspathReference(String key, String value) {
            assertThat(rule.check(createConfig(Map.of(key, value)))).singleElement().satisfies(finding -> {
                assertThat(finding.severity()).isEqualTo(Severity.INFO);
                assertThat(finding.message()).contains("packaged with the application");
            });
        }

        @Test
        @DisplayName("Still detects a genuine custom-pattern key whose value is NOT a resource reference (positive control)")
        void shouldStillDetectNonLocationValueForResourceLikeKey() {
            EffectiveConfig config = createConfig(
                    Map.of("spring.ssl.bundle.pem.default.keystore.private-key",
                            "-----BEGIN PRIVATE KEY-----\nMIIExampleKeyMaterial\n-----END PRIVATE KEY-----")
            );

            List<Finding> findings = rule.check(config);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
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
        @DisplayName("Throws IllegalArgumentException if packaged-value-prefixes contains placeholder prefix '${'")
        void shouldRejectPlaceholderInPackagedPrefixes() {
            Map<String, List<String>> invalidMetadata = Map.of(
                    "high-risk-keys", List.of("spring.datasource.password"),
                    "secret-key-patterns", List.of("password"),
                    "packaged-value-prefixes", List.of("${")
            );

            assertThatThrownBy(() -> new HardcodedSecretsRule().configure(invalidMetadata))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Cannot include placeholder prefix '${' in 'packaged-value-prefixes'");
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