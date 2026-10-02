package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InsecureServerTransportRuleTest {

    private InsecureServerTransportRule rule;

    @BeforeEach
    void setUp() {
        rule = new InsecureServerTransportRule();
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "no", "off", "0", "  FALSE  "})
    @DisplayName("Should report HIGH when server.ssl.enabled is explicitly falsy and keystore is present")
    void shouldReportHighWhenSslExplicitlyDisabledWithKeystore(String falsyValue) {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", falsyValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG011");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("SSL is explicitly disabled");
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "no", "off", "0", "  FALSE  "})
    @DisplayName("Should report MEDIUM when session cookie secure flag is explicitly falsy")
    void shouldReportMediumWhenCookieSecureExplicitlyDisabled(String falsyValue) {
        EffectiveConfig config = configOf(Map.of(
                "server.servlet.session.cookie.secure", falsyValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("Session cookie 'Secure' flag is explicitly disabled");
        assertThat(findings.getFirst().message()).contains("only takes effect with Spring Session");
    }

    @Test
    @DisplayName("Should stay silent when SSL is enabled or session cookie is secure")
    void shouldStaySilentWhenSecurelyConfigured() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", "true",
                "server.servlet.session.cookie.secure", "true"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when SSL key-store is absent even if ssl.enabled is false")
    void shouldStaySilentWhenKeystoreIsAbsent() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.enabled", "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when placeholder resolves to empty default")
    void shouldStaySilentWhenPlaceholderResolvesToEmptyDefault() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", "${SSL_ENABLED:}",
                "server.servlet.session.cookie.secure", "${COOKIE_SECURE:}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"disabled", "Flase", "none", "invalid_value"})
    @DisplayName("Should stay silent for third-bucket unrecognized values (garbage/typos)")
    void shouldStaySilentForUnrecognizedNonFalsyValues(String unrecognizedValue) {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", unrecognizedValue,
                "server.servlet.session.cookie.secure", unrecognizedValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should report INFO when property relies on an unresolved placeholder")
    void shouldReportInfoForUnresolvedPlaceholder() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", "${ENV_SSL_ENABLED}",
                "server.servlet.session.cookie.secure", "${ENV_COOKIE_SECURE}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.severity() == Severity.INFO);
        assertThat(findings.getFirst().message()).contains("unresolved environment placeholder");
    }

    @Test
    @DisplayName("Should stay silent when none of the targeted keys are present")
    void shouldStaySilentWithNoEvidenceOfTargetedKeys() {
        EffectiveConfig config = configOf(Map.of(
                "server.port", "8080",
                "spring.application.name", "demo"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should respect relaxed binding for the compound-word key-store segment")
    void shouldSupportRelaxedBindingForKeyStore() {
        // "server.ssl.enabled" and "server.servlet.session.cookie.secure" have no compound-word
        // segment, so case-folding is the only relaxed-binding dimension available for them
        // (already exercised by the "  FALSE  " variant above). "key-store" is the one key in
        // this rule with a real kebab/camel/snake_case variant to prove RelaxedProperties.get()
        // resolves correctly — written here as camelCase instead of the canonical kebab-case.
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.keyStore", "classpath:keystore.p12",
                "server.ssl.enabled", "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should check rules regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", "false"
        ), profile);

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should not throw and stay silent when all targeted properties are null")
    void shouldNotThrowWhenPropertiesAreNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("server.ssl.key-store", null);
        properties.put("server.ssl.enabled", null);
        properties.put("server.servlet.session.cookie.secure", null);

        EffectiveConfig config = new EffectiveConfig(Path.of("application.yml"), "default", properties);

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report both findings independently when SSL and the session cookie are both insecure")
    void shouldReportBothFindingsWhenSslAndCookieAreBothInsecure() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", "false",
                "server.servlet.session.cookie.secure", "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(2);
        assertThat(findings).anyMatch(f -> f.severity() == Severity.HIGH
                && f.message().contains("SSL is explicitly disabled"));
        assertThat(findings).anyMatch(f -> f.severity() == Severity.MEDIUM
                && f.message().contains("Session cookie 'Secure' flag is explicitly disabled"));
    }

    @Test
    @DisplayName("Should stay silent when key-store is present but blank")
    void shouldStaySilentWhenKeystoreIsBlank() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "   ",
                "server.ssl.enabled", "false"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when ssl.enabled is a literal blank value, before any placeholder resolution")
    void shouldStaySilentWhenRawSslEnabledIsLiterallyBlank() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", "   "
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    private static EffectiveConfig configOf(Map<String, String> properties) {
        return configOf(properties, "default");
    }

    // --- New Tests: Management SSL ---

    @ParameterizedTest
    @ValueSource(strings = {"false", "no", "off", "0", "  FALSE  "})
    @DisplayName("Should report HIGH when management SSL is explicitly disabled with keystore and separate management port")
    void shouldReportHighWhenManagementSslExplicitlyDisabled(String falsyValue) {
        EffectiveConfig config = configOf(Map.of(
                "management.server.port", "8081",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", falsyValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains("Management SSL is explicitly disabled");
        assertThat(findings.getFirst().message()).contains("management.server.port");
    }

    @Test
    @DisplayName("Should stay silent when management.server.port is absent even if management SSL is disabled with keystore")
    void shouldStaySilentWhenManagementPortIsAbsent() {
        EffectiveConfig config = configOf(Map.of(
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    // --- New Tests: HttpOnly & SameSite ---

    @ParameterizedTest
    @ValueSource(strings = {"false", "no", "off", "0", "  FALSE  "})
    @DisplayName("Should report MEDIUM when session cookie HttpOnly is explicitly falsy")
    void shouldReportMediumWhenCookieHttpOnlyExplicitlyDisabled(String falsyValue) {
        EffectiveConfig config = configOf(Map.of(
                "server.servlet.session.cookie.http-only", falsyValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("Session cookie 'HttpOnly' flag is explicitly disabled");
    }

    @ParameterizedTest
    @ValueSource(strings = {"None", "none", "NONE"})
    @DisplayName("Should report MEDIUM when session cookie SameSite is explicitly set to None")
    void shouldReportMediumWhenSameSiteIsNone(String sameSiteValue) {
        EffectiveConfig config = configOf(Map.of(
                "server.servlet.session.cookie.same-site", sameSiteValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("SameSite' attribute is explicitly set to 'None'");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Lax", "Strict", "lax", "strict"})
    @DisplayName("Should stay silent when SameSite is Lax or Strict")
    void shouldStaySilentWhenSameSiteIsSafe(String safeSameSite) {
        EffectiveConfig config = configOf(Map.of(
                "server.servlet.session.cookie.same-site", safeSameSite
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    // --- Modified/Expanded Tests ---

    @Test
    @DisplayName("Should report all findings independently when all insecure flags are configured")
    void shouldReportAllFindingsWhenAllInsecureFlagsPresent() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", "false",
                "server.servlet.session.cookie.secure", "false",
                "management.server.port", "8081",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false",
                "server.servlet.session.cookie.http-only", "false",
                "server.servlet.session.cookie.same-site", "None"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(5);
        long highCount = findings.stream().filter(f -> f.severity() == Severity.HIGH).count();
        long mediumCount = findings.stream().filter(f -> f.severity() == Severity.MEDIUM).count();

        assertThat(highCount).isEqualTo(2);
        assertThat(mediumCount).isEqualTo(3);
    }

    @Test
    @DisplayName("Should stay silent when placeholder resolves to empty default for all properties")
    void shouldStaySilentWhenPlaceholdersResolveToEmptyDefault() {
        EffectiveConfig config = configOf(Map.of(
                "server.ssl.key-store", "classpath:keystore.p12",
                "server.ssl.enabled", "${SSL_ENABLED:}",
                "server.servlet.session.cookie.secure", "${COOKIE_SECURE:}",
                "management.server.port", "8081",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "${MGMT_SSL_ENABLED:}",
                "server.servlet.session.cookie.http-only", "${HTTP_ONLY:}",
                "server.servlet.session.cookie.same-site", "${SAME_SITE:}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    // --- New Tests: additional coverage for the extended checks ---

    @Test
    @DisplayName("Should report INFO when the new checks' properties rely on an unresolved placeholder")
    void shouldReportInfoForUnresolvedPlaceholderInNewChecks() {
        EffectiveConfig config = configOf(Map.of(
                "management.server.port", "8081",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "${ENV_MGMT_SSL_ENABLED}",
                "server.servlet.session.cookie.http-only", "${ENV_HTTP_ONLY}",
                "server.servlet.session.cookie.same-site", "${ENV_SAME_SITE}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(3);
        assertThat(findings).allMatch(f -> f.severity() == Severity.INFO);
        assertThat(findings).allMatch(f -> f.message().contains("unresolved environment placeholder"));
    }

    @Test
    @DisplayName("Should respect relaxed binding for the compound-word http-only segment")
    void shouldSupportRelaxedBindingForHttpOnly() {
        EffectiveConfig config = configOf(Map.of(
                "server.servlet.session.cookie.httpOnly", "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should respect relaxed binding for the compound-word same-site segment")
    void shouldSupportRelaxedBindingForSameSite() {
        EffectiveConfig config = configOf(Map.of(
                "server.servlet.session.cookie.sameSite", "None"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should stay silent when management port is present but management key-store is absent")
    void shouldStaySilentWhenManagementKeystoreIsAbsent() {
        EffectiveConfig config = configOf(Map.of(
                "management.server.port", "8081",
                "management.server.ssl.enabled", "false"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when management port and key-store are present but management.server.ssl.enabled is absent")
    void shouldStaySilentWhenManagementSslEnabledIsAbsent() {
        EffectiveConfig config = configOf(Map.of(
                "management.server.port", "8081",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should not throw and stay silent when the new checks' properties are all null")
    void shouldNotThrowWhenNewCheckPropertiesAreNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("management.server.port", null);
        properties.put("management.server.ssl.key-store", null);
        properties.put("management.server.ssl.enabled", null);
        properties.put("server.servlet.session.cookie.http-only", null);
        properties.put("server.servlet.session.cookie.same-site", null);

        EffectiveConfig config = new EffectiveConfig(Path.of("application.yml"), "default", properties);

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should report management SSL findings regardless of active profile (Zero-Trust)")
    void shouldReportManagementSslRegardlessOfProfile(String profile) {
        EffectiveConfig config = configOf(Map.of(
                "management.server.port", "8081",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        ), profile);

        assertThat(rule.check(config)).hasSize(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"disabled", "Flase", "invalid_value"})
    @DisplayName("Should stay silent for third-bucket unrecognized values in management SSL and HttpOnly")
    void shouldStaySilentForUnrecognizedValuesInNewChecks(String unrecognizedValue) {
        EffectiveConfig config = configOf(Map.of(
                "management.server.port", "8081",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", unrecognizedValue,
                "server.servlet.session.cookie.http-only", unrecognizedValue
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"NoRestriction", "invalid_value", "Strictt"})
    @DisplayName("Should stay silent for unrecognized SameSite values that are neither None, Lax, nor Strict")
    void shouldStaySilentForUnrecognizedSameSiteValues(String unrecognizedValue) {
        EffectiveConfig config = configOf(Map.of(
                "server.servlet.session.cookie.same-site", unrecognizedValue
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when management.server.port is present but blank")
    void shouldStaySilentWhenManagementPortIsBlank() {
        EffectiveConfig config = configOf(Map.of(
                "management.server.port", "   ",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when management.server.ssl.key-store is present but blank")
    void shouldStaySilentWhenManagementKeystoreIsBlank() {
        EffectiveConfig config = configOf(Map.of(
                "management.server.port", "8081",
                "management.server.ssl.key-store", "   ",
                "management.server.ssl.enabled", "false"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    // --- Scenarios checked in running Spring Boot 4.1.1 apps (VALIDATION.md, "SCG011 transport scenarios") ---

    @Test
    @DisplayName("T8: should report HIGH when SSL is disabled with a PEM certificate")
    void shouldReportHighWhenSslDisabledWithPemCertificate() {
        List<Finding> findings = rule.check(configOf(Map.of(
                "server.ssl.certificate", "classpath:cert.pem",
                "server.ssl.certificate-private-key", "classpath:key.pem",
                "server.ssl.enabled", "false"
        )));

        assertThat(findings).singleElement().satisfies(f -> {
            assertThat(f.severity()).isEqualTo(Severity.HIGH);
            assertThat(f.message()).contains("'server.ssl.certificate'").doesNotContain("remove");
        });
    }

    @Test
    @DisplayName("T10: should report HIGH when SSL is disabled with an SSL bundle")
    void shouldReportHighWhenSslDisabledWithBundle() {
        List<Finding> findings = rule.check(configOf(Map.of(
                "server.ssl.bundle", "web",
                "server.ssl.enabled", "false"
        )));

        assertThat(findings).singleElement().satisfies(f -> {
            assertThat(f.severity()).isEqualTo(Severity.HIGH);
            assertThat(f.message()).contains("'server.ssl.bundle'");
        });
    }

    @Test
    @DisplayName("Should report HIGH when SSL is disabled with server-name bundles (SNI)")
    void shouldReportHighWhenSslDisabledWithServerNameBundles() {
        List<Finding> findings = rule.check(configOf(Map.of(
                "server.ssl.server-name-bundles[0].server-name", "example.com",
                "server.ssl.server-name-bundles[0].bundle", "web",
                "server.ssl.enabled", "false"
        )));

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("T12: should stay silent when SSL is disabled without any TLS material")
    void shouldStaySilentWhenSslDisabledWithoutTlsMaterial() {
        assertThat(rule.check(configOf(Map.of("server.ssl.enabled", "false")))).isEmpty();
    }

    @Test
    @DisplayName("M2: should report HIGH when management SSL is disabled on a separate port that inherits server.ssl")
    void shouldReportHighWhenManagementSslDisabledInheritingServerSsl() {
        List<Finding> findings = rule.check(configOf(Map.of(
                "server.port", "9443",
                "server.ssl.key-store", "classpath:keystore.p12",
                "management.server.port", "9444",
                "management.server.ssl.enabled", "false"
        )));

        assertThat(findings).singleElement().satisfies(f -> {
            assertThat(f.severity()).isEqualTo(Severity.HIGH);
            assertThat(f.message()).contains("Management SSL is explicitly disabled", "'server.ssl.key-store'");
        });
    }

    @Test
    @DisplayName("M1: should stay silent when the separate management port inherits server.ssl")
    void shouldStaySilentWhenManagementPortInheritsServerSsl() {
        assertThat(rule.check(configOf(Map.of(
                "server.port", "9443",
                "server.ssl.key-store", "classpath:keystore.p12",
                "management.server.port", "9444"
        )))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"-1", "-100"})
    @DisplayName("M5: should stay silent when a negative management port disables the management server")
    void shouldStaySilentWhenManagementPortIsNegative(String port) {
        assertThat(rule.check(configOf(Map.of(
                "management.server.port", port,
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        )))).isEmpty();
    }

    @Test
    @DisplayName("M6: should stay silent when the management port equals server.port")
    void shouldStaySilentWhenManagementPortEqualsServerPort() {
        assertThat(rule.check(configOf(Map.of(
                "server.port", "9443",
                "server.ssl.key-store", "classpath:keystore.p12",
                "management.server.port", "9443",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        )))).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when the management port is 8080 and server.port is not set")
    void shouldStaySilentWhenManagementPortEqualsDefaultServerPort() {
        assertThat(rule.check(configOf(Map.of(
                "management.server.port", "8080",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        )))).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH when the management port is 0 (random), even if server.port is 0")
    void shouldReportHighWhenManagementPortIsRandom() {
        assertThat(rule.check(configOf(Map.of(
                "server.port", "0",
                "management.server.port", "0",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        )))).singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should report HIGH when the management port placeholder resolves to a separate port")
    void shouldReportHighWhenManagementPortPlaceholderHasSeparateDefault() {
        assertThat(rule.check(configOf(Map.of(
                "management.server.port", "${MGMT_PORT:9444}",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        )))).singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should report INFO when the management port is an unresolved placeholder")
    void shouldReportInfoWhenManagementPortIsUnresolved() {
        assertThat(rule.check(configOf(Map.of(
                "management.server.port", "${MGMT_PORT}",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        )))).singleElement().satisfies(f -> {
            assertThat(f.severity()).isEqualTo(Severity.INFO);
            assertThat(f.message()).contains("'management.server.port'", "${MGMT_PORT}");
        });
    }

    @Test
    @DisplayName("Should report INFO when server.port is an unresolved placeholder the management port could equal")
    void shouldReportInfoWhenServerPortIsUnresolved() {
        assertThat(rule.check(configOf(Map.of(
                "server.port", "${PORT}",
                "management.server.port", "9444",
                "management.server.ssl.key-store", "classpath:mgmt-keystore.p12",
                "management.server.ssl.enabled", "false"
        )))).singleElement().satisfies(f -> {
            assertThat(f.severity()).isEqualTo(Severity.INFO);
            assertThat(f.message()).contains("'server.port'");
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "off"})
    @DisplayName("R1: should report MEDIUM when the WebFlux session cookie secure flag is falsy")
    void shouldReportMediumWhenReactiveCookieSecureDisabled(String value) {
        assertThat(rule.check(configOf(Map.of(
                "server.reactive.session.cookie.secure", value
        )))).singleElement().satisfies(f -> {
            assertThat(f.severity()).isEqualTo(Severity.MEDIUM);
            assertThat(f.message()).contains("server.reactive.session.cookie.secure", "WebFlux")
                    .doesNotContain("Spring Session");
        });
    }

    @Test
    @DisplayName("R2/R3: should report MEDIUM for the WebFlux http-only and same-site keys")
    void shouldReportMediumForReactiveHttpOnlyAndSameSite() {
        List<Finding> findings = rule.check(configOf(Map.of(
                "server.reactive.session.cookie.http-only", "false",
                "server.reactive.session.cookie.same-site", "None"
        )));

        assertThat(findings).hasSize(2).allMatch(f -> f.severity() == Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should report INFO when a WebFlux cookie key relies on an unresolved placeholder")
    void shouldReportInfoForUnresolvedReactiveCookie() {
        assertThat(rule.check(configOf(Map.of(
                "server.reactive.session.cookie.secure", "${COOKIE_SECURE}"
        )))).singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
    }

    private static EffectiveConfig configOf(Map<String, String> properties, String profileLabel) {
        return new EffectiveConfig(
                Path.of("application.yml"),
                profileLabel,
                properties
        );
    }
}