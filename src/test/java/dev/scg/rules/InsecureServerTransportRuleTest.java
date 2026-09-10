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
    @DisplayName("Should report HIGH when session cookie secure flag is explicitly falsy")
    void shouldReportHighWhenCookieSecureExplicitlyDisabled(String falsyValue) {
        EffectiveConfig config = configOf(Map.of(
                "server.servlet.session.cookie.secure", falsyValue
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains("Session cookie 'Secure' flag is explicitly disabled");
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
        assertThat(findings).allMatch(f -> f.severity() == Severity.HIGH);
        assertThat(findings).anyMatch(f -> f.message().contains("SSL is explicitly disabled"));
        assertThat(findings).anyMatch(f -> f.message().contains("Session cookie 'Secure' flag is explicitly disabled"));
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

    private static EffectiveConfig configOf(Map<String, String> properties, String profileLabel) {
        return new EffectiveConfig(
                Path.of("application.yml"),
                profileLabel,
                properties
        );
    }
}