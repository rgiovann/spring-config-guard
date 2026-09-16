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

class JwtResourceServerInsecureTransportRuleTest {

    private static final String ISSUER_URI_KEY = "spring.security.oauth2.resourceserver.jwt.issuer-uri";
    private static final String JWK_SET_URI_KEY = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri";

    private JwtResourceServerInsecureTransportRule rule;

    @BeforeEach
    void setUp() {
        rule = new JwtResourceServerInsecureTransportRule();
    }

    @Test
    @DisplayName("Should stay silent when neither issuer-uri nor jwk-set-uri is present")
    void shouldStaySilentWithNoEvidenceOfTargetedKeys() {
        EffectiveConfig config = configOf(Map.of(
                "server.port", "8080",
                "spring.application.name", "demo"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH when issuer-uri uses HTTP")
    void shouldReportHighWhenIssuerUriIsHttp() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG017");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("forged JWKS");
    }

    @Test
    @DisplayName("Should report HIGH when jwk-set-uri uses HTTP")
    void shouldReportHighWhenJwkSetUriIsHttp() {
        EffectiveConfig config = configOf(Map.of(
                JWK_SET_URI_KEY, "http://auth.example.com/.well-known/jwks.json"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains("forged JWKS");
    }

    @Test
    @DisplayName("Should report both findings independently when issuer-uri and jwk-set-uri are both HTTP")
    void shouldReportBothFindingsWhenBothAreHttp() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm",
                JWK_SET_URI_KEY, "http://auth.example.com/.well-known/jwks.json"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.severity() == Severity.HIGH);
    }

    @Test
    @DisplayName("Should stay silent when issuer-uri uses HTTPS")
    void shouldStaySilentWhenIssuerUriIsHttps() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "https://auth.example.com/realm"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when jwk-set-uri uses HTTPS")
    void shouldStaySilentWhenJwkSetUriIsHttps() {
        EffectiveConfig config = configOf(Map.of(
                JWK_SET_URI_KEY, "https://auth.example.com/.well-known/jwks.json"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH regardless of scheme casing")
    void shouldReportHighForUppercaseHttpScheme() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "HTTP://auth.example.com/realm"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should report INFO when issuer-uri relies on an unresolved placeholder")
    void shouldReportInfoForUnresolvedPlaceholderOnIssuerUri() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "${ISSUER_URI}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("unresolved placeholder");
    }

    @Test
    @DisplayName("Should report INFO when jwk-set-uri relies on an unresolved placeholder")
    void shouldReportInfoForUnresolvedPlaceholderOnJwkSetUri() {
        EffectiveConfig config = configOf(Map.of(
                JWK_SET_URI_KEY, "${JWK_SET_URI}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("unresolved placeholder");
    }

    @Test
    @DisplayName("Should stay silent when placeholder resolves to an empty default")
    void shouldStaySilentWhenPlaceholderResolvesToEmptyDefault() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "${ISSUER_URI:}",
                JWK_SET_URI_KEY, "${JWK_SET_URI:}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH with a static-default note when the placeholder default itself is HTTP")
    void shouldReportHighWithStaticDefaultNoteWhenPlaceholderDefaultIsHttp() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "${ISSUER_URI:http://auth.example.com/realm}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains("static placeholder fallback");
    }

    @Test
    @DisplayName("Should respect relaxed binding for issuer-uri written in camelCase")
    void shouldSupportRelaxedBindingForIssuerUri() {
        EffectiveConfig config = configOf(Map.of(
                "spring.security.oauth2.resourceserver.jwt.issuerUri", "http://auth.example.com/realm"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should respect relaxed binding for jwk-set-uri written in snake_case")
    void shouldSupportRelaxedBindingForJwkSetUri() {
        EffectiveConfig config = configOf(Map.of(
                "spring.security.oauth2.resourceserver.jwt.jwk_set_uri", "http://auth.example.com/.well-known/jwks.json"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should report regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm"
        ), profile);

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should stay silent when issuer-uri is present but blank, before any placeholder resolution")
    void shouldStaySilentWhenValueIsLiterallyBlank() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "   "
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should not throw and stay silent when the targeted properties are null")
    void shouldNotThrowWhenPropertiesAreNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put(ISSUER_URI_KEY, null);
        properties.put(JWK_SET_URI_KEY, null);

        EffectiveConfig config = new EffectiveConfig(Path.of("application.yml"), "default", properties);

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH when URL contains leading/trailing whitespace")
    void shouldReportHighWhenUrlHasLeadingOrTrailingWhitespace() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "  http://auth.example.com/realm  "
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should stay silent when placeholder resolves to a static HTTPS default")
    void shouldStaySilentWhenPlaceholderDefaultIsHttps() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "${ISSUER_URI:https://auth.example.com/realm}"
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
