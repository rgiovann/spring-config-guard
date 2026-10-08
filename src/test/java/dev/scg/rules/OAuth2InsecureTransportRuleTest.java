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

class OAuth2InsecureTransportRuleTest {

    private static final String ISSUER_URI_KEY = "spring.security.oauth2.resourceserver.jwt.issuer-uri";
    private static final String JWK_SET_URI_KEY = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri";
    private static final String PUBLIC_KEY_LOCATION_KEY = "spring.security.oauth2.resourceserver.jwt.public-key-location";
    private static final String INTROSPECTION_URI_KEY = "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri";

    private OAuth2InsecureTransportRule rule;

    @BeforeEach
    void setUp() {
        rule = new OAuth2InsecureTransportRule();
    }

    @Test
    @DisplayName("Should stay silent when none of the four keys is present")
    void shouldStaySilentWithNoEvidenceOfTargetedKeys() {
        EffectiveConfig config = configOf(Map.of(
                "server.port", "8080",
                "spring.application.name", "demo"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("I1: should report HIGH when issuer-uri uses HTTP")
    void shouldReportHighWhenIssuerUriIsHttp() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG017");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains(ISSUER_URI_KEY).contains("authentication bypass");
    }

    @Test
    @DisplayName("J1: should report HIGH when jwk-set-uri uses HTTP")
    void shouldReportHighWhenJwkSetUriIsHttp() {
        EffectiveConfig config = configOf(Map.of(
                JWK_SET_URI_KEY, "http://auth.example.com/.well-known/jwks.json"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains(JWK_SET_URI_KEY).contains("authentication bypass");
    }

    @Test
    @DisplayName("Should report only jwk-set-uri when both it and issuer-uri are HTTP: issuer-uri isn't fetched then")
    void shouldReportOnlyJwkSetUriWhenBothAreHttp() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm",
                JWK_SET_URI_KEY, "http://auth.example.com/.well-known/jwks.json"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains(JWK_SET_URI_KEY).doesNotContain(ISSUER_URI_KEY);
    }

    @Test
    @DisplayName("B1: should report jwk-set-uri when it is HTTP next to an HTTPS issuer-uri")
    void shouldReportJwkSetUriWhenHttpNextToHttpsIssuerUri() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "https://auth.example.com/realm",
                JWK_SET_URI_KEY, "http://auth.example.com/.well-known/jwks.json"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains(JWK_SET_URI_KEY);
    }

    @Test
    @DisplayName("B2: should stay silent on an HTTP issuer-uri next to an HTTPS jwk-set-uri, which decides where the keys come from")
    void shouldStaySilentOnHttpIssuerUriNextToHttpsJwkSetUri() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm",
                JWK_SET_URI_KEY, "https://auth.example.com/.well-known/jwks.json"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report an HTTP issuer-uri as INFO next to a jwk-set-uri that is an unresolved placeholder, which may resolve empty")
    void shouldReportHttpIssuerUriAsInfoNextToUnresolvedJwkSetUri() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm",
                JWK_SET_URI_KEY, "${JWK_SET_URI}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(2).allMatch(f -> f.severity() == Severity.INFO);
        assertThat(findings.get(0).message()).contains(JWK_SET_URI_KEY).contains("unresolved placeholder");
        assertThat(findings.get(1).message()).contains(ISSUER_URI_KEY)
                .contains("Used only if '" + JWK_SET_URI_KEY + "', an unresolved placeholder, resolves empty");
    }

    @Test
    @DisplayName("Should report only the placeholder when jwk-set-uri is unresolved and issuer-uri is HTTPS")
    void shouldReportOnlyThePlaceholderWhenJwkSetUriIsUnresolvedAndIssuerUriIsHttps() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "https://auth.example.com/realm",
                JWK_SET_URI_KEY, "${JWK_SET_URI}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains(JWK_SET_URI_KEY);
    }

    @Test
    @DisplayName("Should stop at the first key resolved after an unresolved placeholder")
    void shouldStopAtFirstResolvedKeyAfterPlaceholder() {
        EffectiveConfig config = configOf(Map.of(
                JWK_SET_URI_KEY, "${JWK_SET_URI}",
                ISSUER_URI_KEY, "https://auth.example.com/realm",
                PUBLIC_KEY_LOCATION_KEY, "http://auth.example.com/key.pub"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains(JWK_SET_URI_KEY);
    }

    @Test
    @DisplayName("Should report an HTTP issuer-uri when jwk-set-uri resolves to an empty default, which leaves it unset")
    void shouldReportIssuerUriWhenJwkSetUriResolvesEmpty() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm",
                JWK_SET_URI_KEY, "${JWK_SET_URI:}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains(ISSUER_URI_KEY);
    }

    @Test
    @DisplayName("K1: should report HIGH when public-key-location uses HTTP")
    void shouldReportHighWhenPublicKeyLocationIsHttp() {
        EffectiveConfig config = configOf(Map.of(
                PUBLIC_KEY_LOCATION_KEY, "http://auth.example.com/key.pub"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains(PUBLIC_KEY_LOCATION_KEY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"classpath:key.pub", "file:/etc/keys/key.pub", "https://auth.example.com/key.pub"})
    @DisplayName("Should stay silent when public-key-location is not an HTTP URL")
    void shouldStaySilentWhenPublicKeyLocationIsNotHttp(String location) {
        EffectiveConfig config = configOf(Map.of(
                PUBLIC_KEY_LOCATION_KEY, location
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("B3: should report an HTTP issuer-uri next to a public-key-location, since issuer-uri is still fetched")
    void shouldReportHttpIssuerUriNextToPublicKeyLocation() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm",
                PUBLIC_KEY_LOCATION_KEY, "file:/etc/keys/key.pub"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains(ISSUER_URI_KEY);
    }

    @Test
    @DisplayName("B4: should stay silent on an HTTP public-key-location next to an HTTPS jwk-set-uri, which decides where the keys come from")
    void shouldStaySilentOnHttpPublicKeyLocationNextToHttpsJwkSetUri() {
        EffectiveConfig config = configOf(Map.of(
                JWK_SET_URI_KEY, "https://auth.example.com/.well-known/jwks.json",
                PUBLIC_KEY_LOCATION_KEY, "http://auth.example.com/key.pub"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("B5: should stay silent on an HTTP public-key-location next to an HTTPS issuer-uri, which decides where the keys come from")
    void shouldStaySilentOnHttpPublicKeyLocationNextToHttpsIssuerUri() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "https://auth.example.com/realm",
                PUBLIC_KEY_LOCATION_KEY, "http://auth.example.com/key.pub"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report only issuer-uri when both it and public-key-location are HTTP: the key isn't read then")
    void shouldReportOnlyIssuerUriWhenItAndPublicKeyLocationAreHttp() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "http://auth.example.com/realm",
                PUBLIC_KEY_LOCATION_KEY, "http://auth.example.com/key.pub"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains(ISSUER_URI_KEY).doesNotContain(PUBLIC_KEY_LOCATION_KEY);
    }

    @Test
    @DisplayName("Should report the key source before introspection-uri, in a fixed order")
    void shouldReportKeySourceBeforeIntrospectionUri() {
        EffectiveConfig config = configOf(Map.of(
                INTROSPECTION_URI_KEY, "http://auth.example.com/introspect",
                ISSUER_URI_KEY, "http://auth.example.com/realm"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).extracting(Finding::message)
                .satisfiesExactly(
                        m -> assertThat(m).contains(ISSUER_URI_KEY),
                        m -> assertThat(m).contains(INTROSPECTION_URI_KEY));
    }

    @Test
    @DisplayName("O1: should report HIGH when introspection-uri uses HTTP")
    void shouldReportHighWhenIntrospectionUriIsHttp() {
        EffectiveConfig config = configOf(Map.of(
                INTROSPECTION_URI_KEY, "http://auth.example.com/introspect"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains(INTROSPECTION_URI_KEY).contains("client secret");
    }

    @Test
    @DisplayName("O2: should stay silent when introspection-uri uses HTTPS")
    void shouldStaySilentWhenIntrospectionUriIsHttps() {
        EffectiveConfig config = configOf(Map.of(
                INTROSPECTION_URI_KEY, "https://auth.example.com/introspect"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report an HTTP introspection-uri next to a jwk-set-uri, which doesn't decide it")
    void shouldReportIntrospectionUriNextToJwkSetUri() {
        EffectiveConfig config = configOf(Map.of(
                JWK_SET_URI_KEY, "https://auth.example.com/.well-known/jwks.json",
                INTROSPECTION_URI_KEY, "http://auth.example.com/introspect"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains(INTROSPECTION_URI_KEY);
    }

    @Test
    @DisplayName("Should report INFO when introspection-uri relies on an unresolved placeholder")
    void shouldReportInfoForUnresolvedPlaceholderOnIntrospectionUri() {
        EffectiveConfig config = configOf(Map.of(
                INTROSPECTION_URI_KEY, "${INTROSPECTION_URI}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("I2: should stay silent when issuer-uri uses HTTPS")
    void shouldStaySilentWhenIssuerUriIsHttps() {
        EffectiveConfig config = configOf(Map.of(
                ISSUER_URI_KEY, "https://auth.example.com/realm"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("J2: should stay silent when jwk-set-uri uses HTTPS")
    void shouldStaySilentWhenJwkSetUriIsHttps() {
        EffectiveConfig config = configOf(Map.of(
                JWK_SET_URI_KEY, "https://auth.example.com/.well-known/jwks.json"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {ISSUER_URI_KEY, JWK_SET_URI_KEY})
    @DisplayName("I3/J3: should report HIGH regardless of scheme casing")
    void shouldReportHighForUppercaseHttpScheme(String key) {
        EffectiveConfig config = configOf(Map.of(
                key, "HTTP://auth.example.com/realm"
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

    @Test
    @DisplayName("Should respect relaxed binding for jwk-set-uri when it decides the key source")
    void shouldSupportRelaxedBindingForJwkSetUriPrecedence() {
        EffectiveConfig config = configOf(Map.of(
                "spring.security.oauth2.resourceserver.jwt.jwkSetUri", "https://auth.example.com/.well-known/jwks.json",
                ISSUER_URI_KEY, "http://auth.example.com/realm"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should respect relaxed binding for public-key-location written in snake_case")
    void shouldSupportRelaxedBindingForPublicKeyLocation() {
        EffectiveConfig config = configOf(Map.of(
                "spring.security.oauth2.resourceserver.jwt.public_key_location", "http://auth.example.com/key.pub"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should respect relaxed binding for introspection-uri written in camelCase")
    void shouldSupportRelaxedBindingForIntrospectionUri() {
        EffectiveConfig config = configOf(Map.of(
                "spring.security.oauth2.resourceserver.opaquetoken.introspectionUri", "http://auth.example.com/introspect"
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

    @Test
    @DisplayName("L13: an http:// jwk-set-uri on a loopback address is INFO, not HIGH")
    void loopbackJwkSetUriIsInfo() {
        List<Finding> findings = rule.check(configOf(Map.of(
                JWK_SET_URI_KEY, "http://localhost:8080/oauth2/jwks")));

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("loopback addresses");
    }

    @Test
    @DisplayName("L17: an http:// issuer-uri on a loopback address stays HIGH: its metadata may name keys elsewhere")
    void loopbackIssuerUriStaysHigh() {
        assertThat(rule.check(configOf(Map.of(ISSUER_URI_KEY, "http://localhost:9000"))))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    // --- OAuth2 Client provider (VALIDATION.md, "OAuth2 Client provider transport scenarios")

    private static final String PROVIDER = "spring.security.oauth2.client.provider.scg.";

    @ParameterizedTest(name = "token-uri={0}")
    @ValueSource(strings = {"http://auth.example.com/token", "HTTP://auth.example.com/token"})
    @DisplayName("C1, C2, C4: an http:// token-uri is HIGH: the client sends its secret there in the clear")
    void clientTokenUriOverHttpIsHigh(String value) {
        assertThat(rule.check(configOf(Map.of(PROVIDER + "token-uri", value))))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                    assertThat(finding.message()).contains(PROVIDER + "token-uri").contains("client secret");
                });
    }

    @Test
    @DisplayName("I1: an http:// issuer-uri is HIGH: whoever answers names the token endpoint")
    void clientIssuerUriOverHttpIsHigh() {
        assertThat(rule.check(configOf(Map.of(PROVIDER + "issuer-uri", "http://auth.example.com"))))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                    assertThat(finding.message()).contains(PROVIDER + "issuer-uri").contains("token endpoint");
                });
    }

    @Test
    @DisplayName("C3, I2: https:// is silent")
    void clientOverHttpsIsSilent() {
        assertThat(rule.check(configOf(Map.of(
                PROVIDER + "token-uri", "https://auth.example.com/token",
                PROVIDER + "issuer-uri", "https://auth.example.com")))).isEmpty();
    }

    @Test
    @DisplayName("Both keys are used, so both are reported")
    void clientTokenAndIssuerBothReported() {
        assertThat(rule.check(configOf(Map.of(
                PROVIDER + "token-uri", "http://auth.example.com/token",
                PROVIDER + "issuer-uri", "http://auth.example.com"))))
                .hasSize(2).allSatisfy(finding -> assertThat(finding.severity()).isEqualTo(Severity.HIGH));
    }

    @Test
    @DisplayName("Loopback: a token-uri is INFO; an issuer-uri stays HIGH, since its metadata may name other hosts (spring-authorization-server's demo-client)")
    void clientLoopback() {
        assertThat(rule.check(configOf(Map.of(PROVIDER + "token-uri", "http://localhost:9000/oauth2/token"))))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.INFO));
        assertThat(rule.check(configOf(Map.of("spring.security.oauth2.client.provider.spring.issuer-uri", "http://localhost:9000"))))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.HIGH));
    }

    @Test
    @DisplayName("Placeholders: unresolved is INFO, an http:// default HIGH with its origin, an empty default silent")
    void clientPlaceholders() {
        assertThat(rule.check(configOf(Map.of(PROVIDER + "token-uri", "${TOKEN_URI}"))))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.INFO));
        assertThat(rule.check(configOf(Map.of(PROVIDER + "token-uri", "${TOKEN_URI:http://auth.example.com/token}"))))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                    assertThat(finding.message()).contains("static placeholder fallback");
                });
        assertThat(rule.check(configOf(Map.of(PROVIDER + "token-uri", "${TOKEN_URI:}")))).isEmpty();
    }

    @Test
    @DisplayName("Relaxed binding: a camelCase key is reported under the key as written")
    void clientRelaxedKey() {
        assertThat(rule.check(configOf(Map.of("spring.security.oauth2.client.provider.scg.tokenUri", "http://auth.example.com/token"))))
                .singleElement().satisfies(finding -> assertThat(finding.message()).contains("provider.scg.tokenUri"));
    }

    @Test
    @DisplayName("Out of scope: the login-flow keys (jwk-set-uri, user-info-uri), authorization-uri and registration keys are silent")
    void clientOtherKeysSilent() {
        assertThat(rule.check(configOf(Map.of(
                PROVIDER + "jwk-set-uri", "http://auth.example.com/jwks",
                PROVIDER + "user-info-uri", "http://auth.example.com/userinfo",
                PROVIDER + "authorization-uri", "http://auth.example.com/authorize",
                "spring.security.oauth2.client.registration.scg.redirect-uri", "http://app.example.com/login/oauth2/code/scg"))))
                .isEmpty();
    }
}
