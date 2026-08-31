// FILE: CorsInsecureProtocolsRuleTest.java
// PACKAGE: dev.scg.rules

package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CorsInsecureProtocolsRuleTest {

    private final CorsInsecureProtocolsRule rule = new CorsInsecureProtocolsRule();
    private static final Path FAKE_PATH = Path.of("application.yml");


    @ParameterizedTest
    @ValueSource(strings = {"dev", "test", "local", "prod", "qa"})
    @DisplayName("Should generate MEDIUM finding for http:// origin in any profile (Zero-Trust)")
    void shouldGenerateFindingForHttpInAnyProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                profile,
                Map.of("management.endpoints.web.cors.allowed-origins", "http://app.company.com")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG004");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("http://app.company.com");
    }

    @Test
    @DisplayName("Should NOT generate finding for http://localhost or http://127.0.0.1")
    void shouldNotGenerateFindingForLocalhost() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origins", "http://localhost:3000, http://127.0.0.1:8080")
        );

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should NOT generate finding for origins using secure protocol https://")
    void shouldNotGenerateFindingForHttps() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origins", "https://app.company.com")
        );

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should detect http:// when mixed with secure origins in a comma-separated list")
    void shouldDetectHttpInMixedList() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origins", "https://secure.com, http://insecure.com")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("http://insecure.com");
    }

    @Test
    @DisplayName("Should detect http:// in allowed-origin-patterns property")
    void shouldDetectHttpInAllowedOriginPatterns() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origin-patterns", "http://*.company.com")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("management.endpoints.web.cors.allowed-origin-patterns");
    }

    @Test
    @DisplayName("Should detect localhost subdomain bypass attempts (e.g., http://localhost.attacker.com)")
    void shouldDetectSubdomainLocalhostBypass() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origins", "http://localhost.attacker.com")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("http://localhost.attacker.com");
    }

    @Test
    @DisplayName("Should recognize IPv6 loopback, 127.x.x.x range, and .localhost as local and NOT generate finding")
    void shouldRecognizeLoopbackVariationsAsLocal() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origins", "http://127.0.1.1:8080, http://[::1]:3000, http://app.localhost")
        );

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should generate finding for .local mDNS domains over http:// to prevent LAN MitM")
    void shouldGenerateFindingForMdnsLocalDomains() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origins", "http://app.local:8080")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG004");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("http://app.local:8080");
    }

    @Test
    @DisplayName("Should NOT throw exception on malformed URI, treating it fail-closed as non-local")
    void shouldNotThrowExceptionForMalformedUri() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origins", "http://an_invalid_syntax_origin.com")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @Test
    @DisplayName("Should generate an INFO finding when allowed-origins relies on an unresolved environment placeholder")
    void shouldGenerateInfoFindingForUnresolvedPlaceholders() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("management.endpoints.web.cors.allowed-origins", "${CORS_ALLOWED_ORIGINS}")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG004");
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder", "${CORS_ALLOWED_ORIGINS}");
    }

}