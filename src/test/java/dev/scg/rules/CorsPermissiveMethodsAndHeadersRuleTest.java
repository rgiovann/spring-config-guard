// FILE: CorsPermissiveMethodsAndHeadersRuleTest.java
// PACKAGE: dev.scg.rules

package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CorsPermissiveMethodsAndHeadersRuleTest {

    private final CorsPermissiveMethodsAndHeadersRule rule = new CorsPermissiveMethodsAndHeadersRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    private static final String ALLOWED_METHODS_KEY = "management.endpoints.web.cors.allowed-methods";
    private static final String EXPOSED_HEADERS_KEY = "management.endpoints.web.cors.exposed-headers";

    @Test
    @DisplayName("Should generate a MEDIUM Finding when allowed-methods=*")
    void shouldGenerateFindingForAllowedMethodsWildcard() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                ProfileMerger.BASE_PROFILE_LABEL,
                Map.of(ALLOWED_METHODS_KEY, "*")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG005");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains(ALLOWED_METHODS_KEY);
    }

    @Test
    @DisplayName("Should generate a MEDIUM Finding when exposed-headers contains Authorization or Set-Cookie")
    void shouldGenerateFindingForExposedSensitiveHeaders() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(EXPOSED_HEADERS_KEY, "Authorization, X-Custom-Header, Set-Cookie")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("Authorization", "Set-Cookie");
    }

    @Test
    @DisplayName("Should generate a MEDIUM Finding when exposed-headers=*")
    void shouldGenerateMediumFindingForExposedHeadersWildcard() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(EXPOSED_HEADERS_KEY, "*")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains(EXPOSED_HEADERS_KEY);
    }

    @Test
    @DisplayName("Should NOT generate a Finding when allowed-methods explicitly specifies safe methods")
    void shouldNotGenerateFindingForExplicitMethods() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(ALLOWED_METHODS_KEY, "GET, POST, PUT, DELETE")
        );

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should NOT generate a Finding when exposed-headers contains safe operational headers")
    void shouldNotGenerateFindingForExplicitSafeHeaders() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(EXPOSED_HEADERS_KEY, "Content-Disposition, X-Total-Count")
        );

        assertThat(rule.check(config)).isEmpty();
    }

    // --- TESTES ADICIONAIS PARA COBERTURA COMPLETA ---

    @Test
    @DisplayName("Should detect sensitive headers regardless of letter casing")
    void shouldDetectSensitiveHeadersCaseInsensitively() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(EXPOSED_HEADERS_KEY, "authorization, SET-COOKIE")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("authorization", "SET-COOKIE");
    }

    @Test
    @DisplayName("Should detect wildcards provided as YAML list items")
    void shouldDetectWildcardInYamlListFormat() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        EXPOSED_HEADERS_KEY + "[0]", "X-Custom-Header",
                        EXPOSED_HEADERS_KEY + "[1]", "*"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should generate an INFO finding when property value relies on an unresolved environment placeholder")
    void shouldGenerateInfoFindingForUnresolvedPlaceholders() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(ALLOWED_METHODS_KEY, "${CORS_ALLOWED_METHODS}")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG005");
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder", "${CORS_ALLOWED_METHODS}");
    }
}