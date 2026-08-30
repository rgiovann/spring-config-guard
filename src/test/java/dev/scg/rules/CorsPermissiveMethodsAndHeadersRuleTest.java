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

    @Test
    @DisplayName("Should generate a MEDIUM Finding when allowed-methods=*")
    void shouldGenerateFindingForAllowedMethodsWildcard() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                ProfileMerger.BASE_PROFILE_LABEL,
                Map.of("spring.mvc.cors.allowed-methods", "*")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG005");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("spring.mvc.cors.allowed-methods");
    }

    @Test
    @DisplayName("Should generate a MEDIUM Finding when exposed-headers contains Authorization or Set-Cookie")
    void shouldGenerateFindingForExposedSensitiveHeaders() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.mvc.cors.exposed-headers", "Authorization, X-Custom-Header, Set-Cookie")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("Authorization", "Set-Cookie");
    }

    @Test
    @DisplayName("Should generate a LOW Finding when exposed-headers=*")
    void shouldGenerateLowFindingForExposedHeadersWildcard() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.mvc.cors.exposed-headers", "*")
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.LOW);
    }

    @Test
    @DisplayName("Should NOT generate a Finding when allowed-methods explicitly specifies methods")
    void shouldNotGenerateFindingForExplicitMethods() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.mvc.cors.allowed-methods", "GET, POST, PUT, DELETE")
        );

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should NOT generate a Finding when exposed-headers contains safe operational headers")
    void shouldNotGenerateFindingForExplicitSafeHeaders() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.mvc.cors.exposed-headers", "Content-Disposition, X-Total-Count")
        );

        assertThat(rule.check(config)).isEmpty();
    }
}

