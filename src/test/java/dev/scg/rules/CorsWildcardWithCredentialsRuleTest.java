// FILE: CorsWildcardWithCredentialsRuleTest.java
// PACKAGE: dev.scg.rules

package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class CorsWildcardWithCredentialsRuleTest {

    private final CorsWildcardWithCredentialsRule rule = new CorsWildcardWithCredentialsRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    @Test
    @DisplayName("Should generate SCG003 finding when allowed-origins=* and allow-credentials=true in Spring MVC")
    void shouldGenerateFindingWhenWildcardAndCredentialsEnabledInMvc() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                ProfileMerger.BASE_PROFILE_LABEL,
                Map.of(
                        "spring.mvc.cors.allowed-origins", "*",
                        "spring.mvc.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG003");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("spring.mvc.cors.allowed-origins");
    }

    @Test
    @DisplayName("Should generate finding when allowed-origin-patterns=* and allow-credentials=true")
    void shouldGenerateFindingWhenWildcardInPatternsAndCredentialsEnabled() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origin-patterns", "*",
                        "spring.mvc.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("spring.mvc.cors.allowed-origin-patterns");
    }

    @Test
    @DisplayName("Should generate finding for Actuator Web CORS properties")
    void shouldGenerateFindingForActuatorProperties() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "*",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("management.endpoints.web.cors.allowed-origins");
    }

    @Test
    @DisplayName("Should generate multiple findings if both MVC and Actuator are vulnerable")
    void shouldGenerateMultipleFindingsForVulnerableMvcAndActuator() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origins", "*",
                        "spring.mvc.cors.allow-credentials", "true",
                        "management.endpoints.web.cors.allowed-origins", "*",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(2);
    }

    @Test
    @DisplayName("Should detect wildcard in YAML indexed lists (allowed-origins[0]=*)")
    void shouldDetectWildcardInIndexedYamlList(){
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origins[0]", "https://app.com",
                        "spring.mvc.cors.allowed-origins[1]", "*",
                        "spring.mvc.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @Test
    @DisplayName("Should detect subdomains with wildcard e.g. https://*.domain.com")
    void shouldDetectWildcardInSubdomainPattern() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origin-patterns", "https://*.mydomain.com",
                        "spring.mvc.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "TRUE", "yes", "YES", "on", "1"})
    @DisplayName("Should recognize truthy variations for allow-credentials property")
    void shouldRecognizeTruthyVariantsInAllowCredentials(String truthyValue) {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origins", "*",
                        "spring.mvc.cors.allow-credentials", truthyValue
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @Test
    @DisplayName("Should apply Relaxed Binding on key naming (camelCase vs kebab-case)")
    void shouldApplyRelaxedBindingOnKeys() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowedOrigins", "*",
                        "spring.mvc.cors.allowCredentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @Test
    @DisplayName("Should generate finding when allowed-origins is a dynamic placeholder without default")
    void shouldGenerateFindingForDynamicPlaceholderWithoutDefault() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origins", "${CORS_ORIGIN}",
                        "spring.mvc.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
    }

    @Test
    @DisplayName("Should NOT generate finding when placeholder contains default with explicit origin")
    void shouldNotGenerateFindingForPlaceholderWithSafeDefault() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origins", "${CORS_ORIGIN:https://myapp.com}",
                        "spring.mvc.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should NOT generate finding when allow-credentials is false")
    void shouldNotGenerateFindingWhenCredentialsIsFalse() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origins", "*",
                        "spring.mvc.cors.allow-credentials", "false"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should NOT generate finding when origins are explicit and safe")
    void shouldNotGenerateFindingForExplicitOrigins() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.mvc.cors.allowed-origins", "https://example.com,https://api.example.com",
                        "spring.mvc.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should NOT throw exception nor generate finding when values are null or empty")
    void shouldNotThrowExceptionWhenValuesAreNullOrEmpty() {
        Map<String, String> properties = new HashMap<>();
        properties.put("spring.mvc.cors.allowed-origins", null);
        properties.put("spring.mvc.cors.allow-credentials", null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        assertDoesNotThrow(() -> assertThat(rule.check(config)).isEmpty());
    }
}