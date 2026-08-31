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
    @DisplayName("Should classify a domain-scoped wildcard origin pattern as MEDIUM, not HIGH")
    void shouldClassifyDomainScopedWildcardAsMedium() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origin-patterns", "https://*.minhaempresa.com",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
            assertThat(finding.message()).contains("domain-scoped wildcard");
        });
    }

    @Test
    @DisplayName("Should retain HIGH severity when a list includes the global wildcard")
    void shouldRetainHighSeverityForGlobalWildcardAmongPatterns() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origin-patterns", "https://*.minhaempresa.com, *",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should not generate finding when no wildcard is present")
    void shouldNotGenerateFindingWithoutWildcard() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origin-patterns",
                        "https://app.minhaempresa.com",
                        "management.endpoints.web.cors.allow-credentials",
                        "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should classify multiple scoped wildcard patterns as MEDIUM")
    void shouldClassifyMultipleScopedWildcardsAsMedium() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origin-patterns",
                        "https://*.minhaempresa.com, https://*.parceiro.com",
                        "management.endpoints.web.cors.allow-credentials",
                        "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
            assertThat(finding.message()).contains("domain-scoped wildcard");
        });
    }

    @Test
    @DisplayName("Should treat unresolved placeholder as GLOBAL")
    void shouldTreatUnresolvedPlaceholderAsGlobal() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origin-patterns",
                        "${CORS_ALLOWED_ORIGINS}",
                        "management.endpoints.web.cors.allow-credentials",
                        "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        });
    }

    @Test
    @DisplayName("Should generate findings independently for allowed-origins and allowed-origin-patterns")
    void shouldGenerateFindingsForBothOriginProperties() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "*",
                        "management.endpoints.web.cors.allowed-origin-patterns", "https://*.minhaempresa.com",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(2);

        assertThat(findings)
                .filteredOn(finding ->
                        finding.message().contains("allowed-origins"))
                .singleElement()
                .satisfies(finding ->
                        assertThat(finding.severity()).isEqualTo(Severity.HIGH));

        assertThat(findings)
                .filteredOn(finding ->
                        finding.message().contains("allowed-origin-patterns"))
                .singleElement()
                .satisfies(finding ->
                        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM));
    }

    @Test
    @DisplayName("Should retain HIGH severity when global wildcard appears in either origin property")
    void shouldDetectGlobalWildcardRegardlessOfOriginProperty() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "https://app.minhaempresa.com",
                        "management.endpoints.web.cors.allowed-origin-patterns", "*",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                    assertThat(finding.message())
                            .contains("allowed-origin-patterns");
                });
    }

    @Test
    @DisplayName("Should classify scoped wildcard in allowed-origins when credentials are enabled")
    void shouldClassifyScopedWildcardInAllowedOrigins() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins",
                        "https://*.minhaempresa.com, https://api.parceiro.com",
                        "management.endpoints.web.cors.allow-credentials",
                        "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .satisfies(finding ->
                        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM));
    }

    @Test
    @DisplayName("Should not generate finding when both origin properties contain only explicit origins")
    void shouldIgnoreExplicitOriginsInBothProperties() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins",
                        "https://app.minhaempresa.com, https://admin.minhaempresa.com",
                        "management.endpoints.web.cors.allowed-origin-patterns",
                        "https://api.minhaempresa.com",
                        "management.endpoints.web.cors.allow-credentials",
                        "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should not generate finding when credentials are disabled")
    void shouldIgnoreWildcardsWhenCredentialsAreDisabled() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "*",
                        "management.endpoints.web.cors.allowed-origin-patterns", "https://*.minhaempresa.com",
                        "management.endpoints.web.cors.allow-credentials", "false"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should not generate finding when credentials property is absent")
    void shouldIgnoreWildcardsWhenCredentialsPropertyIsAbsent() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "*"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Should not generate finding when credentials value is false regardless of origin property")
    void shouldIgnoreWildcardPatternsWhenCredentialsAreFalse() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origin-patterns", "*",
                        "management.endpoints.web.cors.allow-credentials", "false"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"TRUE", "True", " true ", " true"})
    @DisplayName("Should detect wildcard when allow-credentials uses a supported truthy representation")
    void shouldDetectWildcardForTruthyCredentialValues(String credentialsValue) {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "*",
                        "management.endpoints.web.cors.allow-credentials", credentialsValue
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should handle list-style allowed-origins representation")
    void shouldHandleListStyleAllowedOrigins() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins[0]", "*",
                        "management.endpoints.web.cors.allowed-origins[1]",
                        "https://app.minhaempresa.com",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                    assertThat(finding.message())
                            .contains("allowed-origins");
                });
    }

    @Test
    @DisplayName("Should handle list-style allowed-origin-patterns representation")
    void shouldHandleListStyleAllowedOriginPatterns() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origin-patterns[0]",
                        "https://*.minhaempresa.com",
                        "management.endpoints.web.cors.allowed-origin-patterns[1]",
                        "https://*.parceiro.com",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .satisfies(finding ->
                        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM));
    }

    @Test
    @DisplayName("Should prioritize global wildcard over scoped wildcard in list representation")
    void shouldPrioritizeGlobalWildcardInListRepresentation() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origin-patterns[0]",
                        "https://*.minhaempresa.com",
                        "management.endpoints.web.cors.allowed-origin-patterns[1]",
                        "*",
                        "management.endpoints.web.cors.allow-credentials", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.HIGH);
    }


}
