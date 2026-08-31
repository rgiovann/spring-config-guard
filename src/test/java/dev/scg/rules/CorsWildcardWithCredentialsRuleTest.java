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

    public static final String ALLOWED_ORIGIN_PATTERNS_KEY = "management.endpoints.web.cors.allowed-origin-patterns";
    public static final String ALLOW_CREDENTIALS_KEY = "management.endpoints.web.cors.allow-credentials";
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
                        ALLOW_CREDENTIALS_KEY, "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("management.endpoints.web.cors.allowed-origins");
    }

    @Test
    @DisplayName("Should retain HIGH severity when a list includes the global wildcard")
    void shouldRetainHighSeverityForGlobalWildcardAmongPatterns() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        ALLOWED_ORIGIN_PATTERNS_KEY, "https://*.minhaempresa.com, *",
                        ALLOW_CREDENTIALS_KEY, "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }


    @Test
    @DisplayName("Should treat unresolved placeholder as GLOBAL")
    void shouldTreatUnresolvedPlaceholderAsGlobal() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        ALLOWED_ORIGIN_PATTERNS_KEY,
                        "${CORS_ALLOWED_ORIGINS}",
                        ALLOW_CREDENTIALS_KEY,
                        "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement()
                .satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.HIGH));
    }

    @Test
    @DisplayName("Should classify a placeholder resolving to a domain-scoped pattern as MEDIUM")
    void shouldClassifyPlaceholderWithScopedDefaultAsMedium() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        ALLOWED_ORIGIN_PATTERNS_KEY,
                        "${CORS_ORIGIN:https://*.minhaempresa.com}",
                        ALLOW_CREDENTIALS_KEY,
                        "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should classify a placeholder resolving to the literal global wildcard as HIGH")
    void shouldClassifyPlaceholderWithGlobalDefaultAsHigh() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins",
                        "${CORS_ORIGIN:*}",
                        ALLOW_CREDENTIALS_KEY,
                        "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should generate findings independently for allowed-origins and allowed-origin-patterns")
    void shouldGenerateFindingsForBothOriginProperties() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "*",
                        ALLOWED_ORIGIN_PATTERNS_KEY, "https://*.minhaempresa.com",
                        ALLOW_CREDENTIALS_KEY, "true"
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
                        ALLOWED_ORIGIN_PATTERNS_KEY, "*",
                        ALLOW_CREDENTIALS_KEY, "true"
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
                        ALLOW_CREDENTIALS_KEY,
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
                        ALLOWED_ORIGIN_PATTERNS_KEY,
                        "https://api.minhaempresa.com",
                        ALLOW_CREDENTIALS_KEY,
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
                        ALLOWED_ORIGIN_PATTERNS_KEY, "https://*.minhaempresa.com",
                        ALLOW_CREDENTIALS_KEY, "false"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://*.vercel.app",
            "https://tenant-*.minhaempresa.com"
    })
    @DisplayName("Should generate MEDIUM finding for realistic domain-scoped wildcard patterns")
    void shouldGenerateMediumFindingForNonGlobalWildcardPattern(String scopedOrigin) {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        ALLOWED_ORIGIN_PATTERNS_KEY, scopedOrigin,
                        ALLOW_CREDENTIALS_KEY, "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG003");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("domain-scoped wildcard");
    }


    @Test
    @DisplayName("Should differentiate global '*' (HIGH) from domain-restricted wildcard patterns (MEDIUM)")
    void shouldDifferentiateGlobalAndNonGlobalSeverities() {
        EffectiveConfig globalConfig = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "*",
                        ALLOW_CREDENTIALS_KEY, "true"
                )
        );

        EffectiveConfig nonGlobalConfig = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        ALLOWED_ORIGIN_PATTERNS_KEY, "https://*.domain.com",
                        ALLOW_CREDENTIALS_KEY, "true"
                )
        );
        

        List<Finding> globalFindings = rule.check(globalConfig);
        List<Finding> nonGlobalFindings = rule.check(nonGlobalConfig);

        assertThat(globalFindings).hasSize(1);
        assertThat(globalFindings.getFirst().severity()).isEqualTo(Severity.HIGH);

        assertThat(nonGlobalFindings).hasSize(1);
        assertThat(nonGlobalFindings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
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

    @ParameterizedTest
    @ValueSource(strings = {"TRUE", "True", " true ", " true"})
    @DisplayName("Should detect wildcard when allow-credentials uses a supported truthy representation")
    void shouldDetectWildcardForTruthyCredentialValues(String credentialsValue) {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "management.endpoints.web.cors.allowed-origins", "*",
                        ALLOW_CREDENTIALS_KEY, credentialsValue
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.HIGH);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "comma-separated",
            "list-style"
    })
    @DisplayName("Should classify domain-scoped wildcards as MEDIUM regardless of notation format")
    void shouldClassifyNonGlobalWildcardsAsMediumForBothNotations(String format) {
        Map<String, String> properties = "comma-separated".equals(format)
                ? Map.of(
                ALLOWED_ORIGIN_PATTERNS_KEY,
                "https://*.minhaempresa.com, https://*.parceiro.com",
                ALLOW_CREDENTIALS_KEY, "true"
        )
                : Map.of(
                "management.endpoints.web.cors.allowed-origin-patterns[0]", "https://*.minhaempresa.com",
                "management.endpoints.web.cors.allowed-origin-patterns[1]", "https://*.parceiro.com",
                ALLOW_CREDENTIALS_KEY, "true"
        );

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
                    assertThat(finding.message()).contains("domain-scoped wildcard");
                });
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
                        ALLOW_CREDENTIALS_KEY, "true"
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
                        ALLOW_CREDENTIALS_KEY, "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings)
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should not throw exception when property values contain null")
    void shouldNotThrowExceptionWhenValuesAreNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("management.endpoints.web.cors.allowed-origins", null);
        properties.put(ALLOW_CREDENTIALS_KEY, null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        assertDoesNotThrow(() -> assertThat(rule.check(config)).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "*",
            "https://*",
            "http://*",
            "*://*"
    })
    @DisplayName("Should generate HIGH Finding for global wildcard patterns without literal hosts")
    void shouldGenerateHighFindingForGlobalWildcards(String pattern) {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                ProfileMerger.BASE_PROFILE_LABEL,
                Map.of(
                        ALLOWED_ORIGIN_PATTERNS_KEY, pattern,
                        ALLOW_CREDENTIALS_KEY, "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://*.empresa.com",
            "https://*.com",
            "https://*.sub.empresa.com.br",
            "http://*.internal.net"
    })
    @DisplayName("Should generate MEDIUM Finding for wildcard patterns with literal host parts")
    void shouldGenerateMediumFindingForDomainScopedWildcards(String pattern) {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                ProfileMerger.BASE_PROFILE_LABEL,
                Map.of(
                        ALLOWED_ORIGIN_PATTERNS_KEY, pattern,
                        ALLOW_CREDENTIALS_KEY, "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should NOT generate Finding when allow-credentials=false")
    void shouldNotGenerateFindingWhenCredentialsDisabled() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                ProfileMerger.BASE_PROFILE_LABEL,
                Map.of(
                        ALLOWED_ORIGIN_PATTERNS_KEY, "https://*",
                        ALLOW_CREDENTIALS_KEY, "false"
                )
        );

        assertThat(rule.check(config)).isEmpty();
    }

}
