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
import org.junit.jupiter.params.provider.CsvSource;
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
    @DisplayName("Should report an unresolved placeholder as INFO: static analysis can't tell (never HIGH)")
    void shouldReportUnresolvedPlaceholderAsInfo() {
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
                .satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.INFO));
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
    @DisplayName("Should report LOW for a placeholder resolving to '*' in allowed-origins: Spring rejects it with credentials")
    void shouldReportLowForPlaceholderResolvingToStarInAllowedOrigins() {
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
                .isEqualTo(Severity.LOW);
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
                        finding.message().contains("allowed-origins'"))
                .singleElement()
                .satisfies(finding ->
                        assertThat(finding.severity()).isEqualTo(Severity.LOW));

        assertThat(findings)
                .filteredOn(finding ->
                        finding.message().contains("domain-scoped wildcard"))
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
    @DisplayName("Should stay silent for a domain wildcard in allowed-origins: Spring compares it literally (403 for every origin)")
    void shouldIgnoreScopedWildcardInAllowedOrigins() {
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

        assertThat(findings).isEmpty();
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
                        ALLOWED_ORIGIN_PATTERNS_KEY, "*",
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
                        ALLOWED_ORIGIN_PATTERNS_KEY, "*",
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
    @DisplayName("Should find '*' in list-style allowed-origins and report it as LOW")
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
                    assertThat(finding.severity()).isEqualTo(Severity.LOW);
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
            "*://*",
            // An attacker can register a matching origin (checked in a running app): evil.com,
            // evilexample.com, app.evil.com
            "https://*.com",
            "https://*example.com",
            "https://app.*",
            "https://*.example.com.*"
    })
    @DisplayName("Should generate HIGH Finding for patterns without literal hosts, or that an attacker can register a match for")
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
            "https://*.sub.empresa.com.br",
            "http://*.internal.net",
            "https://*-staging.empresa.com",
            "https://*.empresa.com:[*]"
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

    // Checked against running Spring Boot 4.1.1 apps (VALIDATION.md, "SCG003 CORS scenarios")

    @ParameterizedTest(name = "{0}: {1} = {2} -> {3}")
    @CsvSource(delimiter = '|', value = {
            "management.endpoints.web.cors | allowed-origin-patterns | *                     | HIGH",
            "spring.graphql.cors           | allowed-origin-patterns | *                     | HIGH",
            "spring.graphql.cors           | allowed-origin-patterns | https://*             | HIGH",
            "spring.graphql.cors           | allowed-origin-patterns | https://*.example.com | MEDIUM",
            "spring.graphql.cors           | allowed-origins         | *                     | LOW"
    })
    @DisplayName("Spring for GraphQL's CORS properties behave like Actuator's, with credentials enabled")
    void shouldCoverGraphqlCorsLikeActuator(String prefix, String key, String value, Severity expected) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                prefix + "." + key, value,
                prefix + ".allow-credentials", "true"));

        assertThat(rule.check(config)).singleElement().satisfies(finding -> {
            assertThat(finding.severity()).isEqualTo(expected);
            assertThat(finding.message()).contains(prefix + ".");
        });
    }

    @Test
    @DisplayName("A literal domain wildcard in spring.graphql.cors.allowed-origins is silent too (Spring answers 403)")
    void shouldIgnoreLiteralWildcardInGraphqlAllowedOrigins() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.graphql.cors.allowed-origins", "https://*.example.com",
                "spring.graphql.cors.allow-credentials", "true"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("allow-credentials from an unresolved placeholder with a wildcard pattern is INFO, not HIGH")
    void shouldReportUnresolvedCredentialsWithWildcardAsInfo() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                ALLOWED_ORIGIN_PATTERNS_KEY, "*",
                ALLOW_CREDENTIALS_KEY, "${CORS_CREDENTIALS}"));

        assertThat(rule.check(config)).singleElement()
                .satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.INFO));
    }

    @ParameterizedTest(name = "Silent: {0} = {1}")
    @CsvSource(delimiter = '|', value = {
            // Nothing to doubt: no wildcard can match, whatever the credentials resolve to
            "management.endpoints.web.cors.allowed-origin-patterns | https://app.example.com",
            // '*' in allowed-origins is either rejected (credentials true) or harmless (false)
            "management.endpoints.web.cors.allowed-origins         | *"
    })
    @DisplayName("allow-credentials from an unresolved placeholder stays silent when no outcome is a risk")
    void shouldStaySilentWhenUnresolvedCredentialsCantMatter(String key, String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                key, value,
                ALLOW_CREDENTIALS_KEY, "${CORS_CREDENTIALS}"));

        assertThat(rule.check(config)).isEmpty();
    }
}
