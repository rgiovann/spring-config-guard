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

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;

class H2ConsoleExposedRuleTest {

    private final H2ConsoleExposedRule rule = new H2ConsoleExposedRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    @Test
    @DisplayName("Should generate a HIGH Finding when the H2 console is enabled in the base profile")
    void shouldGenerateFindingWhenH2IsEnabledInBase() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                ProfileMerger.BASE_PROFILE_LABEL,
                Map.of("spring.h2.console.enabled", "true")
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        Finding finding = findings.getFirst();
        assertEquals("SCG002", finding.ruleId());
        assertEquals(Severity.HIGH, finding.severity());
        assertTrue(finding.message().contains("spring.h2.console.enabled=true"));
    }

    @Test
    @DisplayName("Should generate a finding when the H2 console is enabled in a production profile")
    void shouldGenerateFindingWhenH2IsEnabledInProd() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.h2.console.enabled", "TRUE")
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
    }

    @Test
    @DisplayName("Should generate a finding for Spring Boot truthy variants (yes, on, 1)")
    void shouldGenerateFindingForTruthyVariants() {
        List<String> truthyValues = List.of("yes", "YES", "on", "1");

        for (String value : truthyValues) {
            EffectiveConfig config = new EffectiveConfig(
                    FAKE_PATH,
                    "prod",
                    Map.of("spring.h2.console.enabled", value)
            );

            List<Finding> findings = rule.check(config);
            assertEquals(1, findings.size(), "Should have generated a Finding for the truthy value: " + value);
        }
    }

    @Test
    @DisplayName("Should generate a finding for profile names containing keywords as substrings (delivery, devices)")
    void shouldGenerateFindingForProfilesWithSafeKeywordsAsSubstrings() {
        List<String> unsafeProfiles = List.of("delivery", "devices", "contest");

        for (String profile : unsafeProfiles) {
            EffectiveConfig config = new EffectiveConfig(
                    FAKE_PATH,
                    profile,
                    Map.of("spring.h2.console.enabled", "true")
            );

            List<Finding> findings = rule.check(config);
            assertEquals(1, findings.size(), "Should have generated a Finding for the profile: " + profile);
        }
    }

    @Test
    @DisplayName("Should NOT generate a Finding when the H2 console is disabled or absent")
    void shouldNotGenerateFindingWhenDisabledOrAbsent() {
        EffectiveConfig disabledConfig = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.h2.console.enabled", "false")
        );

        EffectiveConfig missingConfig = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("server.port", "8080")
        );

        assertTrue(rule.check(disabledConfig).isEmpty());
        assertTrue(rule.check(missingConfig).isEmpty());
    }

    @Test
    @DisplayName("Should NOT throw an exception or generate a Finding when the property value is null")
    void shouldNotThrowExceptionWhenPropertyIsNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("spring.h2.console.enabled", null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        assertDoesNotThrow(() -> assertTrue(rule.check(config).isEmpty()));
    }

    @Test
    @DisplayName("Should escalate the message when web-allow-others is enabled along with the console")
    void shouldEscalateMessageWhenWebAllowOthersIsEnabled() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.h2.console.enabled", "true",
                        "spring.h2.console.settings.web-allow-others", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        Finding finding = findings.getFirst();
        assertEquals(Severity.HIGH, finding.severity());
        assertTrue(finding.message().contains("AGGRAVATING FACTOR"));
        assertTrue(finding.message().contains("spring.h2.console.settings.web-allow-others=true"));
    }

    @Test
    @DisplayName("Should NOT escalate the message when web-allow-others is absent")
    void shouldNotEscalateMessageWhenWebAllowOthersIsAbsent() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.h2.console.enabled", "true")
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        assertFalse(findings.getFirst().message().contains("AGGRAVATING FACTOR"));
    }

    @Test
    @DisplayName("Should NOT escalate the message when web-allow-others is explicitly false")
    void shouldNotEscalateMessageWhenWebAllowOthersIsFalse() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.h2.console.enabled", "true",
                        "spring.h2.console.settings.web-allow-others", "false"
                )
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        assertFalse(findings.getFirst().message().contains("AGGRAVATING FACTOR"));
    }

    @Test
    @DisplayName("Should generate a finding when enabled is a dynamic placeholder without a default")
    void shouldGenerateFindingWhenEnabledIsDynamicPlaceholderWithoutDefault() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod",
                Map.of("spring.h2.console.enabled", "${H2_ENABLED}"));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should NOT generate a Finding when enabled is a placeholder with a false default")
    void shouldNotGenerateFindingWhenEnabledIsPlaceholderWithFalseDefault() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod",
                Map.of("spring.h2.console.enabled", "${H2_ENABLED:false}"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should escalate the message when web-allow-others is a dynamic placeholder without a default")
    void shouldEscalateMessageWhenWebAllowOthersIsDynamicPlaceholderWithoutDefault() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.h2.console.enabled", "true",
                "spring.h2.console.settings.web-allow-others", "${ALLOW_REMOTE}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("AGGRAVATING FACTOR");
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "test", "local", "dev-local", "cloud-test", "local_db", "test.ci", "prod", "qa"})
    @DisplayName("Should generate a Finding when H2 console is enabled regardless of the profile (Zero-Trust)")
    void shouldGenerateFindingRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                profile,
                Map.of("spring.h2.console.enabled", "true")
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size(), "Should report a violation for profile: " + profile);
        assertEquals("SCG002", findings.getFirst().ruleId());
        assertEquals(Severity.HIGH, findings.getFirst().severity());
    }

}