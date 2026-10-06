package dev.scg.rules;

import dev.scg.core.ConfigLoader;
import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ConfigFileGrouper;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Row IDs (H1, P1, A2, ...) are the rows of VALIDATION.md, "SCG002 H2 console scenarios", measured in
 * spring-env-benchmark/h2-console.
 */
class H2ConsoleExposedRuleTest {

    private static final String ENABLED = "spring.h2.console.enabled";
    private static final String ALLOW_OTHERS = "spring.h2.console.settings.web-allow-others";

    private final H2ConsoleExposedRule rule = new H2ConsoleExposedRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    private List<Finding> check(Map<String, String> properties) {
        return rule.check(new EffectiveConfig(FAKE_PATH, "prod", properties));
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "TRUE", "True", "${H2_ENABLED:true}"})
    @DisplayName("H1, H2, H11: HIGH when enabled is true, in any case, the only value that turned the console on")
    void highWhenTrue(String value) {
        List<Finding> findings = check(Map.of(ENABLED, value));

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG002");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message())
                .contains(ENABLED + "=" + value)
                .contains("web SQL client")
                .contains("reverse proxy");
    }

    @ParameterizedTest
    @ValueSource(strings = {"yes", "YES", "on", "1", "true ", "false", "off", "", "banana", "${H2_ENABLED:false}"})
    @DisplayName("H3-H9: silent for every other value, including yes, on, 1 and a trailing space: the console stayed off")
    void silentForAnyOtherValue(String value) {
        assertThat(check(Map.of(ENABLED, value))).isEmpty();
    }

    @Test
    @DisplayName("H0: silent when the key is absent or null")
    void silentWhenAbsent() {
        Map<String, String> nullValue = new HashMap<>();
        nullValue.put(ENABLED, null);

        assertThat(check(Map.of("server.port", "8080"))).isEmpty();
        assertThat(check(nullValue)).isEmpty();
    }

    @Test
    @DisplayName("H10: INFO when enabled is a placeholder without a default: the value can't be known statically")
    void infoWhenUnresolved() {
        List<Finding> findings = check(Map.of(ENABLED, "${H2_ENABLED}"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("unresolved environment placeholder");
    }

    @Test
    @DisplayName("Y1: an unquoted YAML on is a YAML boolean, loaded as true, so it is HIGH")
    void unquotedYamlOnIsHigh(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "spring.h2.console.enabled: on\n");

        List<Finding> findings = new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(dir)).stream()
                .flatMap(group -> new ProfileMerger().merge(group).stream())
                .flatMap(config -> rule.check(config).stream())
                .toList();

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("P1: 'true ' with a trailing space in a .properties file reaches the rule as written, and is silent")
    void trailingSpaceThroughTheLoaderIsSilent(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.properties"), "spring.h2.console.enabled=true \n");

        List<Finding> findings = new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(dir)).stream()
                .flatMap(group -> new ProfileMerger().merge(group).stream())
                .flatMap(config -> rule.check(config).stream())
                .toList();

        assertThat(findings).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "yes", "on", "1", "${UNSET:true}"})
    @DisplayName("A1, A2, A5: web-allow-others, bound through the Binder, names the aggravating factor for every true literal")
    void allowOthersEscalatesMessage(String value) {
        List<Finding> findings = check(Map.of(ENABLED, "true", ALLOW_OTHERS, value));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message())
                .contains("AGGRAVATING FACTOR")
                .contains(ALLOW_OTHERS + "=" + value);
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "no"})
    @DisplayName("H1: web-allow-others false or absent keeps the loopback-only message")
    void allowOthersFalseKeepsLoopbackMessage(String value) {
        List<Finding> withFalse = check(Map.of(ENABLED, "true", ALLOW_OTHERS, value));
        List<Finding> absent = check(Map.of(ENABLED, "true"));

        assertThat(withFalse.getFirst().message()).doesNotContain("AGGRAVATING FACTOR").contains("loopback clients only");
        assertThat(absent.getFirst().message()).doesNotContain("AGGRAVATING FACTOR").contains("loopback clients only");
    }

    @Test
    @DisplayName("web-allow-others as a placeholder without a default says it may let every client in, without claiming it does")
    void allowOthersUnresolvedSaysMay() {
        List<Finding> findings = check(Map.of(ENABLED, "true", ALLOW_OTHERS, "${ALLOW_REMOTE}"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message())
                .doesNotContain("AGGRAVATING FACTOR")
                .contains("if it resolves to true");
    }

    @Test
    @DisplayName("A4, T1: web-admin-password and a custom path don't change the finding")
    void adminPasswordAndPathDontChangeTheFinding() {
        List<Finding> withPassword = check(Map.of(ENABLED, "true", ALLOW_OTHERS, "true",
                "spring.h2.console.settings.web-admin-password", "secret"));
        List<Finding> withPath = check(Map.of(ENABLED, "true", "spring.h2.console.path", "/db"));

        assertThat(withPassword).hasSize(1);
        assertThat(withPassword.getFirst().message()).contains("AGGRAVATING FACTOR");
        assertThat(withPath).hasSize(1);
        assertThat(withPath.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("A3: web-allow-others alone is silent: it didn't turn the console on")
    void allowOthersAloneIsSilent() {
        assertThat(check(Map.of(ALLOW_OTHERS, "true"))).isEmpty();
    }

    @Test
    @DisplayName("Should respect relaxed binding: camelCase and upper-case keys")
    void relaxedBinding() {
        List<Finding> findings = check(Map.of(
                "SPRING.H2.CONSOLE.ENABLED", "true",
                "spring.h2.console.settings.webAllowOthers", "true"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("AGGRAVATING FACTOR");
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "test", "local", "dev-local", "cloud-test", "local_db", "test.ci", "prod", "qa", "delivery", "devices"})
    @DisplayName("Should generate a Finding when H2 console is enabled regardless of the profile (Zero-Trust)")
    void shouldGenerateFindingRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of(ENABLED, "true"));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }
}
