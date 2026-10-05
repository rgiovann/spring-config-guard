package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Row IDs (D1, C2, G4, S3, ...) are the rows of VALIDATION.md, "SCG013 health details scenarios",
 * measured in spring-env-benchmark/health-details and health-details-secured.
 */
class HealthDetailsExposureRuleTest {

    private final HealthDetailsExposureRule rule = new HealthDetailsExposureRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");
    private static final String KEY = "management.endpoint.health.show-details";
    private static final String COMPONENTS = "management.endpoint.health.show-components";
    private static final String GROUP = "management.endpoint.health.group.custom";

    private List<Finding> check(Map<String, String> properties) {
        return rule.check(new EffectiveConfig(FAKE_PATH, "prod", properties));
    }

    @Test
    @DisplayName("D0, D5, S0: silent when show-details is absent or never")
    void silentWhenAbsentOrNever() {
        assertThat(check(Map.of())).isEmpty();
        assertThat(check(Map.of(KEY, "never"))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"always", "ALWAYS", "Always", "${SHOW_DETAILS:always}"})
    @DisplayName("D1, D7, S1: show-details=always is MEDIUM: any caller got the details")
    void alwaysIsMedium(String value) {
        List<Finding> findings = check(Map.of(KEY, value));

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG013");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains(KEY + "=" + value).contains("to any caller").contains("/actuator/health");
    }

    @ParameterizedTest
    @ValueSource(strings = {"when-authorized", "WHEN-AUTHORIZED", "when_authorized", "WHEN_AUTHORIZED", "whenAuthorized",
            "WHENAUTHORIZED", "when.authorized", "when authorized"})
    @DisplayName("D2-D4, S2: show-details=when-authorized, in any spelling Spring binds, is INFO: only authenticated users got the details")
    void whenAuthorizedIsInfo(String value) {
        List<Finding> findings = check(Map.of(KEY, value));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("authenticated users").contains("anonymous callers get the status only");
    }

    @Test
    @DisplayName("S3: when-authorized with roles names the roles")
    void whenAuthorizedNamesRoles() {
        List<Finding> findings = check(Map.of(KEY, "when-authorized", "management.endpoint.health.roles", "ADMIN"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("with one of the roles 'ADMIN'");
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "sometimes", "", "   ", "${SOME_VAR:}", "${SHOW_DETAILS:never}"})
    @DisplayName("D6: silent for values Spring can't bind (the app doesn't start), blank values and never via a default")
    void silentForUnbindableOrBlank(String value) {
        assertThat(check(Map.of(KEY, value))).isEmpty();
    }

    @Test
    @DisplayName("an unresolved placeholder is INFO")
    void unresolvedIsInfo() {
        List<Finding> findings = check(Map.of(KEY, "${SHOW_DETAILS}"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("unresolved environment placeholder '${SHOW_DETAILS}'");
    }

    @Test
    @DisplayName("C1: show-components=always alone is INFO: names and status without details")
    void showComponentsAloneIsInfo() {
        List<Finding> findings = check(Map.of(COMPONENTS, "always"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("names and status of its components").contains("any caller");
    }

    @Test
    @DisplayName("S4: show-components=when-authorized alone is INFO, for authenticated users")
    void showComponentsWhenAuthorizedIsInfo() {
        List<Finding> findings = check(Map.of(COMPONENTS, "when-authorized"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("to authenticated users");
    }

    @Test
    @DisplayName("C2: show-components=never hides the details, so show-details=always is silent")
    void showComponentsNeverHidesDetails() {
        assertThat(check(Map.of(KEY, "always", COMPONENTS, "never"))).isEmpty();
    }

    @Test
    @DisplayName("the lower of the two decides: always details with when-authorized components is INFO")
    void lowerOfTheTwoDecides() {
        List<Finding> findings = check(Map.of(KEY, "always", COMPONENTS, "when-authorized"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("G1, G2: a group with show-details=always is MEDIUM, named with its path; the endpoint itself is silent")
    void groupAlwaysIsMedium() {
        List<Finding> findings = check(Map.of(GROUP + ".include", "db", GROUP + ".show-details", "always"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("Health group 'custom' (/actuator/health/custom)");
    }

    @Test
    @DisplayName("G3: a group with show-components=always alone is INFO")
    void groupComponentsIsInfo() {
        List<Finding> findings = check(Map.of(GROUP + ".include", "db", GROUP + ".show-components", "always"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("G4: the message names the group's additional-path, which can be on the main server port")
    void groupNamesAdditionalPath() {
        List<Finding> findings = check(Map.of(
                GROUP + ".include", "db",
                GROUP + ".show-details", "always",
                GROUP + ".additional-path", "server:/healthz"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("and server:/healthz");
    }

    @Test
    @DisplayName("S5: a group with show-details=when-authorized is INFO")
    void groupWhenAuthorizedIsInfo() {
        List<Finding> findings = check(Map.of(GROUP + ".include", "db", GROUP + ".show-details", "when-authorized"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("G5: a group that sets neither key inherits the endpoint's, and isn't reported again for it")
    void groupWithoutItsOwnKeysIsNotReported() {
        List<Finding> findings = check(Map.of(KEY, "always", GROUP + ".include", "db"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).startsWith("The health endpoint");
    }

    @Test
    @DisplayName("G6: a group's show-components=never hides the details the endpoint's show-details would give it")
    void groupInheritsAndOverrides() {
        List<Finding> findings = check(Map.of(KEY, "always", GROUP + ".show-components", "never"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).startsWith("The health endpoint");
    }

    @Test
    @DisplayName("groups are reported in a stable order, each with its own finding, whatever the input order")
    void groupsInStableOrder() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put("management.endpoint.health.group.zeta.show-details", "always");
        properties.put("management.endpoint.health.group.alpha.show-details", "always");
        List<Finding> findings = check(properties);

        assertThat(findings).extracting(Finding::message)
                .satisfiesExactly(
                        first -> assertThat(first).contains("'alpha'"),
                        second -> assertThat(second).contains("'zeta'"));
    }

    @Test
    @DisplayName("G7: a group's empty show-details falls back to the endpoint's, like an unset one")
    void groupEmptyValueInherits() {
        List<Finding> findings = check(Map.of(
                KEY, "always",
                GROUP + ".show-details", "",
                GROUP + ".show-components", "${UNSET:}"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).startsWith("The health endpoint");
    }

    @Test
    @DisplayName("a group name with a dot, as ConfigLoader writes group[a.b], stays whole")
    void groupNameWithDot() {
        List<Finding> findings = check(Map.of("management.endpoint.health.group.a.b.show-details", "always"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("Health group 'a.b' (/actuator/health/a.b)");
    }

    @Test
    @DisplayName("roles written as a list are all named")
    void rolesAsList() {
        List<Finding> findings = check(Map.of(
                KEY, "when-authorized",
                "management.endpoint.health.roles[0]", "ADMIN",
                "management.endpoint.health.roles[1]", "OPS"));

        assertThat(findings.getFirst().message()).contains("with one of the roles 'ADMIN,OPS'");
    }

    @Test
    @DisplayName("an unresolved show-details next to show-components=never is silent: never hides the details whatever it resolves to")
    void unresolvedDetailsUnderComponentsNeverIsSilent() {
        assertThat(check(Map.of(KEY, "${SHOW_DETAILS}", COMPONENTS, "never"))).isEmpty();
    }

    @Test
    @DisplayName("a group doesn't repeat the endpoint's unresolved placeholder")
    void groupDoesNotRepeatInheritedPlaceholder() {
        List<Finding> findings = check(Map.of(KEY, "${SHOW_DETAILS}", GROUP + ".show-components", "always"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).startsWith("The health endpoint").contains("${SHOW_DETAILS}");
    }

    @Test
    @DisplayName("X1, X2: still MEDIUM when the endpoint is turned off (documented scope decision)")
    void restrictionIsNotChecked() {
        assertThat(check(Map.of(KEY, "always", "management.endpoint.health.access", "none"))).hasSize(1);
        assertThat(check(Map.of(KEY, "always", "management.endpoints.web.exposure.exclude", "health"))).hasSize(1);
    }

    @Test
    @DisplayName("Should respect relaxed binding case-folding across segments")
    void shouldSupportRelaxedBinding() {
        List<Finding> findings = check(Map.of(
                "MANAGEMENT.ENDPOINT.HEALTH.SHOW-DETAILS", "ALWAYS",
                "management.endpoint.health.group.custom.showDetails", "always"));

        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.severity() == Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should not throw and stay silent when the property value is null")
    void shouldNotThrowWhenPropertyIsNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put(KEY, null);
        properties.put(GROUP + ".show-details", null);

        assertThat(check(properties)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should report regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of(KEY, "always"));

        assertThat(rule.check(config)).hasSize(1);
    }
}
