package dev.scg;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.scg.cli.ExitCodeResolver;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs the built pipeline against the committed demo-project showcase fixtures and pins the exact
 * findings they're documented to produce (see BACKLOG.md / README references to these fixtures).
 * Without this, the fixtures are just static YAML/properties files that could silently drift out of
 * sync with rule behavior as rules evolve -- this test is what keeps them honest.
 */
class DemoProjectShowcaseTest {

    private static final String MULTI_PROFILE_DIR = "demo-project/multi-profile-showcase";
    private static final String PROPERTIES_DIR = "demo-project/properties-format-showcase";
    private static final String POLICY_FILE = MULTI_PROFILE_DIR + "/policy-demo.yml";
    private static final String CLEAN_PROPERTIES_DIR = "demo-project-clean/properties-format-showcase";

    @Test
    @DisplayName("multi-profile-showcase reports the 11 expected findings across base/dev/prod")
    void shouldReportExpectedFindingsAcrossProfiles() {
        String output = run(new String[]{MULTI_PROFILE_DIR, "--fail-on=NONE"});

        assertTrue(output.contains("Summary: 11 violation(s)"));

        assertTrue(hasFinding(output, "SCG001", "[base]"));
        assertTrue(hasFinding(output, "SCG006", "[base]"));

        assertTrue(hasFinding(output, "SCG001", "[profile: dev]"));
        assertTrue(hasFinding(output, "SCG006", "[profile: dev]"));
        assertTrue(hasFinding(output, "SCG012", "[profile: dev]"));
        assertTrue(hasFinding(output, "SCG011", "[profile: dev]"));

        assertTrue(hasFinding(output, "SCG001", "[profile: prod]"));
        assertTrue(hasFinding(output, "SCG003", "[profile: prod]"));
        assertTrue(hasFinding(output, "SCG006", "[profile: prod]"));
        assertTrue(hasFinding(output, "SCG012", "[profile: prod]"));
        assertTrue(hasFinding(output, "SCG017", "[profile: prod]"));

        assertEquals(10, output.lines().filter(l -> l.startsWith("[HIGH]")).count());
        assertEquals(1, output.lines().filter(l -> l.startsWith("[MEDIUM]")).count());
    }

    @Test
    @DisplayName("policy-demo.yml suppresses only SCG012 in dev, leaving SCG012 in prod and everything else untouched")
    void shouldSuppressOnlyConfiguredEntryViaPolicy() {
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream originalErr = System.err;
        String output;
        try {
            System.setErr(new PrintStream(errContent, true, StandardCharsets.UTF_8));
            output = run(new String[]{MULTI_PROFILE_DIR, "--policy=" + POLICY_FILE, "--fail-on=NONE"});
        } finally {
            System.setErr(originalErr);
        }

        assertTrue(output.contains("Summary: 10 violation(s)"));
        assertFalse(hasFinding(output, "SCG012", "[profile: dev]"),
                "SCG012 in dev should be suppressed by the policy");
        assertTrue(hasFinding(output, "SCG012", "[profile: prod]"),
                "SCG012 in prod must remain -- suppression is scoped to dev only, not the whole rule");

        assertTrue(errContent.toString(StandardCharsets.UTF_8).contains("1 finding(s) suppressed by policy"));
    }

    @Test
    @DisplayName("properties-format-showcase reports SCG002 (HIGH), SCG006 (HIGH), and SCG006 (INFO) on profile test")
    void shouldReportExpectedFindingsInPropertiesFormat() {
        String output = run(new String[]{PROPERTIES_DIR, "--fail-on=NONE"});

        assertTrue(output.contains("Summary: 3 violation(s)"));
        assertTrue(output.lines().anyMatch(l -> l.startsWith("[HIGH] SCG002") && l.contains("[profile: test]")));
        assertTrue(output.lines().anyMatch(l -> l.startsWith("[HIGH] SCG006") && l.contains("[profile: test]")));
        assertTrue(output.lines().anyMatch(l -> l.startsWith("[INFO] SCG006") && l.contains("[profile: test]")));
    }

    @Test
    @DisplayName("clean properties-format-showcase counterpart reports only 2 INFO findings and never fails the build")
    void shouldReportOnlyInfoFindingsForCleanPropertiesCounterpart() {
        String output = run(new String[]{CLEAN_PROPERTIES_DIR, "--fail-on=NONE"});

        assertTrue(output.contains("Summary: 2 violation(s)"));
        assertEquals(0, output.lines().filter(l -> l.startsWith("[HIGH]") || l.startsWith("[MEDIUM]") || l.startsWith("[LOW]")).count());
        assertEquals(2, output.lines().filter(l -> l.startsWith("[INFO] SCG006")).count());

        // Confirms INFO alone never fails the build, even under the CLI's own default --fail-on=HIGH.
        assertEquals(ExitCodeResolver.SUCCESS, runReturningExitCode(new String[]{CLEAN_PROPERTIES_DIR}));
    }

    @Test
    @DisplayName("--fail-on=LOW still succeeds against the clean fixture -- INFO is excluded at every threshold, not just the default HIGH")
    void shouldSucceedAtLowestFailOnThresholdForCleanFixture() {
        assertEquals(ExitCodeResolver.SUCCESS,
                runReturningExitCode(new String[]{CLEAN_PROPERTIES_DIR, "--fail-on=LOW"}));
    }

    @Test
    @DisplayName("--json produces valid, parseable JSON end-to-end through Main, with the expected findings")
    void shouldProduceValidJsonOutputEndToEnd() throws Exception {
        String output = run(new String[]{PROPERTIES_DIR, "--json", "--fail-on=NONE"});

        List<Finding> findings = new ObjectMapper().readValue(output, new TypeReference<>() {});

        assertEquals(3, findings.size());
        assertTrue(findings.stream().allMatch(f -> "test".equals(f.profileLabel())));
        assertTrue(findings.stream().anyMatch(f -> "SCG002".equals(f.ruleId()) && f.severity() == Severity.HIGH));
        assertTrue(findings.stream().anyMatch(f -> "SCG006".equals(f.ruleId()) && f.severity() == Severity.HIGH));
        assertTrue(findings.stream().anyMatch(f -> "SCG006".equals(f.ruleId()) && f.severity() == Severity.INFO));
    }

    private static boolean hasFinding(String output, String ruleId, String profileMarker) {
        return output.lines().anyMatch(l -> l.contains(ruleId) && l.contains(profileMarker));
    }

    private static String run(String[] args) {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        try {
            System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));
            Main.run(args);
        } finally {
            System.setOut(originalOut);
        }
        return outContent.toString(StandardCharsets.UTF_8);
    }

    private static int runReturningExitCode(String[] args) {
        ByteArrayOutputStream discarded = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        try {
            System.setOut(new PrintStream(discarded, true, StandardCharsets.UTF_8));
            return Main.run(args);
        } finally {
            System.setOut(originalOut);
        }
    }
}
