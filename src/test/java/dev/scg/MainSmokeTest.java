package dev.scg;

import dev.scg.cli.ExitCodeResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class MainSmokeTest {

    @Test
    @DisplayName("Should execute E2E analysis validating multi-documents, inheritance/overriding, and mixing YAML with Properties")
    void shouldRunE2EAnalysisWithComplexProfileScenarios(@TempDir Path tempDir) throws Exception {
        // 1. Arrange: Base YAML containing multi-document (---) with a safe dev profile
        Path appYaml = tempDir.resolve("application.yml");
        String appYamlContent = """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "*"
                ---
                spring:
                  config:
                    activate:
                      on-profile: dev
                  h2:
                    console:
                      enabled: true
                """;
        Files.writeString(appYaml, appYamlContent);

        // 2. Arrange: Prod YAML overriding/fixing the inherited Actuator and enabling risky H2
        Path appProdYaml = tempDir.resolve("application-prod.yml");
        String appProdYamlContent = """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "health,metrics"
                spring:
                  h2:
                    console:
                      enabled: true
                      settings:
                        web-allow-others: true
                """;
        Files.writeString(appProdYaml, appProdYamlContent);

        // 3. Arrange: Classic .properties file for the QA profile
        Path appQaProps = tempDir.resolve("application-qa.properties");
        String appQaPropsContent = """
                spring.h2.console.enabled=true
                """;
        Files.writeString(appQaProps, appQaPropsContent);

        // Capture console output
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;

        int exitCode;
        try {
            System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));

            // Act: Execute the CLI
            exitCode = Main.run(new String[]{tempDir.toString()});
        } finally {
            System.setOut(originalOut);
        }

        String output = outContent.toString(StandardCharsets.UTF_8);

        // Assert: Result validations
        assertEquals(ExitCodeResolver.THRESHOLD_EXCEEDED, exitCode, "Should fail due to HIGH violations");

        // Rule SCG001 - Actuator: base, qa, and dev inherit include="*" from the base without
        // their own redefinition (only prod overrides it to "health,metrics"). Deliberate
        // decision (session on 08/21/2026): ActuatorExposureRule does not exempt safe
        // profiles, unlike H2ConsoleExposedRule — the nature of the leak (real secrets)
        // and the risk of shared credentials between dev/staging justify keeping it
        // restricted at all times.
        assertTrue(output.contains("SCG001"), "Should report Actuator violation");
        long scg001Count = output.lines().filter(line -> line.contains("SCG001")).count();
        assertEquals(3, scg001Count, "SCG001 should appear in base, qa, and dev (all inherit include=* without redefining it); prod is the only one that fixes the property");

        boolean devHasActuatorViolation = output.lines()
                .anyMatch(line -> line.contains("SCG001") && line.contains("[profile: dev]"));
        assertTrue(devHasActuatorViolation, "Actuator should be flagged even in dev — deliberate decision not to exempt by profile");

        boolean qaHasActuatorViolation = output.lines()
                .anyMatch(line -> line.contains("SCG001") && line.contains("[profile: qa]"));
        assertTrue(qaHasActuatorViolation, "Actuator inherited from the base should also be flagged in qa");

        // Rule SCG002 - H2 Console in PROD (with aggravating factor) and in QA (without aggravating factor)
        assertTrue(output.contains("SCG002"), "Should report H2 Console violation");
        assertTrue(output.contains("[profile: prod]"), "Should report H2 in prod");
        assertTrue(output.contains("[profile: qa]"), "Should report H2 in qa");
        assertTrue(
                output.contains("AGGRAVATING FACTOR: spring.h2.console.settings.web-allow-others=true"),
                "Should indicate the RCE aggravating factor in prod"
        );
        // Ensures that the DEV profile (defined via the multi-document ---) remains
        // exempt from H2 (SafeProfileClassifier), even though it is no longer exempt
        // from Actuator — the two rules have different profile policies by design.
        boolean devHasH2Violation = output.lines()
                .anyMatch(line -> line.contains("SCG002") && line.contains("[profile: dev]"));
        assertFalse(devHasH2Violation, "The dev profile should remain exempt from H2 console (H2-specific rule), but not from Actuator");
        // Expected total number of violations:
        // SCG001: base + qa + dev = 3
        // SCG002: prod (with aggravating factor) + qa (without aggravating factor) = 2
        // Total = 5 HIGH violations

        boolean prodHasActuatorViolation = output.lines()
                .anyMatch(line -> line.contains("SCG001") && line.contains("[profile: prod]"));
        assertFalse(prodHasActuatorViolation, "The prod profile redefined the property and should NOT have an Actuator violation");

        assertTrue(output.contains("Summary: 5 violation(s) — HIGH: 5, MEDIUM: 0, LOW: 0"),
                "The summary should account for exactly 5 HIGH violations");
    }
}

