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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainSmokeTest {

    @Test
    @DisplayName("Should execute E2E analysis validating multi-documents, inheritance/overriding, and mixing YAML with Properties under Zero-Trust policy")
    void shouldRunE2EAnalysisWithComplexProfileScenarios(@TempDir Path tempDir) throws Exception {
        // 1. Arrange: Base YAML containing multi-document (---) with a dev profile
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

        // Rule SCG001 - Actuator Exposure (Zero-Trust)
        assertTrue(output.contains("SCG001"), "Should report Actuator violation");
        long scg001Count = output.lines().filter(line -> line.contains("SCG001")).count();
        assertEquals(3, scg001Count, "SCG001 should appear in base, qa, and dev (all inherit include=* without redefining it)");

        boolean devHasActuatorViolation = output.lines()
                .anyMatch(line -> line.contains("SCG001") && line.contains("[profile: dev]"));
        assertTrue(devHasActuatorViolation, "Actuator should be flagged in dev under Zero-Trust policy");

        boolean qaHasActuatorViolation = output.lines()
                .anyMatch(line -> line.contains("SCG001") && line.contains("[profile: qa]"));
        assertTrue(qaHasActuatorViolation, "Actuator inherited from the base should also be flagged in qa");

        boolean prodHasActuatorViolation = output.lines()
                .anyMatch(line -> line.contains("SCG001") && line.contains("[profile: prod]"));
        assertFalse(prodHasActuatorViolation, "The prod profile redefined the property and should NOT have an Actuator violation");

        // Rule SCG002 - H2 Console (Zero-Trust)
        assertTrue(output.contains("SCG002"), "Should report H2 Console violation");
        assertTrue(output.contains("[profile: prod]"), "Should report H2 in prod");
        assertTrue(output.contains("[profile: qa]"), "Should report H2 in qa");
        assertTrue(
                output.contains("AGGRAVATING FACTOR: spring.h2.console.settings.web-allow-others=true"),
                "Should indicate the RCE aggravating factor in prod"
        );

        boolean devHasH2Violation = output.lines()
                .anyMatch(line -> line.contains("SCG002") && line.contains("[profile: dev]"));
        assertTrue(devHasH2Violation, "Under Zero-Trust policy, H2 Console enabled in committed dev configs must be flagged");

        // Expected total number of violations:
        // SCG001: base + qa + dev = 3
        // SCG002: prod + qa + dev = 3
        // Total = 6 HIGH violations
        assertTrue(output.contains("Summary: 6 violation(s) — HIGH: 6, MEDIUM: 0, LOW: 0"),
                "The summary should account for exactly 6 HIGH violations");
    }
}