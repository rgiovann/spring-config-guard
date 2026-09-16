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

class PolicyIntegrationTest {

    @Test
    @DisplayName("Should suppress the configured rule+profile via --policy and report SUCCESS")
    void shouldSuppressConfiguredRuleAndProfile(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve("application.yml"), """
                server:
                  port: 8080
                """);
        Files.writeString(tempDir.resolve("application-dev.yml"), """
                spring:
                  h2:
                    console:
                      enabled: true
                """);

        Path policyFile = tempDir.resolve("scg-policy.yml");
        Files.writeString(policyFile, """
                SCG002:
                  - dev
                """);

        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;

        int exitCode;
        try {
            System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(errContent, true, StandardCharsets.UTF_8));

            exitCode = Main.run(new String[]{tempDir.toString(), "--policy=" + policyFile});
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }

        String output = outContent.toString(StandardCharsets.UTF_8);
        String errOutput = errContent.toString(StandardCharsets.UTF_8);

        assertFalse(output.contains("SCG002"), "SCG002 should be suppressed by policy for the dev profile");
        assertTrue(output.contains("no violations found"), "No findings should remain after suppression");
        assertEquals(ExitCodeResolver.SUCCESS, exitCode, "Suppressed finding must not count toward the exit code");
        assertTrue(errOutput.contains("1 finding(s) suppressed by policy"),
                "Should report the suppressed count for transparency");
    }

    @Test
    @DisplayName("Should exit with USAGE_ERROR when the policy file references an unknown rule ID")
    void shouldFailFastOnUnknownRuleIdInPolicy(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve("application.yml"), """
                server:
                  port: 8080
                """);

        Path policyFile = tempDir.resolve("scg-policy.yml");
        Files.writeString(policyFile, """
                SCG999:
                  - dev
                """);

        PrintStream originalErr = System.err;
        int exitCode;
        try {
            System.setErr(new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
            exitCode = Main.run(new String[]{tempDir.toString(), "--policy=" + policyFile});
        } finally {
            System.setErr(originalErr);
        }

        assertEquals(ExitCodeResolver.USAGE_ERROR, exitCode);
    }

    @Test
    @DisplayName("Should exit with USAGE_ERROR and a 'not found' message (not a raw IOException message) when the policy file does not exist")
    void shouldFailCleanlyWhenPolicyFileDoesNotExist(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve("application.yml"), """
                server:
                  port: 8080
                """);

        Path missingPolicyFile = tempDir.resolve("does-not-exist.yml");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream originalErr = System.err;
        int exitCode;
        try {
            System.setErr(new PrintStream(errContent, true, StandardCharsets.UTF_8));
            exitCode = Main.run(new String[]{tempDir.toString(), "--policy=" + missingPolicyFile});
        } finally {
            System.setErr(originalErr);
        }

        String errOutput = errContent.toString(StandardCharsets.UTF_8);

        assertEquals(ExitCodeResolver.USAGE_ERROR, exitCode);
        assertTrue(errOutput.contains("not found"),
                "Should explicitly say the policy file was not found, not just echo the IOException's bare path");
        assertFalse(errOutput.contains("\tat "),
                "Must not leak a raw stack trace to the user (no '\\tat ' frame lines)");
    }
}
