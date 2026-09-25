package dev.scg;

import dev.scg.cli.ExitCodeResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the --version short-circuit in Main. Unit tests run from target/classes, where Maven's
 * pom.properties doesn't exist yet, so the version itself is always unknown here; the release
 * workflow checks the real version on the packaged jar.
 */
class VersionFlagTest {

    private String runAndCaptureStdout(String[] args, int expectedExitCode) {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;

        int exitCode;
        try {
            System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));
            exitCode = Main.run(args);
        } finally {
            System.setOut(originalOut);
        }

        assertEquals(expectedExitCode, exitCode);
        return outContent.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("Should print the version line and exit SUCCESS for --version")
    void shouldPrintVersionAndExitSuccess() {
        String output = runAndCaptureStdout(new String[]{"--version"}, ExitCodeResolver.SUCCESS);

        assertEquals("spring-config-guard (version unknown: not running from a packaged jar)", output.strip());
    }

    @Test
    @DisplayName("Should print the version even when combined with other arguments, without validating them")
    void shouldPrintVersionEvenWithOtherArgumentsPresent() {
        // "/does/not/exist" would normally fail directory validation -- --version must short-circuit
        // before that check runs, the same way --help does.
        String output = runAndCaptureStdout(new String[]{"/does/not/exist", "--version"}, ExitCodeResolver.SUCCESS);

        assertTrue(output.startsWith("spring-config-guard "));
    }

    @Test
    @DisplayName("Should let --help win when both --help and --version are given")
    void shouldLetHelpWinOverVersion() {
        String output = runAndCaptureStdout(new String[]{"--version", "--help"}, ExitCodeResolver.SUCCESS);

        assertTrue(output.contains("Usage: spring-config-guard"));
    }

    @Test
    @DisplayName("Should list --version in the help text")
    void shouldListVersionInHelpText() {
        String output = runAndCaptureStdout(new String[]{"--help"}, ExitCodeResolver.SUCCESS);

        assertTrue(output.contains("--version"));
    }
}
