package dev.scg;

import dev.scg.cli.ExitCodeResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HelpFlagTest {

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
    @DisplayName("Should print help and exit SUCCESS for --help")
    void shouldPrintHelpForLongFlag() {
        String output = runAndCaptureStdout(new String[]{"--help"}, ExitCodeResolver.SUCCESS);

        assertTrue(output.contains("Usage: spring-config-guard"));
        assertTrue(output.contains("--policy"));
        assertTrue(output.contains("--fail-on"));
    }

    @Test
    @DisplayName("Should print help and exit SUCCESS for -h")
    void shouldPrintHelpForShortFlag() {
        String output = runAndCaptureStdout(new String[]{"-h"}, ExitCodeResolver.SUCCESS);

        assertTrue(output.contains("Usage: spring-config-guard"));
    }

    @Test
    @DisplayName("Should print help even when combined with other arguments, without validating them")
    void shouldPrintHelpEvenWithOtherArgumentsPresent() {
        // "/does/not/exist" would normally fail directory validation -- --help must short-circuit
        // before that check runs, not just be silently ignored as an "unknown argument".
        String output = runAndCaptureStdout(new String[]{"/does/not/exist", "--help"}, ExitCodeResolver.SUCCESS);

        assertTrue(output.contains("Usage: spring-config-guard"));
    }
}
