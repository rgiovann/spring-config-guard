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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Main's side of evaluating on-profile as Spring Boot does (ARCHITECTURE.md, ADR-012): the stderr
 * warning for documents only a combination of profiles activates, and a malformed on-profile as
 * an input error.
 */
class ProfileCombinationWarningTest {

    private static final String WARNING =
            "spring-config-guard: 1 document(s) apply only when several profiles are active together, which is not evaluated.";

    @Test
    @DisplayName("Warns once for a document only 'a & b' activates")
    void warnsForADocumentOnlyACombinationActivates(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("application.yml"), """
                server.port: 8080
                ---
                spring.config.activate.on-profile: 'a & b'
                spring.h2.console.enabled: true
                """);

        Run run = run(dir.toString());

        assertThat(run.exitCode).isEqualTo(ExitCodeResolver.SUCCESS);
        assertThat(run.err).contains(WARNING);
    }

    @Test
    @DisplayName("Counts a Global document once in Config Server Mode, though every service inherits it")
    void countsAGlobalDocumentOnceInConfigServerMode(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("application.yml"), """
                server.port: 8080
                ---
                spring.config.activate.on-profile: 'a & b'
                spring.h2.console.enabled: true
                """);
        Files.writeString(dir.resolve("customers-service.yml"), "server.port: 8081");
        Files.writeString(dir.resolve("vets-service.yml"), "server.port: 8082");

        Run run = run(dir.toString(), "--config-server");

        assertThat(run.err).contains(WARNING);
    }

    @Test
    @DisplayName("No warning when every conditioned document applies to some configuration")
    void noWarningWhenEveryDocumentIsEvaluated(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("application.yml"), """
                server.port: 8080
                ---
                spring.config.activate.on-profile: '!a'
                server.port: 8081
                """);

        assertThat(run(dir.toString()).err).doesNotContain("several profiles");
    }

    @Test
    @DisplayName("A malformed on-profile is an input error: exit code 2, naming the file")
    void malformedOnProfileIsAnInputError(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("application.yml"), """
                spring.config.activate.on-profile: 'a & b | c'
                server.port: 8080
                """);

        Run run = run(dir.toString());

        assertThat(run.exitCode).isEqualTo(ExitCodeResolver.USAGE_ERROR);
        assertThat(run.err)
                .contains("Error reading configuration: Invalid spring.config.activate.on-profile in '")
                .contains("application.yml")
                .contains("Malformed profile expression [a & b | c]");
    }

    private record Run(int exitCode, String err) {
    }

    private static Run run(String... args) {
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        int exitCode;
        try {
            System.setOut(new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(errContent, true, StandardCharsets.UTF_8));
            exitCode = Main.run(args);
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
        return new Run(exitCode, errContent.toString(StandardCharsets.UTF_8));
    }
}
