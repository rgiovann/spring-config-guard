package dev.scg.cli;

import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CliArgumentParserTest {

    private final CliArgumentParser parser = new CliArgumentParser();

    @Test
    @DisplayName("Should extract directory as a positional argument")
    void shouldExtractDirectoryAsPositionalArgument() {
        CliOptions options = parser.parse(new String[]{"/tmp/config"});

        assertThat(options.directory()).isEqualTo(Path.of("/tmp/config"));
    }

    @Test
    @DisplayName("Should use HIGH as the default fail-on severity when the flag is omitted")
    void shouldUseHighAsDefaultFailOnWhenFlagIsOmitted() {
        CliOptions options = parser.parse(new String[]{"/tmp/config"});

        assertThat(options.failOnSeverity()).contains(Severity.HIGH);
    }

    @Test
    @DisplayName("Should recognize the JSON flag in any position")
    void shouldRecognizeJsonFlagInAnyPosition() {
        CliOptions options = parser.parse(new String[]{"/tmp/config", "--json", "--fail-on=LOW"});

        assertThat(options.jsonOutput()).isTrue();
    }

    @Test
    @DisplayName("Should accept fail-on case-insensitively")
    void shouldAcceptFailOnCaseInsensitive() {
        CliOptions options = parser.parse(new String[]{"/tmp/config", "--fail-on=medium"});

        assertThat(options.failOnSeverity()).contains(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should map fail-on NONE to an empty Optional")
    void shouldMapFailOnNoneToEmptyOptional() {
        CliOptions options = parser.parse(new String[]{"/tmp/config", "--fail-on=NONE"});

        assertThat(options.failOnSeverity()).isEmpty();
    }

    @Test
    @DisplayName("Should throw CliUsageException when arguments are empty")
    void shouldThrowCliUsageExceptionWhenArgsAreEmpty() {
        assertThatThrownBy(() -> parser.parse(new String[]{}))
                .isInstanceOf(CliUsageException.class)
                .hasMessageContaining("Usage:");
    }

    @Test
    @DisplayName("Should throw CliUsageException for an unknown flag")
    void shouldThrowCliUsageExceptionForUnknownFlag() {
        assertThatThrownBy(() -> parser.parse(new String[]{"/tmp/config", "--verbose"}))
                .isInstanceOf(CliUsageException.class)
                .hasMessageContaining("--verbose");
    }

    @Test
    @DisplayName("Should throw CliUsageException for an invalid fail-on value")
    void shouldThrowCliUsageExceptionForInvalidFailOnValue() {
        assertThatThrownBy(() -> parser.parse(new String[]{"/tmp/config", "--fail-on=CRITICAL"}))
                .isInstanceOf(CliUsageException.class)
                .hasMessageContaining("CRITICAL");
    }
}