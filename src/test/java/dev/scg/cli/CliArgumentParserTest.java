package dev.scg.cli;

import dev.scg.core.Severity;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CliArgumentParserTest {

    private final CliArgumentParser parser = new CliArgumentParser();

    @Test
    void deveExtrairDiretorioComoArgumentoPosicional() {
        CliOptions options = parser.parse(new String[]{"/tmp/config"});

        assertThat(options.directory()).isEqualTo(Path.of("/tmp/config"));
    }

    @Test
    void deveUsarHighComoFailOnPadraoQuandoFlagOmitida() {
        CliOptions options = parser.parse(new String[]{"/tmp/config"});

        assertThat(options.failOnSeverity()).contains(Severity.HIGH);
    }

    @Test
    void deveReconhecerFlagJsonEmQualquerPosicao() {
        CliOptions options = parser.parse(new String[]{"/tmp/config", "--json", "--fail-on=LOW"});

        assertThat(options.jsonOutput()).isTrue();
    }

    @Test
    void deveAceitarFailOnCaseInsensitive() {
        CliOptions options = parser.parse(new String[]{"/tmp/config", "--fail-on=medium"});

        assertThat(options.failOnSeverity()).contains(Severity.MEDIUM);
    }

    @Test
    void deveMapearFailOnNoneParaOptionalVazio() {
        CliOptions options = parser.parse(new String[]{"/tmp/config", "--fail-on=NONE"});

        assertThat(options.failOnSeverity()).isEmpty();
    }

    @Test
    void deveLancarCliUsageExceptionQuandoArgsVazio() {
        assertThatThrownBy(() -> parser.parse(new String[]{}))
                .isInstanceOf(CliUsageException.class)
                .hasMessageContaining("Uso:");
    }

    @Test
    void deveLancarCliUsageExceptionParaFlagDesconhecida() {
        assertThatThrownBy(() -> parser.parse(new String[]{"/tmp/config", "--verbose"}))
                .isInstanceOf(CliUsageException.class)
                .hasMessageContaining("--verbose");
    }

    @Test
    void deveLancarCliUsageExceptionParaValorInvalidoDeFailOn() {
        assertThatThrownBy(() -> parser.parse(new String[]{"/tmp/config", "--fail-on=CRITICAL"}))
                .isInstanceOf(CliUsageException.class)
                .hasMessageContaining("CRITICAL");
    }
}