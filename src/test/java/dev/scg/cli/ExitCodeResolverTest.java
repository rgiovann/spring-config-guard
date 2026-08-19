package dev.scg.cli;

import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ExitCodeResolverTest {

    private final ExitCodeResolver resolver = new ExitCodeResolver();

    private Finding findingWith(Severity severity) {
        return new Finding("SCGxxx", severity, "mensagem de teste", "application.yml", "prod");
    }

    @Test
    void deveRetornarSuccessQuandoListaDeFindingsVazia() {
        int exitCode = resolver.resolve(List.of(), Optional.of(Severity.HIGH));

        assertThat(exitCode).isEqualTo(ExitCodeResolver.SUCCESS);
    }

    @Test
    void deveRetornarSuccessQuandoFailOnSeverityForOptionalEmpty() {
        List<Finding> findings = List.of(findingWith(Severity.HIGH), findingWith(Severity.LOW));

        int exitCode = resolver.resolve(findings, Optional.empty());

        assertThat(exitCode).isEqualTo(ExitCodeResolver.SUCCESS);
    }

    @Test
    void deveRetornarThresholdExceededQuandoExisteFindingNoThresholdExato() {
        List<Finding> findings = List.of(findingWith(Severity.HIGH));

        int exitCode = resolver.resolve(findings, Optional.of(Severity.HIGH));

        assertThat(exitCode).isEqualTo(ExitCodeResolver.THRESHOLD_EXCEEDED);
    }

    @Test
    void deveRetornarSuccessQuandoFindingsSaoMaisBrandosQueOThreshold() {
        List<Finding> findings = List.of(findingWith(Severity.LOW));

        int exitCode = resolver.resolve(findings, Optional.of(Severity.HIGH));

        assertThat(exitCode).isEqualTo(ExitCodeResolver.SUCCESS);
    }

    @Test
    void deveRetornarThresholdExceededQuandoThresholdLowEExisteQualquerFinding() {
        for (Severity severity : Severity.values()) {
            List<Finding> findings = List.of(findingWith(severity));

            assertThat(resolver.resolve(findings, Optional.of(Severity.LOW)))
                    .as("severidade testada: %s", severity)
                    .isEqualTo(ExitCodeResolver.THRESHOLD_EXCEEDED);
        }
    }
}