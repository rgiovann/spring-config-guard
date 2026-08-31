package dev.scg.cli;

import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
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
    @DisplayName("Should return SUCCESS when the findings list is empty")
    void shouldReturnSuccessWhenFindingsListIsEmpty() {
        int exitCode = resolver.resolve(List.of(), Optional.of(Severity.HIGH));

        assertThat(exitCode).isEqualTo(ExitCodeResolver.SUCCESS);
    }

    @Test
    @DisplayName("Should return SUCCESS when fail-on severity is Optional.empty")
    void shouldReturnSuccessWhenFailOnSeverityIsOptionalEmpty() {
        List<Finding> findings = List.of(findingWith(Severity.HIGH), findingWith(Severity.LOW));

        int exitCode = resolver.resolve(findings, Optional.empty());

        assertThat(exitCode).isEqualTo(ExitCodeResolver.SUCCESS);
    }

    @Test
    @DisplayName("Should return THRESHOLD_EXCEEDED when a finding exists at the exact threshold")
    void shouldReturnThresholdExceededWhenFindingExistsAtExactThreshold() {
        List<Finding> findings = List.of(findingWith(Severity.HIGH));

        int exitCode = resolver.resolve(findings, Optional.of(Severity.HIGH));

        assertThat(exitCode).isEqualTo(ExitCodeResolver.THRESHOLD_EXCEEDED);
    }

    @Test
    @DisplayName("Should return SUCCESS when findings are less severe than the threshold")
    void shouldReturnSuccessWhenFindingsAreLessSevereThanThreshold() {
        List<Finding> findings = List.of(findingWith(Severity.LOW));

        int exitCode = resolver.resolve(findings, Optional.of(Severity.HIGH));

        assertThat(exitCode).isEqualTo(ExitCodeResolver.SUCCESS);
    }

    @Test
    @DisplayName("Should return THRESHOLD_EXCEEDED when the threshold is LOW and any actionable finding exists")
    void shouldReturnThresholdExceededWhenThresholdIsLowAndAnyActionableFindingExists() {
        List<Severity> actionableSeverities = List.of(Severity.HIGH, Severity.MEDIUM, Severity.LOW);

        for (Severity severity : actionableSeverities) {
            List<Finding> findings = List.of(findingWith(severity));

            assertThat(resolver.resolve(findings, Optional.of(Severity.LOW)))
                    .as("tested severity: %s", severity)
                    .isEqualTo(ExitCodeResolver.THRESHOLD_EXCEEDED);
        }
    }

    @Test
    @DisplayName("Should return SUCCESS when finding severity is INFO regardless of the fail-on threshold")
    void shouldReturnSuccessWhenFindingIsInfo() {
        List<Finding> findings = List.of(findingWith(Severity.INFO));

        assertThat(resolver.resolve(findings, Optional.of(Severity.LOW)))
                .isEqualTo(ExitCodeResolver.SUCCESS);
    }
}

