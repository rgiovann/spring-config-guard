package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


class RuleRegistryTest {

    @Test
    @DisplayName("Should discover all rules registered via ServiceLoader")
    void shouldDiscoverAllRulesRegisteredViaServiceLoader() {
        List<String> ids = RuleRegistry.discoverRules().stream()
                .map(Rule::id)
                .toList();

        assertThat(ids).contains("SCG001", "SCG002","SCG003");
    }

    @Test
    @DisplayName("Should sort rules deterministically by ID")
    void shouldSortRulesDeterministicallyById() {
        List<String> ids = RuleRegistry.discoverRules().stream()
                .map(Rule::id)
                .toList();

        assertThat(ids).isSorted();
    }

    @Test
    @DisplayName("Should return an immutable list")
    void shouldReturnImmutableList() {
        assertThat(RuleRegistry.discoverRules()).isUnmodifiable();
    }
}

