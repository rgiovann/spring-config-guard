package dev.scg.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RuleRegistryTest {

    @Test
    void deveDescobrirTodasAsRegrasRegistradasViaServiceLoader() {
        List<String> ids = RuleRegistry.discoverRules().stream()
                .map(Rule::id)
                .toList();

        assertThat(ids).contains("SCG001", "SCG002");
    }

    @Test
    void deveOrdenarRegrasDeterministicamentePorId() {
        List<String> ids = RuleRegistry.discoverRules().stream()
                .map(Rule::id)
                .toList();

        assertThat(ids).isSorted();
    }

    @Test
    void deveRetornarListaImutavel() {
        assertThat(RuleRegistry.discoverRules()).isUnmodifiable();
    }
}