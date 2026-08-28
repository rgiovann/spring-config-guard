package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class EnvironmentPlaceholderTest {

    @Test
    @DisplayName("Valor nulo deve retornar Optional.empty()")
    void valorNullDeveRetornarEmpty() {
        assertTrue(EnvironmentPlaceholder.resolve(null).isEmpty());
    }

    @Test
    @DisplayName("String sem sintaxe de placeholder deve ser retornada intacta")
    void stringSemPlaceholderDeveRetornarIntacta() {
        Optional<String> result = EnvironmentPlaceholder.resolve("true");
        assertTrue(result.isPresent());
        assertEquals("true", result.get());
    }

    @Test
    @DisplayName("Placeholder com valor default simples deve extrair o fallback")
    void placeholderComDefaultSimplesDeveExtrairFallback() {
        Optional<String> result = EnvironmentPlaceholder.resolve("${ENABLE_H2:false}");
        assertTrue(result.isPresent());
        assertEquals("false", result.get());
    }

    @Test
    @DisplayName("Placeholder com valor default contendo caractere wildcard deve extrair fallback corretamente")
    void placeholderComDefaultWildcardDeveExtrairFallback() {
        Optional<String> result = EnvironmentPlaceholder.resolve("${ACTUATOR_EXPOSURE:*}");
        assertTrue(result.isPresent());
        assertEquals("*", result.get());
    }

    @Test
    @DisplayName("Placeholder sem valor default deve retornar Optional.empty() para evitar falso positivo")
    void placeholderSemDefaultDeveRetornarEmpty() {
        Optional<String> result = EnvironmentPlaceholder.resolve("${ENABLE_H2}");
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("Múltiplos placeholders na mesma string devem ter seus fallbacks substituídos")
    void multiplosPlaceholdersNaMesmaStringDevemSerSubstituidos() {
        Optional<String> result = EnvironmentPlaceholder.resolve("host-${ENV:dev}-port-${PORT:8080}");
        assertTrue(result.isPresent());
        assertEquals("host-dev-port-8080", result.get());
    }

    @Test
    @DisplayName("Se um dos múltiplos placeholders não possuir fallback, a resolução total deve falhar")
    void seUmPlaceholderNaoTiverDefaultDeveRetornarEmpty() {
        Optional<String> result = EnvironmentPlaceholder.resolve("host-${ENV:dev}-port-${PORT}");
        assertTrue(result.isEmpty());
    }

}