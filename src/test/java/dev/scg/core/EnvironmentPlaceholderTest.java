package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;


class EnvironmentPlaceholderTest {

    @Test
    @DisplayName("Null value should return Optional.empty()")
    void nullValueShouldReturnEmpty() {
        assertTrue(EnvironmentPlaceholder.resolve(null).isEmpty());
    }

    @Test
    @DisplayName("String without placeholder syntax should be returned unchanged")
    void stringWithoutPlaceholderShouldReturnUnchanged() {
        Optional<String> result = EnvironmentPlaceholder.resolve("true");
        assertTrue(result.isPresent());
        assertEquals("true", result.get());
    }

    @Test
    @DisplayName("Placeholder with a simple default value should extract the fallback")
    void placeholderWithSimpleDefaultShouldExtractFallback() {
        Optional<String> result = EnvironmentPlaceholder.resolve("${ENABLE_H2:false}");
        assertTrue(result.isPresent());
        assertEquals("false", result.get());
    }

    @Test
    @DisplayName("Placeholder with a default value containing a wildcard character should extract the fallback correctly")
    void placeholderWithWildcardDefaultShouldExtractFallback() {
        Optional<String> result = EnvironmentPlaceholder.resolve("${ACTUATOR_EXPOSURE:*}");
        assertTrue(result.isPresent());
        assertEquals("*", result.get());
    }

    @Test
    @DisplayName("Placeholder without a default value should return Optional.empty() to avoid false positives")
    void placeholderWithoutDefaultShouldReturnEmpty() {
        Optional<String> result = EnvironmentPlaceholder.resolve("${ENABLE_H2}");
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("Multiple placeholders in the same string should have their fallbacks substituted")
    void multiplePlaceholdersInSameStringShouldBeSubstituted() {
        Optional<String> result = EnvironmentPlaceholder.resolve("host-${ENV:dev}-port-${PORT:8080}");
        assertTrue(result.isPresent());
        assertEquals("host-dev-port-8080", result.get());
    }

    @Test
    @DisplayName("If one of the multiple placeholders has no fallback, the entire resolution should fail")
    void ifOnePlaceholderHasNoDefaultShouldReturnEmpty() {
        Optional<String> result = EnvironmentPlaceholder.resolve("host-${ENV:dev}-port-${PORT}");
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("Should resolve a nested placeholder using the innermost default")
    void shouldResolveNestedPlaceholderUsingTheInnermostDefault() {
        assertThat(EnvironmentPlaceholder.resolve("${OUTER:${INNER:default}}"))
                .contains("default");
    }

    @Test
    @DisplayName("Should return empty when the inner placeholder has no default")
    void shouldReturnEmptyWhenInnerPlaceholderHasNoDefault() {
        assertThat(EnvironmentPlaceholder.resolve("${OUTER:${INNER}}")).isEmpty();
    }

    @Test
    @DisplayName("Should resolve a nested placeholder mixed with literal text")
    void shouldResolveNestedPlaceholderMixedWithLiteralText() {
        assertThat(EnvironmentPlaceholder.resolve("prefix-${OUTER:${INNER:mid}}-suffix"))
                .contains("prefix-mid-suffix");
    }

    @Test
    @DisplayName("Should continue resolving multiple simple placeholders correctly")
    void shouldContinueResolvingMultipleSimplePlaceholdersCorrectly() {
        // Regression: ensures that rewriting the parser did not break the
        // non-nested multi-placeholder case that already worked before.
        assertThat(EnvironmentPlaceholder.resolve("${A:1}-${B:2}")).contains("1-2");
    }

    @Test
    @DisplayName("Should treat an unclosed key as a literal")
    void shouldTreatUnclosedKeyAsLiteral() {
        assertThat(EnvironmentPlaceholder.resolve("tr${incompleto"))
                .contains("tr${incompleto");
    }

}

