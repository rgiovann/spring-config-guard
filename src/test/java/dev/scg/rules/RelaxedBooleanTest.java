package dev.scg.rules;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class RelaxedBooleanTest {

    @Test
    @DisplayName("Should consider truthy the values recognized by Spring's relaxed binding")
    void shouldConsiderTruthyValuesRecognizedBySpringRelaxedBinding() {
        assertThat(RelaxedBoolean.isTruthy("true")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("yes")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("on")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("1")).isTrue();
    }

    @Test
    @DisplayName("Should be case insensitive")
    void shouldBeCaseInsensitive() {
        assertThat(RelaxedBoolean.isTruthy("TRUE")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("True")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("YES")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("ON")).isTrue();
    }

    @Test
    @DisplayName("Should ignore surrounding whitespace")
    void shouldIgnoreSurroundingWhitespace() {
        assertThat(RelaxedBoolean.isTruthy(" true ")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("\ttrue\n")).isTrue();
    }

    @Test
    @DisplayName("Should return false for non-truthy values")
    void shouldReturnFalseForNonTruthyValues() {
        assertThat(RelaxedBoolean.isTruthy("false")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("no")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("off")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("0")).isFalse();
    }

    @Test
    @DisplayName("Should return false for invalid values or typos")
    void shouldReturnFalseForInvalidValuesOrTypos() {
        // "flase" — the same case already protected in ActuatorExposureRule:
        // a typo should not accidentally be counted as false (nor as true).
        assertThat(RelaxedBoolean.isTruthy("flase")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("yep")).isFalse();
    }

    @Test
    @DisplayName("Should return false when value is null")
    void shouldReturnFalseWhenValueIsNull() {
        assertThat(RelaxedBoolean.isTruthy(null)).isFalse();
    }

    @Test
    @DisplayName("Should return false when value is empty")
    void shouldReturnFalseWhenValueIsEmpty() {
        assertThat(RelaxedBoolean.isTruthy("")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("   ")).isFalse();
    }

    @Test
    @DisplayName("Should return true for dynamic placeholder without default")
    void shouldReturnTrueForDynamicPlaceholderWithoutDefault() {
        // Security posture: a statically indeterminable value is treated
        // as a potential risk, not as an absence of risk.
        assertThat(RelaxedBoolean.isTruthy("${SOME_ENV_VAR}")).isTrue();
    }

    @Test
    @DisplayName("Should resolve placeholder with default normally")
    void shouldResolvePlaceholderWithDefaultNormally() {
        assertThat(RelaxedBoolean.isTruthy("${SOME_ENV_VAR:true}")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("${SOME_ENV_VAR:false}")).isFalse();
    }
}

