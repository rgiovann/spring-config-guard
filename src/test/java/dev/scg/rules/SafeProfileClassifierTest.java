package dev.scg.rules;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


class SafeProfileClassifierTest {

    @Test
    @DisplayName("Should consider safe when profile is a token")
    void shouldConsiderSafeWhenProfileIsToken() {
        assertThat(SafeProfileClassifier.isSafeProfile("dev")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("test")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("local")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("development")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("testing")).isTrue();
    }

    @Test
    @DisplayName("Should be case insensitive")
    void shouldBeCaseInsensitive() {
        // Regression: real bug introduced during the utility class extraction
        // (the lowercase conversion, previously done by the caller, had disappeared from the pipeline).
        assertThat(SafeProfileClassifier.isSafeProfile("DEV")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("Dev")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("TEST")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("Prod-TEST")).isTrue();
    }

    @Test
    @DisplayName("Should consider safe for profiles composed with a token")
    void shouldConsiderSafeForProfilesComposedWithToken() {
        assertThat(SafeProfileClassifier.isSafeProfile("dev-local")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("cloud-test")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("local_db")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("test.ci")).isTrue();
    }

    @Test
    @DisplayName("Should not consider safe for substring without separator")
    void shouldNotConsiderSafeForSubstringWithoutSeparator() {
        // "delivery" contains "dev" as a substring, but without a separator it is not the
        // same as the isolated "dev" token — it should not trigger a false negative.
        assertThat(SafeProfileClassifier.isSafeProfile("delivery")).isFalse();
        assertThat(SafeProfileClassifier.isSafeProfile("devices")).isFalse();
        assertThat(SafeProfileClassifier.isSafeProfile("contest")).isFalse();
    }

    @Test
    @DisplayName("Should not consider safe for production profile")
    void shouldNotConsiderSafeForProductionProfile() {
        assertThat(SafeProfileClassifier.isSafeProfile("prod")).isFalse();
        assertThat(SafeProfileClassifier.isSafeProfile("production")).isFalse();
        assertThat(SafeProfileClassifier.isSafeProfile("staging")).isFalse();
    }

    @Test
    @DisplayName("Should return false when profile is null")
    void shouldReturnFalseWhenProfileIsNull() {
        assertThat(SafeProfileClassifier.isSafeProfile(null)).isFalse();
    }

    @Test
    @DisplayName("Should return false when profile is empty")
    void shouldReturnFalseWhenProfileIsEmpty() {
        assertThat(SafeProfileClassifier.isSafeProfile("")).isFalse();
    }
}

