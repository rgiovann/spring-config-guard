package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Every expectation below was measured against a Spring Boot 4.1.1 app (VALIDATION.md, "Profile
 * expressions in {@code on-profile}"): whether a document with that {@code on-profile} value was
 * applied, for each set of active profiles.
 */
class ProfileExpressionTest {

    /** The active-profile sets measured, in the column order of {@link #measured()}. */
    private static final List<Set<String>> ACTIVE_SETS = List.of(
            Set.of("default"),   // no profile active: Spring activates the default profile
            Set.of("a"),
            Set.of("b"),
            Set.of("c"),
            Set.of("a", "b"),
            Set.of("b", "c"));

    /** Expression, then one character per active set above: 1 when Spring applied the document. */
    static Stream<Arguments> measured() {
        return Stream.of(
                Arguments.of("P1", "!a", "101101"),
                Arguments.of("P2", "a,b", "011011"),
                Arguments.of("P4", "a & b", "000010"),
                Arguments.of("P5", "a | b", "011011"),
                Arguments.of("P6", "(a & !b) | c", "010101"),
                Arguments.of("P7", "!a, b", "101111"),
                Arguments.of("P8", "default", "100000"),
                Arguments.of("E1", "!default", "011111"),
                Arguments.of("E2", "a b", "000000"),
                Arguments.of("E3", "a)", "010010"),
                Arguments.of("E3", "(a", "010010"),
                Arguments.of("E3", "&a", "010010"),
                Arguments.of("E3", "a&", "010010"),
                Arguments.of("E4", "!!a", "010010"),
                Arguments.of("E4", "(a)", "010010"),
                Arguments.of("E5", "a & (b | c)", "000010"),
                Arguments.of("E6", "!(a | b)", "100100"),
                Arguments.of("E6", "!a & !b", "100100"));
    }

    @ParameterizedTest(name = "{0}: ''{1}''")
    @MethodSource("measured")
    @DisplayName("Matches the documents Spring Boot applied, for every measured set of active profiles")
    void matchesWhatSpringBootApplied(String row, String value, String applied) {
        ProfileExpression expression = ProfileExpression.parse(value);

        for (int i = 0; i < ACTIVE_SETS.size(); i++) {
            assertThat(expression.matches(ACTIVE_SETS.get(i)))
                    .as("%s '%s' with %s active", row, value, ACTIVE_SETS.get(i))
                    .isEqualTo(applied.charAt(i) == '1');
        }
    }

    @Test
    @DisplayName("P14: spaces around list items are ignored")
    void spacesAroundListItemsAreIgnored() {
        ProfileExpression expression = ProfileExpression.parse(" a ,  b ");

        assertThat(expression.matches(Set.of("default"))).isFalse();
        assertThat(expression.matches(Set.of("a"))).isTrue();
        assertThat(expression.matches(Set.of("b"))).isTrue();
    }

    @Test
    @DisplayName("E2: a space inside a name is part of the profile name")
    void spaceInsideNameIsPartOfTheName() {
        // As Spring's parser reads it. Spring Boot refuses to activate a profile named "a b", so in a
        // running application such a document never applies.
        ProfileExpression expression = ProfileExpression.parse("a b");

        assertThat(expression.matches(Set.of("a b"))).isTrue();
        assertThat(expression.profileNames()).containsExactly("a b");
    }

    @ParameterizedTest(name = "''{0}''")
    @ValueSource(strings = {"a & b | c", "a | !b & c", "!"})
    @DisplayName("P13, E7: an expression Spring Boot refuses to start with is malformed")
    void rejectsMalformedExpressions(String value) {
        assertThatThrownBy(() -> ProfileExpression.parse(value))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Malformed profile expression");
    }

    @ParameterizedTest(name = "''{0}''")
    @ValueSource(strings = {"a,,b", ",a", "a,", " "})
    @DisplayName("E8: an empty list item is rejected, as Spring Boot rejects it")
    void rejectsEmptyItems(String value) {
        assertThatThrownBy(() -> ProfileExpression.parse(value))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must contain text");
    }

    @Test
    @DisplayName("Lists every profile name referenced, negated or not, in the order written")
    void listsProfileNamesInOrder() {
        assertThat(ProfileExpression.parse("(api-docs & !b) | c, prod").profileNames())
                .containsExactly("api-docs", "b", "c", "prod");
        assertThat(ProfileExpression.parse("!api-docs").profileNames())
                .containsExactly("api-docs");
    }

    @Test
    @DisplayName("E9: profile names are case-sensitive")
    void profileNamesAreCaseSensitive() {
        assertThat(ProfileExpression.parse("Prod").matches(Set.of("prod"))).isFalse();
    }

    @Test
    @DisplayName("Keeps the value as written for messages")
    void keepsTheValueAsWritten() {
        assertThat(ProfileExpression.parse(" a ,  b ").text()).isEqualTo(" a ,  b ");
    }
}
