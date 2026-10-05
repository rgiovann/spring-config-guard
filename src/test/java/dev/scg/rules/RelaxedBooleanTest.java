package dev.scg.rules;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class RelaxedBooleanTest {

    @Test
    @DisplayName("True and false literals are the ones Spring's StringToBooleanConverter accepts, in any case")
    void shouldMatchSpringBooleanLiterals() {
        for (String value : new String[]{"true", "on", "yes", "1", "TRUE", " On ", "\ttrue\n"}) {
            assertThat(RelaxedBoolean.isTrueLiteral(value)).as(value).isTrue();
            assertThat(RelaxedBoolean.isFalseLiteral(value)).as(value).isFalse();
        }
        for (String value : new String[]{"false", "off", "no", "0", "FALSE", " Off "}) {
            assertThat(RelaxedBoolean.isFalseLiteral(value)).as(value).isTrue();
            assertThat(RelaxedBoolean.isTrueLiteral(value)).as(value).isFalse();
        }
    }

    @Test
    @DisplayName("Literal checks don't resolve placeholders and reject other values")
    void shouldRejectNonLiterals() {
        for (String value : new String[]{"${X:true}", "${X}", "enabled", "Flase", "yep", "", "   ", "2"}) {
            assertThat(RelaxedBoolean.isTrueLiteral(value)).as(value).isFalse();
            assertThat(RelaxedBoolean.isFalseLiteral(value)).as(value).isFalse();
        }
        assertThat(RelaxedBoolean.isTrueLiteral(null)).isFalse();
        assertThat(RelaxedBoolean.isFalseLiteral(null)).isFalse();
    }
}

