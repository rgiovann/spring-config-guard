package dev.scg.rules;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RelaxedBooleanTest {

    @Test
    void deveConsiderarTruthyOsValoresReconhecidosPeloRelaxedBindingDoSpring() {
        assertThat(RelaxedBoolean.isTruthy("true")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("yes")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("on")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("1")).isTrue();
    }

    @Test
    void deveSerCaseInsensitive() {
        assertThat(RelaxedBoolean.isTruthy("TRUE")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("True")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("YES")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("ON")).isTrue();
    }

    @Test
    void deveIgnorarEspacosEmVolta() {
        assertThat(RelaxedBoolean.isTruthy(" true ")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("\ttrue\n")).isTrue();
    }

    @Test
    void deveRetornarFalseParaValoresNaoTruthy() {
        assertThat(RelaxedBoolean.isTruthy("false")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("no")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("off")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("0")).isFalse();
    }

    @Test
    void deveRetornarFalseParaValorInvalidoOuTypo() {
        // "flase" — mesmo caso que já protegemos na ActuatorExposureRule:
        // typo não deve acidentalmente contar como false (nem como true).
        assertThat(RelaxedBoolean.isTruthy("flase")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("yep")).isFalse();
    }

    @Test
    void deveRetornarFalseQuandoValorForNull() {
        assertThat(RelaxedBoolean.isTruthy(null)).isFalse();
    }

    @Test
    void deveRetornarFalseQuandoValorForVazio() {
        assertThat(RelaxedBoolean.isTruthy("")).isFalse();
        assertThat(RelaxedBoolean.isTruthy("   ")).isFalse();
    }

    @Test
    void deveRetornarTrueParaPlaceholderDinamicoSemDefault() {
        // Postura de segurança: valor não determinável estaticamente é tratado
        // como potencial risco, não como ausência de risco.
        assertThat(RelaxedBoolean.isTruthy("${SOME_ENV_VAR}")).isTrue();
    }

    @Test
    void deveResolverPlaceholderComDefaultNormalmente() {
        assertThat(RelaxedBoolean.isTruthy("${SOME_ENV_VAR:true}")).isTrue();
        assertThat(RelaxedBoolean.isTruthy("${SOME_ENV_VAR:false}")).isFalse();
    }
}