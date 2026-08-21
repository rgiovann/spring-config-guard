package dev.scg.rules;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SafeProfileClassifierTest {

    @Test
    void deveConsiderarSeguroQuandoProfileForToken() {
        assertThat(SafeProfileClassifier.isSafeProfile("dev")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("test")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("local")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("development")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("testing")).isTrue();
    }

    @Test
    void deveSerCaseInsensitive() {
        // Regressão: bug real introduzido durante a extração da classe utilitária
        // (o lowercase, antes feito pelo chamador, tinha desaparecido do pipeline).
        assertThat(SafeProfileClassifier.isSafeProfile("DEV")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("Dev")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("TEST")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("Prod-TEST")).isTrue();
    }

    @Test
    void deveConsiderarSeguroParaPerfisCompostosComToken() {
        assertThat(SafeProfileClassifier.isSafeProfile("dev-local")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("cloud-test")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("local_db")).isTrue();
        assertThat(SafeProfileClassifier.isSafeProfile("test.ci")).isTrue();
    }

    @Test
    void naoDeveConsiderarSeguroParaSubstringSemSeparador() {
        // "delivery" contém "dev" como substring, mas sem separador não é o
        // mesmo que o token "dev" isolado — não deve disparar falso negativo.
        assertThat(SafeProfileClassifier.isSafeProfile("delivery")).isFalse();
        assertThat(SafeProfileClassifier.isSafeProfile("devices")).isFalse();
        assertThat(SafeProfileClassifier.isSafeProfile("contest")).isFalse();
    }

    @Test
    void naoDeveConsiderarSeguroParaProfileDeProducao() {
        assertThat(SafeProfileClassifier.isSafeProfile("prod")).isFalse();
        assertThat(SafeProfileClassifier.isSafeProfile("production")).isFalse();
        assertThat(SafeProfileClassifier.isSafeProfile("staging")).isFalse();
    }

    @Test
    void deveRetornarFalseQuandoProfileForNull() {
        assertThat(SafeProfileClassifier.isSafeProfile(null)).isFalse();
    }

    @Test
    void deveRetornarFalseQuandoProfileForVazio() {
        assertThat(SafeProfileClassifier.isSafeProfile("")).isFalse();
    }
}