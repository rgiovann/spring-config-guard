package dev.scg.core;

/**
 * Representa um problema encontrado por uma regra.
 *
 * Por que record e não classe comum? Finding é puro dado imutável — não tem
 * comportamento, só carrega informação de um ponto (a regra) para outro
 * (o relatório). Record elimina boilerplate de getters/equals/hashCode/toString
 * sem esconder nada: é exatamente o que parece ser.
 */
public record Finding(
        String ruleId,
        Severity severity,
        String message,
        String sourceFile
) {
    @Override
    public String toString() {
        return "[%s] %s (%s) — %s".formatted(severity, ruleId, sourceFile, message);
    }
}
