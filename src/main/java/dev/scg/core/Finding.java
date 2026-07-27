package dev.scg.core;

/**
 * Representa um problema encontrado por uma regra.
 *
 * profileLabel identifica em qual configuração efetiva o achado ocorreu
 * ("base", "dev", "prod", etc) — nunca nulo ou vazio, mesma convenção
 * de EffectiveConfig.profileLabel(). Isso permite que a mesma regra,
 * rodando contra o mesmo arquivo, aponte problemas diferentes em
 * profiles diferentes sem ambiguidade na mensagem final.
 */
public record Finding(
        String ruleId,
        Severity severity,
        String message,
        String sourceFile,
        String profileLabel
) {
    @Override
    public String toString() {
        return "[%s] %s (%s) [profile: %s] — %s".formatted(severity, ruleId, sourceFile, profileLabel, message);
    }
}
