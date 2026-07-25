package dev.scg.core;

import java.nio.file.Path;
import java.util.Map;

/**
 * O resultado de mesclar o(s) documento(s) base de um arquivo com um
 * profile nomeado específico (ou o base sozinho, quando profileLabel
 * é "base"). É isso que as regras (Rule) efetivamente avaliam — nunca
 * um ConfigDocument cru isoladamente, porque um documento de profile
 * sozinho pode não refletir a config real (algumas chaves só existem
 * no base e continuam valendo).
 *
 * profileLabel nunca é nulo ou vazio: para o cenário "nenhum profile
 * ativo", o valor é a String literal "base" — nunca null, nunca
 * Optional. Isso simplifica toda regra e toda formatação de mensagem,
 * já que elas nunca precisam checar ausência.
 */
public record EffectiveConfig(
        Path sourceFile,
        String profileLabel,
        Map<String, String> properties
) {
}