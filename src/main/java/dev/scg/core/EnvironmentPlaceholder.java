package dev.scg.core;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class EnvironmentPlaceholder {

    // Captura o padrão ${NOME_VARIAVEL:default_value} ou ${NOME_VARIAVEL}
    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\$\\{([^}:]+)(?::([^}]*))?\\}");

    private EnvironmentPlaceholder() {}

    /**
     * Resolve expressões ${...} em uma propriedade.
     * Retorna Optional.empty() se houver variável sem fallback padrão.
     */
    public static Optional<String> resolve(String rawValue) {
        if (rawValue == null) {
            return Optional.empty();
        }

        Matcher matcher = PLACEHOLDER_PATTERN.matcher(rawValue);
        if (!matcher.find()) {
            return Optional.of(rawValue); // Não é um placeholder, retorna a string literal
        }

        matcher.reset();
        StringBuilder sb = new StringBuilder();

        while (matcher.find()) {
            String defaultValue = matcher.group(2); // Grupo 2 contém o valor após o ':'
            if (defaultValue == null) {
                // Variável sem valor default ex: ${ENV_VAR} -> Não é possível prever no linter
                return Optional.empty();
            }
            matcher.appendReplacement(sb, Matcher.quoteReplacement(defaultValue));
        }
        matcher.appendTail(sb);

        return Optional.of(sb.toString());
    }
}