package dev.scg.rules;

import dev.scg.core.EnvironmentPlaceholder;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public final class RelaxedBoolean {

    private static final Set<String> TRUTHY_VALUES = Set.of("true", "yes", "on", "1");

    public static boolean isTruthy(String value) {
        if (value == null) {
            return false; // chave ausente — comportamento inalterado
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        if (resolved.isEmpty()) {
            // Placeholder dinâmico sem default: valor real só existe em
            // runtime, não é determinável em análise estática. Postura de
            // segurança do projeto: assumir o pior caso (verdadeiro) em vez
            // de silenciar um risco potencial.
            return true;
        }

        return TRUTHY_VALUES.contains(resolved.get().trim().toLowerCase(Locale.ROOT));
    }
}