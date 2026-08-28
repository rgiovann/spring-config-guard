package dev.scg.rules;

import dev.scg.core.EnvironmentPlaceholder;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public final class RelaxedBoolean {
    private static final Set<String> TRUTHY_VALUES = Set.of("true", "yes", "on", "1");
    public static boolean isTruthy(String value) {
        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        // Se a variável não tem fallback definido, não assumimos true
        return resolved.filter(s -> TRUTHY_VALUES.contains(s.trim().toLowerCase(Locale.ROOT))).isPresent();
    }
}