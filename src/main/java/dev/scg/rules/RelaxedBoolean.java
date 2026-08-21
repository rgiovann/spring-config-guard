package dev.scg.rules;

import java.util.Locale;
import java.util.Set;

public final class RelaxedBoolean {
    private static final Set<String> TRUTHY_VALUES = Set.of("true", "yes", "on", "1");
    public static boolean isTruthy(String value) {
        return value != null && TRUTHY_VALUES.contains(value.trim().toLowerCase(Locale.ROOT));
    }
}