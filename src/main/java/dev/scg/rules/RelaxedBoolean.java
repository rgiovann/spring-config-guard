package dev.scg.rules;

import java.util.Locale;
import java.util.Set;

/**
 * Booleans as Spring reads them from a property: its {@code StringToBooleanConverter} accepts
 * {@code true}/{@code on}/{@code yes}/{@code 1} and {@code false}/{@code off}/{@code no}/{@code 0},
 * in any case. The two sets are not complements: any other literal fails to bind.
 */
public final class RelaxedBoolean {

    private static final Set<String> TRUTHY_VALUES = Set.of("true", "yes", "on", "1");
    private static final Set<String> FALSY_VALUES = Set.of("false", "no", "off", "0");

    /** Whether a literal (placeholders already resolved) is one Spring reads as {@code true}. */
    public static boolean isTrueLiteral(String value) {
        return value != null && TRUTHY_VALUES.contains(value.strip().toLowerCase(Locale.ROOT));
    }

    /** Whether a literal (placeholders already resolved) is one Spring reads as {@code false}. */
    public static boolean isFalseLiteral(String value) {
        return value != null && FALSY_VALUES.contains(value.strip().toLowerCase(Locale.ROOT));
    }
}