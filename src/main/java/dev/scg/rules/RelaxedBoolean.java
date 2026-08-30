package dev.scg.rules;

import dev.scg.core.EnvironmentPlaceholder;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public final class RelaxedBoolean {

    private static final Set<String> TRUTHY_VALUES = Set.of("true", "yes", "on", "1");

    public static boolean isTruthy(String value) {
        if (value == null) {
            return false; // missing key — unchanged behavior
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        if (resolved.isEmpty()) {

        // Dynamic placeholder without a default: the actual value only exists at
        // runtime and cannot be determined through static analysis. Project security
        // posture: assume the worst case (true) instead of suppressing a potential risk.


            return true;
        }

        return TRUTHY_VALUES.contains(resolved.get().trim().toLowerCase(Locale.ROOT));
    }
}