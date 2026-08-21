package dev.scg.rules;

import java.util.Locale;
import java.util.Set;

public final class SafeProfileClassifier {

    private static final Set<String> SAFE_PROFILE_TOKENS = Set.of(
            "dev", "development", "test", "testing", "local"
    );

    public static boolean isSafeProfile(String profile) {
        if (profile == null) {
            return false;
        }

        String[] tokens = profile.toLowerCase(Locale.ROOT).split("[-_.]");
        for (String token : tokens) {
            if (SAFE_PROFILE_TOKENS.contains(token)) {
                return true;
            }
        }
        return false;
    }
}