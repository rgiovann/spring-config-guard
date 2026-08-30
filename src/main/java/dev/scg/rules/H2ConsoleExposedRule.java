package dev.scg.rules;

import dev.scg.core.*;

import java.util.List;

/**
 * SCG002 — Detects spring.h2.console.enabled=true outside dev/test/local profiles.

 * The H2 Console is a web interface that allows arbitrary SQL execution in the application.
 * It is extremely useful for local development, but a critical vector for RCE (Remote Code Execution)
 * and data leakage if exposed in production environments.
 * spring.h2.console.settings.web-allow-others (default false) controls whether the console accepts
 * remote connections, not just localhost. When true, the risk escalates from "anyone with access to
 * the internal network" to "any host that can reach the application over the network" — the rule keeps
 * HIGH in both cases (deliberate decision: no new severity level), but differentiates the finding message
 * to make the aggravating factor clear.
 */
public final class H2ConsoleExposedRule implements Rule {

    private static final String H2_ENABLED_KEY = "spring.h2.console.enabled";
    private static final String WEB_ALLOW_OTHERS_KEY = "spring.h2.console.settings.web-allow-others";

    @Override
    public String id() {
        return "SCG002";
    }

    @Override
    public String description() {
        return "H2 console enabled outside dev/test/local profiles";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        if (SafeProfileClassifier.isSafeProfile(config.profileLabel())) {
            return List.of(); // Local/dev profiles are exempt from the check
        }

         String enabledValue = RelaxedProperties.get(config.properties(), H2_ENABLED_KEY);

        if (!RelaxedBoolean.isTruthy(enabledValue)) {
            return List.of();
        }

         boolean allowsRemoteAccess = RelaxedBoolean.isTruthy(RelaxedProperties.get(config.properties(), WEB_ALLOW_OTHERS_KEY));

        return List.of(new Finding(
                id(),
                Severity.HIGH,
                buildMessage(enabledValue, config, allowsRemoteAccess),
                config.sourceFile().toString(),
                config.profileLabel()
        ));
    }

    private String buildMessage(String enabledValue, EffectiveConfig config, boolean allowsRemoteAccess) {
        StringBuilder message = new StringBuilder(
                "H2 console enabled (%s=%s) in profile '%s'. "
                        .formatted(H2_ENABLED_KEY, enabledValue, config.profileLabel())
        );

        if (allowsRemoteAccess) {
            message.append("AGGRAVATING FACTOR: %s=true — the console accepts remote connections, not just localhost. "
                            .formatted(WEB_ALLOW_OTHERS_KEY))
                    .append("Critical risk of remote code execution (RCE) from any host that can reach the application over the network. ")
                    .append("Disable both properties outside local environments.");
        } else {
            message.append("High risk of remote code execution (RCE) and data exposure. ")
                    .append("Disable it via 'spring.h2.console.enabled=false' outside local environments.");
        }

        return message.toString();
    }
}