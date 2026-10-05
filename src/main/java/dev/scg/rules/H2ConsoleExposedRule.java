package dev.scg.rules;

import dev.scg.core.*;

import java.util.List;
import java.util.Optional;

/**
 * SCG002 — detects the H2 console turned on by {@code spring.h2.console.enabled}, flagged
 * regardless of profile (Zero-Trust: no profile exemption — see CLAUDE.md).
 * <p>
 * The H2 console is a web SQL client: its login form connects to any JDBC URL typed into it. What
 * the rule reports was measured in a running Spring Boot 4.1.1 app with the H2 console module
 * (VALIDATION.md, "SCG002 H2 console scenarios"):
 * <ul>
 *     <li>Spring Boot turns the console on with {@code @ConditionalOnBooleanProperty}, which took
 *     only {@code true}, in any case: {@code yes}, {@code on}, {@code 1} and {@code true} with a
 *     trailing space left it off, unlike a property bound through the Binder. The value is compared
 *     without trimming. An unquoted YAML {@code on} is a YAML boolean, loaded as {@code true}.</li>
 *     <li>A placeholder without a default stopped the app from starting where the variable was
 *     unset; where it is set, the value can't be known statically, so it is {@link Severity#INFO}.</li>
 *     <li>Without {@code spring.h2.console.settings.web-allow-others}, H2 serves the console to
 *     loopback clients only. It is {@link Severity#HIGH} anyway: through a reverse proxy on the
 *     same machine, forwarding from loopback without an {@code X-Forwarded-For} header, the console
 *     answered a remote client. (A proxy that sends that header, to an app that trusts it, passes
 *     the client's own address instead; that was not measured.) {@code web-allow-others} is bound through the Binder ({@code true}, {@code yes},
 *     {@code on}, {@code 1}) and lets every client in directly; the rule keeps {@code HIGH} and
 *     names it in the message.</li>
 * </ul>
 * Inherent static-analysis limitation: the console exists only in a servlet web application with
 * H2 and Spring Boot's H2 console module on the classpath (the conditions of
 * {@code H2ConsoleAutoConfiguration}). SCG doesn't see the classpath, so a WebFlux application, or
 * one without H2, is reported too.
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
        return "H2 console enabled (flagged regardless of profile)";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        String enabledValue = RelaxedProperties.get(config.properties(), H2_ENABLED_KEY);
        if (enabledValue == null) {
            return List.of();
        }

        Optional<String> enabled = EnvironmentPlaceholder.resolve(enabledValue);
        if (enabled.isEmpty()) {
            return List.of(finding(Severity.INFO,
                    ("'%s=%s' relies on an unresolved environment placeholder: if it resolves to 'true', the H2 " +
                            "console, a web SQL client that connects to any JDBC URL typed into its login form, is " +
                            "served by the application. Static analysis cannot verify the runtime value.")
                            .formatted(H2_ENABLED_KEY, enabledValue),
                    config));
        }
        if (!enabled.get().equalsIgnoreCase("true")) {
            return List.of();
        }

        return List.of(finding(Severity.HIGH, enabledMessage(enabledValue, config), config));
    }

    private String enabledMessage(String enabledValue, EffectiveConfig config) {
        StringBuilder message = new StringBuilder(
                ("H2 console enabled (%s=%s): a web SQL client that connects to any JDBC URL typed into its login " +
                        "form. ").formatted(H2_ENABLED_KEY, enabledValue));

        String allowOthersValue = RelaxedProperties.get(config.properties(), WEB_ALLOW_OTHERS_KEY);
        Optional<String> allowOthers = allowOthersValue == null
                ? Optional.of("false")
                : EnvironmentPlaceholder.resolve(allowOthersValue);

        if (allowOthers.isEmpty()) {
            message.append(("%s=%s relies on an unresolved placeholder: if it resolves to true, the console accepts " +
                    "connections from any client, not just loopback. ").formatted(WEB_ALLOW_OTHERS_KEY, allowOthersValue));
        } else if (RelaxedBoolean.isTrueLiteral(allowOthers.get())) {
            message.append(("AGGRAVATING FACTOR: %s=%s - the console accepts connections from any client that can " +
                    "reach the application, not just loopback. ").formatted(WEB_ALLOW_OTHERS_KEY, allowOthersValue));
        } else {
            message.append("It answers loopback clients only, which can include requests forwarded by a reverse " +
                    "proxy or sidecar on the same machine. ");
        }
        message.append("Disable it via 'spring.h2.console.enabled=false'.");
        return message.toString();
    }

    private Finding finding(Severity severity, String message, EffectiveConfig config) {
        return new Finding(id(), severity, message, config.sourceFile().toString(), config.profileLabel());
    }
}
