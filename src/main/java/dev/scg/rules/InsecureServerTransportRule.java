package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;

/**
 * SCG011 — detects insecure transport configuration in Spring Boot's embedded application server settings:
 * <ul>
 *     <li>{@code server.ssl.enabled=false} when an explicit {@code server.ssl.key-store} is defined.</li>
 *     <li>{@code server.servlet.session.cookie.secure=false}.</li>
 * </ul>
 * <p>
 * Transport security vulnerabilities allow attackers in the network path to intercept session
 * identifiers or sensitive application traffic (CWE-319, CWE-614). Spring Boot defaults session cookies
 * to safe runtime behaviors when TLS is active, but explicit opt-outs in configuration reintroduce
 * cleartext transmission risks.
 * <p>
 * <b>Scope Boundary Note:</b> This rule strictly evaluates the main application server ({@code server.*}).
 * Management/Actuator SSL settings (e.g., {@code management.server.ssl.enabled=false} with
 * {@code management.server.ssl.key-store}) are intentionally out of scope for SCG011. They are currently
 * unowned by any rule and tracked as a candidate for a future Actuator/Management-focused SCG rule.
 * <p>
 * Follows the project's standard 3-state environment placeholder resolution language:
 * <ul>
 *     <li>Unresolved placeholder → {@link Severity#INFO} warning.</li>
 *     <li>Resolved to a risky value → {@link Severity#HIGH}.</li>
 *     <li>Resolved to a safe value or absent → Silent.</li>
 * </ul>
 * <p>
 * Zero-Trust policy: Checked regardless of active profile. Plain {@link Rule}, not {@link ConfigurableRule}.
 */
public final class InsecureServerTransportRule implements Rule {

    private static final String RULE_NAME = "SCG011";

    private static final String SSL_ENABLED_KEY = "server.ssl.enabled";
    private static final String SSL_KEYSTORE_KEY = "server.ssl.key-store";
    private static final String COOKIE_SECURE_KEY = "server.servlet.session.cookie.secure";
    private static final Set<String> FALSY_VALUES = Set.of("false", "no", "off", "0");

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Insecure transport or session cookie settings in Spring Boot embedded server configuration";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        checkDisabledSslWithKeystore(config, findings);
        checkInsecureSessionCookie(config, findings);

        return findings;
    }

    private void checkDisabledSslWithKeystore(EffectiveConfig config, List<Finding> findings) {
        String keystore = RelaxedProperties.get(config.properties(), SSL_KEYSTORE_KEY);
        if (keystore == null || keystore.isBlank()) {
            return;
        }

        String rawSslEnabled = RelaxedProperties.get(config.properties(), SSL_ENABLED_KEY);
        if (rawSslEnabled == null || rawSslEnabled.isBlank()) {
            return;
        }

        Optional<String> resolvedSsl = EnvironmentPlaceholder.resolve(rawSslEnabled.strip());
        if (resolvedSsl.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(SSL_ENABLED_KEY, rawSslEnabled, config));
            return;
        }

        // A resolved-but-blank value (e.g. "${COOKIE_SECURE:}") is a fully resolved value,
        // not an unresolved placeholder -- it does not hit the INFO branch above. Spring
        // Boot's Binder treats an empty-string source as absent, so the property keeps its
        // class default (Ssl.enabled=true, cookie.secure=null/auto-detect) -- both safe.
        // Treating it as "explicitly disabled" here would misreport a config that never
        // stated a concrete value.
        String resolvedValue = resolvedSsl.get().strip();
        if (resolvedValue.isBlank()) {
            return;
        }

        if (isExplicitlyFalsy(resolvedSsl.get())) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    ("SSL is explicitly disabled via '%s=%s' despite '%s' being configured. " +
                            "This leaves the embedded server listening in cleartext HTTP while retaining unused " +
                            "keystore properties. Enable SSL or remove key-store settings.")
                            .formatted(SSL_ENABLED_KEY, rawSslEnabled, SSL_KEYSTORE_KEY),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }
    }

    private void checkInsecureSessionCookie(EffectiveConfig config, List<Finding> findings) {
        String raw = RelaxedProperties.get(config.properties(), COOKIE_SECURE_KEY);
        if (raw == null || raw.isBlank()) {
            return;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(COOKIE_SECURE_KEY, raw, config));
            return;
        }
        // A resolved-but-blank value (e.g. "${COOKIE_SECURE:}") is a fully resolved value,
        // not an unresolved placeholder -- it does not hit the INFO branch above. Spring
        // Boot's Binder treats an empty-string source as absent, so the property keeps its
        // class default (Ssl.enabled=true, cookie.secure=null/auto-detect) -- both safe.
        // Treating it as "explicitly disabled" here would misreport a config that never
        // stated a concrete value.
        String resolvedValue = resolved.get().strip();
        if (resolvedValue.isBlank()) {
            return;
        }

        if (isExplicitlyFalsy(resolved.get())) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    ("Session cookie 'Secure' flag is explicitly disabled via '%s=%s'. " +
                            "This allows session cookies (e.g., JSESSIONID) to be transmitted over unencrypted HTTP " +
                            "connections, making them vulnerable to network interception (CWE-614).")
                            .formatted(COOKIE_SECURE_KEY, raw),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }
    }
    /**
     * Deliberately NOT {@code !RelaxedBoolean.isTruthy(value)}. TRUTHY_VALUES and this
     * method's FALSY_VALUES are not complements of each other over the space of all
     * possible strings — an unrecognized literal (typo, garbage, a value Spring's own
     * StringToBooleanConverter would reject at startup) belongs to neither set. Negating
     * isTruthy() would silently sweep that third bucket into "risk," misreporting a
     * value nobody wrote as a false literal ("SSL is explicitly disabled via '...=Flase'").
     * This rule's risk direction is the opposite of isTruthy's (falsy = risk here, not
     * truthy = risk), so it needs its own positive-membership test against the specific
     * falsy literals, not a negation of the truthy one.
     */
    private boolean isExplicitlyFalsy(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        return FALSY_VALUES.contains(value.strip().toLowerCase(Locale.ROOT));
    }

    private Finding unresolvedPlaceholderFinding(String key, String rawValue, EffectiveConfig config) {
        return new Finding(
                id(),
                Severity.INFO,
                ("Server transport property '%s' relies on an unresolved environment placeholder '%s'. " +
                        "Static analysis cannot verify runtime TLS/transport behavior; ensure secure transport " +
                        "is enforced in production.")
                        .formatted(key, rawValue),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }
}