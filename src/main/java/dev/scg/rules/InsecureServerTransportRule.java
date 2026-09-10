package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;

/**
 * SCG011 — detects insecure transport configuration in Spring Boot's embedded server settings:
 * <ul>
 *     <li>{@code server.ssl.enabled=false} when an explicit {@code server.ssl.key-store} is defined.</li>
 *     <li>{@code server.servlet.session.cookie.secure=false}.</li>
 *     <li>{@code management.server.ssl.enabled=false} when an explicit
 *     {@code management.server.ssl.key-store} is defined and {@code management.server.port} configures
 *     a separate management port.</li>
 *     <li>{@code server.servlet.session.cookie.http-only=false}.</li>
 *     <li>{@code server.servlet.session.cookie.same-site=None} (explicit).</li>
 * </ul>
 * <p>
 * Transport security vulnerabilities allow attackers in the network path to intercept session
 * identifiers or sensitive application traffic (CWE-319, CWE-614), or to steal them via client-side
 * script access (CWE-1004). Spring Boot defaults these settings to safe runtime behaviors, but
 * explicit opt-outs in configuration reintroduce the underlying risk.
 * <p>
 * <b>Management SSL precondition:</b> {@code management.server.ssl.*} only takes effect when
 * {@code management.server.port} configures Actuator to run on its own connector (Spring Boot
 * reference docs, "Customizing the Management Server Port"). Without a separate management port,
 * these properties are silently ignored by Spring Boot itself and Actuator inherits
 * {@code server.ssl.*} instead — so the management-SSL check requires evidence of a separate port
 * before treating an explicit {@code enabled=false} as a real finding.
 * <p>
 * Follows the project's standard 3-state environment placeholder resolution language:
 * <ul>
 *     <li>Unresolved placeholder → {@link Severity#INFO} warning.</li>
 *     <li>Resolved to a risky value → {@link Severity#HIGH} (or {@link Severity#MEDIUM} for the
 *     SameSite=None check — see below).</li>
 *     <li>Resolved to a safe value or absent → Silent.</li>
 * </ul>
 * <p>
 * SameSite is calibrated to {@link Severity#MEDIUM} rather than {@link Severity#HIGH}: unlike the
 * other checks, an explicit {@code same-site=None} does not by itself expose the cookie's value — it
 * widens the set of cross-site requests the cookie is attached to (CSRF-adjacent attack-surface
 * expansion), the same severity class as this project's other attack-surface-expansion findings
 * (e.g. wildcard CORS), not its credential/session-token-exposure findings.
 * <p>
 * Zero-Trust policy: Checked regardless of active profile. Plain {@link Rule}, not {@link ConfigurableRule}.
 */
public final class InsecureServerTransportRule implements Rule {

    private static final String RULE_NAME = "SCG011";

    private static final String SSL_ENABLED_KEY = "server.ssl.enabled";
    private static final String SSL_KEYSTORE_KEY = "server.ssl.key-store";
    private static final String COOKIE_SECURE_KEY = "server.servlet.session.cookie.secure";
    private static final String MANAGEMENT_SSL_ENABLED_KEY = "management.server.ssl.enabled";
    private static final String MANAGEMENT_SSL_KEYSTORE_KEY = "management.server.ssl.key-store";
    private static final String MANAGEMENT_SERVER_PORT_KEY = "management.server.port";
    private static final String COOKIE_HTTP_ONLY_KEY = "server.servlet.session.cookie.http-only";
    private static final String COOKIE_SAME_SITE_KEY = "server.servlet.session.cookie.same-site";
    private static final String SAME_SITE_NONE = "none";
    private static final Set<String> FALSY_VALUES = Set.of("false", "no", "off", "0");

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Insecure transport, management SSL, or session cookie settings in Spring Boot embedded server configuration";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        checkDisabledSslWithKeystore(config, findings);
        checkInsecureSessionCookie(config, findings);
        checkDisabledManagementSslWithKeystore(config, findings);
        checkInsecureCookieHttpOnly(config, findings);
        checkInsecureCookieSameSite(config, findings);

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

    private void checkDisabledManagementSslWithKeystore(EffectiveConfig config, List<Finding> findings) {
        String managementPort = RelaxedProperties.get(config.properties(), MANAGEMENT_SERVER_PORT_KEY);
        if (managementPort == null || managementPort.isBlank()) {
            // management.server.ssl.* only takes effect when Actuator runs on a separate
            // management port (Spring Boot reference docs, "Customizing the Management Server
            // Port"). Without this key, management endpoints share the main connector and inherit
            // server.ssl.* instead -- these properties would be silently ignored by Spring Boot
            // itself, so their presence alone isn't evidence of a real, active misconfiguration.
            return;
        }

        String keystore = RelaxedProperties.get(config.properties(), MANAGEMENT_SSL_KEYSTORE_KEY);
        if (keystore == null || keystore.isBlank()) {
            return;
        }

        String rawManagementSslEnabled = RelaxedProperties.get(config.properties(), MANAGEMENT_SSL_ENABLED_KEY);
        if (rawManagementSslEnabled == null || rawManagementSslEnabled.isBlank()) {
            return;
        }

        Optional<String> resolvedManagementSsl = EnvironmentPlaceholder.resolve(rawManagementSslEnabled.strip());
        if (resolvedManagementSsl.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(MANAGEMENT_SSL_ENABLED_KEY, rawManagementSslEnabled, config));
            return;
        }

        String resolvedValue = resolvedManagementSsl.get().strip();
        if (resolvedValue.isBlank()) {
            return;
        }

        if (isExplicitlyFalsy(resolvedManagementSsl.get())) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    ("Management SSL is explicitly disabled via '%s=%s' despite '%s' being configured " +
                            "on a separate management port ('%s=%s'). This leaves the Actuator management " +
                            "endpoints listening in cleartext HTTP while retaining unused keystore properties. " +
                            "Enable SSL or remove key-store settings.")
                            .formatted(MANAGEMENT_SSL_ENABLED_KEY, rawManagementSslEnabled, MANAGEMENT_SSL_KEYSTORE_KEY,
                                    MANAGEMENT_SERVER_PORT_KEY, managementPort),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }
    }

    private void checkInsecureCookieHttpOnly(EffectiveConfig config, List<Finding> findings) {
        String raw = RelaxedProperties.get(config.properties(), COOKIE_HTTP_ONLY_KEY);
        if (raw == null || raw.isBlank()) {
            return;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(COOKIE_HTTP_ONLY_KEY, raw, config));
            return;
        }

        String resolvedValue = resolved.get().strip();
        if (resolvedValue.isBlank()) {
            return;
        }

        if (isExplicitlyFalsy(resolved.get())) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    ("Session cookie 'HttpOnly' flag is explicitly disabled via '%s=%s'. This allows " +
                            "client-side scripts to read the session cookie (e.g., JSESSIONID) via " +
                            "document.cookie, making it vulnerable to theft through Cross-Site Scripting " +
                            "(XSS) (CWE-1004).")
                            .formatted(COOKIE_HTTP_ONLY_KEY, raw),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }
    }

    private void checkInsecureCookieSameSite(EffectiveConfig config, List<Finding> findings) {
        String raw = RelaxedProperties.get(config.properties(), COOKIE_SAME_SITE_KEY);
        if (raw == null || raw.isBlank()) {
            return;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(COOKIE_SAME_SITE_KEY, raw, config));
            return;
        }

        String resolvedValue = resolved.get().strip();
        if (resolvedValue.isBlank()) {
            // Absence/blank is Spring's own SameSite.OMITTED state -- the attribute is left off
            // the Set-Cookie header entirely, not defaulted to None. Not this rule's risk to flag.
            return;
        }

        if (SAME_SITE_NONE.equalsIgnoreCase(resolvedValue)) {
            findings.add(new Finding(
                    id(),
                    Severity.MEDIUM,
                    ("Session cookie 'SameSite' attribute is explicitly set to 'None' via '%s=%s'. This " +
                            "allows the cookie to be sent on cross-site requests, widening the attack " +
                            "surface for CSRF-style abuse. Use 'Lax' or 'Strict' unless cross-site delivery " +
                            "is a deliberate, justified requirement.")
                            .formatted(COOKIE_SAME_SITE_KEY, raw),
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