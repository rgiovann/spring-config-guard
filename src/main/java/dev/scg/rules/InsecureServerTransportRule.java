package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;

/**
 * SCG011 — detects insecure transport configuration in Spring Boot's embedded server settings:
 * <ul>
 *     <li>{@code server.ssl.enabled=false} when TLS material is configured under {@code server.ssl.*}
 *     ({@code key-store}, a PEM {@code certificate}, a {@code bundle} or {@code server-name-bundles}).</li>
 *     <li>{@code management.server.ssl.enabled=false} when Actuator runs on its own port and TLS
 *     material is configured under {@code management.server.ssl.*} or {@code server.ssl.*}.</li>
 *     <li>{@code session.cookie.secure=false}, {@code session.cookie.http-only=false} and
 *     {@code session.cookie.same-site=None}, under both {@code server.servlet.*} (servlet stack) and
 *     {@code server.reactive.*} (WebFlux).</li>
 * </ul>
 * <p>
 * Transport security vulnerabilities allow attackers in the network path to intercept session
 * identifiers or sensitive application traffic (CWE-319, CWE-614), or to steal them via client-side
 * script access (CWE-1004). Spring Boot defaults these settings to safe runtime behaviors, but
 * explicit opt-outs in configuration reintroduce the underlying risk. The behavior each check relies
 * on was verified in running Spring Boot 4.1.1 apps (VALIDATION.md, "SCG011 transport scenarios").
 * <p>
 * <b>Management port:</b> {@code management.server.ssl.*} only takes effect when Actuator runs on its
 * own connector. The rule follows Spring Boot's {@code ManagementPortType.get()}: a negative
 * {@code management.server.port} disables the management server, and a port equal to
 * {@code server.port} (or to 8080 when {@code server.port} is not set) shares the main connector;
 * either way the management SSL properties are ignored and the rule stays silent. A port whose value
 * can't be known (an unresolved placeholder) is reported as INFO. Without
 * {@code management.server.ssl.*}, a separate management connector inherits {@code server.ssl.*},
 * so TLS material there is also evidence that the management connector was meant to use TLS.
 * <p>
 * Follows the project's standard 3-state environment placeholder resolution language:
 * <ul>
 *     <li>Unresolved placeholder → {@link Severity#INFO} warning.</li>
 *     <li>Resolved to a risky value → {@link Severity#HIGH} for disabled server or management SSL,
 *     {@link Severity#MEDIUM} for the session cookie checks — see below.</li>
 *     <li>Resolved to a safe value or absent → Silent.</li>
 * </ul>
 * <p>
 * Disabled SSL is HIGH: all of the connector's traffic, credentials included, travels in cleartext.
 * The cookie checks are MEDIUM: none of them exposes the cookie's value by itself. Each is defense in
 * depth that only matters once another weakness exists — a request over plain HTTP ({@code Secure}),
 * an XSS ({@code HttpOnly}) or a cross-site request forgery ({@code SameSite=None}).
 * <p>
 * Zero-Trust policy: Checked regardless of active profile. Plain {@link Rule}, not {@link ConfigurableRule}.
 */
public final class InsecureServerTransportRule implements Rule {

    private static final String RULE_NAME = "SCG011";

    private static final String SERVER_SSL_PREFIX = "server.ssl";
    private static final String MANAGEMENT_SSL_PREFIX = "management.server.ssl";
    private static final String SERVER_PORT_KEY = "server.port";
    private static final String MANAGEMENT_SERVER_PORT_KEY = "management.server.port";
    private static final String SERVLET_COOKIE_PREFIX = "server.servlet.session.cookie";
    private static final String REACTIVE_COOKIE_PREFIX = "server.reactive.session.cookie";
    private static final int DEFAULT_SERVER_PORT = 8080;
    private static final List<String> TLS_MATERIAL_KEYS = List.of("key-store", "certificate", "bundle");
    private static final String SERVER_NAME_BUNDLES_KEY = "server-name-bundles";
    private static final String SAME_SITE_NONE = "none";

    /** Spring Boot's {@code ManagementPortType}, plus the case static analysis can't decide. */
    private enum ManagementPort { DISABLED, SAME, DIFFERENT, UNRESOLVED }

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

        checkDisabledServerSsl(config, findings);
        checkDisabledManagementSsl(config, findings);
        checkSessionCookie(config, SERVLET_COOKIE_PREFIX, findings);
        checkSessionCookie(config, REACTIVE_COOKIE_PREFIX, findings);

        return findings;
    }

    private void checkDisabledServerSsl(EffectiveConfig config, List<Finding> findings) {
        Optional<String> material = tlsMaterialKey(config, SERVER_SSL_PREFIX);
        if (material.isEmpty()) {
            return;
        }

        String enabledKey = SERVER_SSL_PREFIX + ".enabled";
        String raw = RelaxedProperties.get(config.properties(), enabledKey);
        Optional<Finding> unresolved = unresolvedFinding(enabledKey, raw, config);
        if (unresolved.isPresent()) {
            findings.add(unresolved.get());
            return;
        }

        if (isExplicitlyFalsy(resolvedOrNull(raw))) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    ("SSL is explicitly disabled via '%s=%s' despite TLS material being configured ('%s'). " +
                            "The embedded server listens in cleartext HTTP, so all of its traffic can be read " +
                            "and altered on the network path (CWE-319). Enable SSL.")
                            .formatted(enabledKey, raw, material.get()),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }
    }

    private void checkDisabledManagementSsl(EffectiveConfig config, List<Finding> findings) {
        String enabledKey = MANAGEMENT_SSL_PREFIX + ".enabled";
        String raw = RelaxedProperties.get(config.properties(), enabledKey);
        Optional<Finding> unresolvedEnabled = unresolvedFinding(enabledKey, raw, config);
        if (unresolvedEnabled.isEmpty() && !isExplicitlyFalsy(resolvedOrNull(raw))) {
            return;
        }

        // A separate management connector inherits server.ssl.* unless management.server.ssl.* is
        // set (ManagementWebServerFactoryCustomizer), so TLS material under either prefix shows the
        // connector was meant to use TLS. Without any, enabled=false states what is already the case.
        Optional<String> material = tlsMaterialKey(config, MANAGEMENT_SSL_PREFIX)
                .or(() -> tlsMaterialKey(config, SERVER_SSL_PREFIX));
        if (material.isEmpty()) {
            return;
        }

        String port = RelaxedProperties.get(config.properties(), MANAGEMENT_SERVER_PORT_KEY);
        switch (managementPort(config)) {
            case DISABLED, SAME -> {
                // The management server is off, or shares the main connector and its server.ssl.*:
                // Spring Boot ignores management.server.ssl.* in both cases.
            }
            case UNRESOLVED -> findings.add(unresolvedPlaceholderFinding(
                    isUnresolved(port) ? MANAGEMENT_SERVER_PORT_KEY : SERVER_PORT_KEY,
                    isUnresolved(port) ? port : RelaxedProperties.get(config.properties(), SERVER_PORT_KEY),
                    config));
            case DIFFERENT -> {
                if (unresolvedEnabled.isPresent()) {
                    findings.add(unresolvedEnabled.get());
                    return;
                }
                findings.add(new Finding(
                        id(),
                        Severity.HIGH,
                        ("Management SSL is explicitly disabled via '%s=%s' despite TLS material being " +
                                "configured ('%s') and Actuator running on its own port ('%s=%s'). The management " +
                                "endpoints listen in cleartext HTTP, so their traffic can be read and altered on " +
                                "the network path (CWE-319). Enable management SSL.")
                                .formatted(enabledKey, raw, material.get(), MANAGEMENT_SERVER_PORT_KEY, port),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }
    }

    /**
     * Mirrors Spring Boot's {@code ManagementPortType.get()}. A port that doesn't bind to an integer
     * fails the application's startup, so it is treated as {@link ManagementPort#SAME} (silent).
     */
    private ManagementPort managementPort(EffectiveConfig config) {
        String rawManagementPort = RelaxedProperties.get(config.properties(), MANAGEMENT_SERVER_PORT_KEY);
        if (isUnresolved(rawManagementPort)) {
            return ManagementPort.UNRESOLVED;
        }
        OptionalInt managementPort = parsePort(rawManagementPort);
        if (managementPort.isEmpty()) {
            return ManagementPort.SAME;
        }
        int management = managementPort.getAsInt();
        if (management < 0) {
            return ManagementPort.DISABLED;
        }
        if (management == 0) {
            // Port 0 is a random port, never shared with the main connector.
            return ManagementPort.DIFFERENT;
        }

        String rawServerPort = RelaxedProperties.get(config.properties(), SERVER_PORT_KEY);
        if (isUnresolved(rawServerPort)) {
            return ManagementPort.UNRESOLVED;
        }
        int server = parsePort(rawServerPort).orElse(DEFAULT_SERVER_PORT);
        return management == server ? ManagementPort.SAME : ManagementPort.DIFFERENT;
    }

    private static OptionalInt parsePort(String raw) {
        String resolved = resolvedOrNull(raw);
        if (resolved == null || resolved.isBlank()) {
            return OptionalInt.empty();
        }
        try {
            return OptionalInt.of(Integer.parseInt(resolved.strip()));
        } catch (NumberFormatException e) {
            return OptionalInt.empty();
        }
    }

    private void checkSessionCookie(EffectiveConfig config, String prefix, List<Finding> findings) {
        boolean reactive = prefix.equals(REACTIVE_COOKIE_PREFIX);

        String secureKey = prefix + ".secure";
        String secure = RelaxedProperties.get(config.properties(), secureKey);
        Optional<Finding> unresolvedSecure = unresolvedFinding(secureKey, secure, config);
        if (unresolvedSecure.isPresent()) {
            findings.add(unresolvedSecure.get());
        } else if (isExplicitlyFalsy(resolvedOrNull(secure))) {
            String effect = reactive
                    ? "WebFlux then sends the session cookie without 'Secure', also on HTTPS responses, so a " +
                            "browser attaches it to plain HTTP requests too, exposing it to network interception (CWE-614)."
                    : "With Spring Session, the session cookie is then sent without 'Secure', also on HTTPS responses, " +
                            "so a browser attaches it to plain HTTP requests too, exposing it to network interception " +
                            "(CWE-614). Tomcat's and Jetty's own session cookie (JSESSIONID) is still marked 'Secure' " +
                            "on HTTPS requests; the key only takes effect with Spring Session.";
            findings.add(cookieFinding("Session cookie 'Secure' flag is explicitly disabled via '%s=%s'. "
                    .formatted(secureKey, secure) + effect, config));
        }

        String httpOnlyKey = prefix + ".http-only";
        String httpOnly = RelaxedProperties.get(config.properties(), httpOnlyKey);
        Optional<Finding> unresolvedHttpOnly = unresolvedFinding(httpOnlyKey, httpOnly, config);
        if (unresolvedHttpOnly.isPresent()) {
            findings.add(unresolvedHttpOnly.get());
        } else if (isExplicitlyFalsy(resolvedOrNull(httpOnly))) {
            findings.add(cookieFinding(("Session cookie 'HttpOnly' flag is explicitly disabled via '%s=%s'. This " +
                    "allows client-side scripts to read the session cookie via document.cookie, so an XSS flaw " +
                    "can steal it (CWE-1004).").formatted(httpOnlyKey, httpOnly), config));
        }

        String sameSiteKey = prefix + ".same-site";
        String sameSite = RelaxedProperties.get(config.properties(), sameSiteKey);
        Optional<Finding> unresolvedSameSite = unresolvedFinding(sameSiteKey, sameSite, config);
        if (unresolvedSameSite.isPresent()) {
            findings.add(unresolvedSameSite.get());
        } else {
            // A blank value is Spring's own OMITTED state: the attribute is left off the Set-Cookie
            // header entirely, not defaulted to None.
            String resolved = resolvedOrNull(sameSite);
            if (resolved != null && SAME_SITE_NONE.equalsIgnoreCase(resolved.strip())) {
                findings.add(cookieFinding(("Session cookie 'SameSite' attribute is explicitly set to 'None' via " +
                        "'%s=%s'. This allows the cookie to be sent on cross-site requests, widening the attack " +
                        "surface for CSRF-style abuse. Use 'Lax' or 'Strict' unless cross-site delivery is a " +
                        "deliberate, justified requirement.").formatted(sameSiteKey, sameSite), config));
            }
        }
    }

    private Finding cookieFinding(String message, EffectiveConfig config) {
        return new Finding(id(), Severity.MEDIUM, message, config.sourceFile().toString(), config.profileLabel());
    }

    /**
     * The first key under {@code prefix} that configures TLS material, as written in the file.
     * A placeholder counts: it still shows TLS was intended.
     */
    private static Optional<String> tlsMaterialKey(EffectiveConfig config, String prefix) {
        Map<String, String> properties = config.properties();
        if (properties == null) {
            return Optional.empty();
        }
        for (String key : TLS_MATERIAL_KEYS) {
            String value = RelaxedProperties.get(properties, prefix + "." + key);
            if (value != null && !value.isBlank()) {
                return RelaxedProperties.findActualKey(properties, prefix + "." + key);
            }
        }
        String serverNameBundles = RelaxedProperties.canonicalize(prefix + "." + SERVER_NAME_BUNDLES_KEY) + "[";
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            if (RelaxedProperties.canonicalize(entry.getKey()).startsWith(serverNameBundles)
                    && entry.getValue() != null && !entry.getValue().isBlank()) {
                return Optional.of(entry.getKey());
            }
        }
        return Optional.empty();
    }

    private static boolean isUnresolved(String raw) {
        return raw != null && !raw.isBlank() && EnvironmentPlaceholder.resolve(raw.strip()).isEmpty();
    }

    /**
     * The value with its placeholders resolved, or {@code null} when absent or unresolved.
     * <p>
     * A resolved-but-blank value (e.g. {@code "${COOKIE_SECURE:}"}) is never treated as an explicit
     * opt-out. For the cookie flags ({@code Boolean}) the Binder keeps the default, which is safe. For
     * {@code ssl.enabled} (a primitive {@code boolean}) the application fails to start ("Failed to
     * bind properties under 'server.ssl.enabled' to boolean"), so nothing is served either.
     */
    private static String resolvedOrNull(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return EnvironmentPlaceholder.resolve(raw.strip()).orElse(null);
    }

    private Optional<Finding> unresolvedFinding(String key, String raw, EffectiveConfig config) {
        return isUnresolved(raw) ? Optional.of(unresolvedPlaceholderFinding(key, raw, config)) : Optional.empty();
    }

    /**
     * Deliberately NOT {@code !RelaxedBoolean.isTrueLiteral(value)}. Spring's true and false
     * literals are not complements of each other over the space of all
     * possible strings — an unrecognized literal (typo, garbage, a value Spring's own
     * StringToBooleanConverter would reject at startup) belongs to neither set. Negating
     * isTrueLiteral() would silently sweep that third bucket into "risk," misreporting a
     * value nobody wrote as a false literal ("SSL is explicitly disabled via '...=Flase'").
     * This rule's risk direction is false = risk, so it needs a positive-membership test
     * against the specific falsy literals ({@link RelaxedBoolean#isFalseLiteral}), not a
     * negation of the truthy one.
     */
    private static boolean isExplicitlyFalsy(String value) {
        return RelaxedBoolean.isFalseLiteral(value);
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
