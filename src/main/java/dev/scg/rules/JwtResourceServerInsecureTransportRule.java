package dev.scg.rules;

import dev.scg.core.ConfigurableRule;
import dev.scg.core.EffectiveConfig;
import dev.scg.core.EnvironmentPlaceholder;
import dev.scg.core.Finding;
import dev.scg.core.RelaxedProperties;
import dev.scg.core.Rule;
import dev.scg.core.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * SCG017 — detects HTTP used where an OAuth2 Resource Server fetches what it validates tokens with:
 * {@code jwt.jwk-set-uri}, {@code jwt.issuer-uri} (OIDC discovery), {@code jwt.public-key-location},
 * and {@code opaquetoken.introspection-uri}. Whoever can read or rewrite that traffic can serve
 * their own keys (or an introspection answer saying any token is active) and get tokens the
 * application accepts — authentication bypass, not just traffic interception. {@link Severity#HIGH};
 * a value that is an unresolved placeholder, or a URI whose host is a loopback address
 * ({@code http://localhost:8080/oauth2/jwks}, {@link ConnectionHosts}; not {@code issuer-uri}, whose
 * metadata may send the client to another host for the keys), is {@link Severity#INFO}.
 * <p>
 * Measured on the wire in a running Spring Boot 4.1.1 resource server, with a listener recording
 * whether each fetch was plain HTTP or TLS (VALIDATION.md, "SCG017 resource server transport
 * scenarios"): with an {@code http://} URI, the keys, the discovery document and the public key
 * were fetched in plain HTTP, and introspection sent the client secret in the clear; the application
 * started with the key it fetched from an {@code http://} {@code public-key-location}, which it reads
 * at startup. Forging a token was not attempted. The keys come from the first of
 * {@code jwk-set-uri}, {@code issuer-uri} and {@code public-key-location} that is set (Spring Boot's
 * {@code IssuerUriCondition} and {@code KeyValueCondition}): next to a {@code jwk-set-uri}, neither
 * of the others was fetched, and next to an {@code issuer-uri}, {@code public-key-location} wasn't,
 * so the keys after the one in use are not reported. When the one before is an unresolved
 * placeholder, it may resolve empty at runtime, so an HTTP value after it is {@link Severity#INFO}.
 * The scheme is matched in any case: {@code HTTP://} connected in plain HTTP too.
 * <p>
 * Deliberately a dedicated rule rather than an addition to {@link InsecureDatabaseTransportRule}'s
 * (SCG012) {@code uri-based}/{@code risky-schemes} list: the same {@code http://} signal causes a
 * qualitatively different, more severe outcome here that a generic scheme scanner can't express in
 * its message or severity.
 * <p>
 * Plain {@link Rule}, not {@link ConfigurableRule}: the four target keys are a fixed, closed fact of
 * Spring Boot's OAuth2 Resource Server support. Zero-Trust: checked regardless of active
 * profile.
 *
 * @see EnvironmentPlaceholder
 */
public final class JwtResourceServerInsecureTransportRule implements Rule {

    private static final String ISSUER_URI_KEY = "spring.security.oauth2.resourceserver.jwt.issuer-uri";
    private static final String JWK_SET_URI_KEY = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri";
    private static final String PUBLIC_KEY_LOCATION_KEY = "spring.security.oauth2.resourceserver.jwt.public-key-location";
    private static final String INTROSPECTION_URI_KEY = "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri";

    /** Where the JWT keys come from, in Spring Boot's order of precedence. */
    private static final List<String> KEY_SOURCES =
            List.of(JWK_SET_URI_KEY, ISSUER_URI_KEY, PUBLIC_KEY_LOCATION_KEY);

    private static final String INSECURE_SCHEME = "http://";

    @Override
    public String id() {
        return "SCG017";
    }

    @Override
    public String description() {
        return "Insecure transport (HTTP) configured for OAuth2 Resource Server token validation endpoints";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();
        // Spring Boot uses the first of these that is set and ignores the rest. A key set to an
        // unresolved placeholder may still resolve empty at runtime, so the keys after it are
        // checked too, with an HTTP value as INFO: it is used only in that case.
        String placeholderBefore = null;
        for (String key : KEY_SOURCES) {
            String rawValue = rawValue(config, key);
            if (rawValue == null) {
                continue;
            }
            Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);
            if (resolved.isPresent() && resolved.get().isBlank()) {
                continue;
            }
            evaluateKey(key, rawValue, placeholderBefore, config, findings);
            if (resolved.isPresent()) {
                break;
            }
            if (placeholderBefore == null) {
                placeholderBefore = key;
            }
        }

        String introspectionUri = rawValue(config, INTROSPECTION_URI_KEY);
        if (introspectionUri != null) {
            evaluateKey(INTROSPECTION_URI_KEY, introspectionUri, null, config, findings);
        }
        return findings;
    }

    /** The value stripped, or {@code null} when the key is absent or blank. */
    private static String rawValue(EffectiveConfig config, String key) {
        String raw = RelaxedProperties.get(config.properties(), key);
        return raw == null || raw.isBlank() ? null : raw.strip();
    }

    /**
     * @param placeholderBefore a key that comes before this one in {@link #KEY_SOURCES} and is set to
     *                          an unresolved placeholder, or {@code null}
     */
    private void evaluateKey(String key, String rawValue, String placeholderBefore, EffectiveConfig config,
                             List<Finding> findings) {
        Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);

        if (resolved.isEmpty()) {
            String message = """
            Property '%s' relies on an unresolved placeholder '%s'. \
            Static analysis cannot verify whether an insecure protocol (HTTP) is used at runtime.\
            """.formatted(key, rawValue);

            findings.add(new Finding(
                    id(),
                    Severity.INFO,
                    message,
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
            return;
        }

        String resolvedValue = resolved.get().strip();
        if (resolvedValue.isBlank()) {
            // Placeholder resolved to empty (e.g. ${VAR:}): treated as unset
            return;
        }

        if (resolvedValue.toLowerCase(Locale.ROOT).startsWith(INSECURE_SCHEME)) {
            boolean isFromStaticDefault = !rawValue.equalsIgnoreCase(resolvedValue);
            String message = buildHighSeverityMessage(key, rawValue, isFromStaticDefault);
            if (placeholderBefore == null) {
                Finding finding = new Finding(id(), Severity.HIGH, message,
                        config.sourceFile().toString(), config.profileLabel());
                // Not issuer-uri: OIDC discovery fetches the keys from the jwks_uri the metadata names,
                // which may be on another host.
                boolean loopback = !key.equals(ISSUER_URI_KEY) && ConnectionHosts.allLoopback(rawValue);
                findings.add(loopback ? ConnectionHosts.onLoopback(finding) : finding);
            } else {
                findings.add(new Finding(id(), Severity.INFO,
                        message + " Used only if '%s', an unresolved placeholder, resolves empty at runtime."
                                .formatted(placeholderBefore),
                        config.sourceFile().toString(), config.profileLabel()));
            }
        }
    }

    private String buildHighSeverityMessage(String key, String rawValue, boolean isFromStaticDefault) {
        String baseMessage = """
            Insecure transport (HTTP) configured in '%s' (%s): the application fetches it in plain HTTP. \
            Whoever can read or rewrite that traffic can serve their own keys (or, for introspection, \
            read the client secret and answer that any token is active), so the application accepts \
            tokens they issue: authentication bypass.\
            """.formatted(key, rawValue);

        if (isFromStaticDefault) {
            return baseMessage + " Value originates from a static placeholder fallback.";
        }
        return baseMessage;
    }
}