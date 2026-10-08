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
 * The same applies to an OAuth2 Client's provider ({@code spring.security.oauth2.client.provider.<name>.*},
 * {@link #checkClientProviders}): an {@code http://} {@code token-uri} receives the client secret in
 * the clear, with {@code client_secret_basic} and {@code client_secret_post} alike, and
 * {@code issuer-uri} is fetched at startup to discover the provider's endpoints, so whoever answers
 * can name the token endpoint the secret is sent to (VALIDATION.md, "OAuth2 Client provider
 * transport scenarios"). Both are used, each for its own purpose ({@code token-uri} overrides the
 * discovered endpoint), so each is evaluated on its own, with the same severities: {@link Severity#HIGH},
 * INFO for an unresolved placeholder or a loopback {@code token-uri}. Not checked:
 * {@code jwk-set-uri} and {@code user-info-uri}, used only in a login flow that wasn't measured, and
 * {@code authorization-uri}, which the user's browser visits, not the application.
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
public final class OAuth2InsecureTransportRule implements Rule {

    private static final String ISSUER_URI_KEY = "spring.security.oauth2.resourceserver.jwt.issuer-uri";
    private static final String JWK_SET_URI_KEY = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri";
    private static final String PUBLIC_KEY_LOCATION_KEY = "spring.security.oauth2.resourceserver.jwt.public-key-location";
    private static final String INTROSPECTION_URI_KEY = "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri";

    /** Where the JWT keys come from, in Spring Boot's order of precedence. */
    private static final List<String> KEY_SOURCES =
            List.of(JWK_SET_URI_KEY, ISSUER_URI_KEY, PUBLIC_KEY_LOCATION_KEY);

    private static final String INSECURE_SCHEME = "http://";

    private static final String CLIENT_PROVIDER_PREFIX =
            RelaxedProperties.canonicalize("spring.security.oauth2.client.provider.");
    private static final String CLIENT_TOKEN_URI = RelaxedProperties.canonicalize("token-uri");
    private static final String CLIENT_ISSUER_URI = RelaxedProperties.canonicalize("issuer-uri");

    private static final String RESOURCE_SERVER_CONSEQUENCE = """
            the application fetches it in plain HTTP. Whoever can read or rewrite that traffic can serve their own keys (or, for introspection, \
            read the client secret and answer that any token is active), so the application accepts \
            tokens they issue: authentication bypass.\
            """;
    private static final String CLIENT_TOKEN_CONSEQUENCE = """
            the OAuth2 client sends its client secret there in plain HTTP, so whoever can read that traffic gets the \
            secret, and the tokens issued for it, and can obtain tokens as this client.\
            """;
    private static final String CLIENT_ISSUER_CONSEQUENCE = """
            the OAuth2 client discovers its provider's endpoints there at startup, in plain HTTP, so whoever can \
            rewrite that traffic can name the token endpoint the client sends its secret to.\
            """;

    @Override
    public String id() {
        return "SCG017";
    }

    @Override
    public String description() {
        return "Insecure transport (HTTP) configured for OAuth2 Resource Server token validation endpoints, "
                + "or for an OAuth2 Client provider's token and issuer URIs";
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
            evaluateKey(key, rawValue, placeholderBefore, key.equals(ISSUER_URI_KEY), RESOURCE_SERVER_CONSEQUENCE,
                    config, findings);
            if (resolved.isPresent()) {
                break;
            }
            if (placeholderBefore == null) {
                placeholderBefore = key;
            }
        }

        String introspectionUri = rawValue(config, INTROSPECTION_URI_KEY);
        if (introspectionUri != null) {
            evaluateKey(INTROSPECTION_URI_KEY, introspectionUri, null, false, RESOURCE_SERVER_CONSEQUENCE,
                    config, findings);
        }
        checkClientProviders(config, findings);
        return findings;
    }

    /**
     * Each OAuth2 Client provider's {@code token-uri} and {@code issuer-uri}, under the key as
     * written. Spring Boot uses both when both are set, so neither hides the other.
     */
    private void checkClientProviders(EffectiveConfig config, List<Finding> findings) {
        config.properties().forEach((writtenKey, value) -> {
            String canonical = RelaxedProperties.canonicalize(writtenKey);
            if (!canonical.startsWith(CLIENT_PROVIDER_PREFIX) || value == null || value.isBlank()) {
                return;
            }
            String rest = canonical.substring(CLIENT_PROVIDER_PREFIX.length());
            int dot = rest.indexOf('.');
            if (dot <= 0) {
                return;
            }
            String setting = rest.substring(dot + 1);
            if (setting.equals(CLIENT_TOKEN_URI)) {
                evaluateKey(writtenKey, value.strip(), null, false, CLIENT_TOKEN_CONSEQUENCE, config, findings);
            } else if (setting.equals(CLIENT_ISSUER_URI)) {
                evaluateKey(writtenKey, value.strip(), null, true, CLIENT_ISSUER_CONSEQUENCE, config, findings);
            }
        });
    }

    /** The value stripped, or {@code null} when the key is absent or blank. */
    private static String rawValue(EffectiveConfig config, String key) {
        String raw = RelaxedProperties.get(config.properties(), key);
        return raw == null || raw.isBlank() ? null : raw.strip();
    }

    /**
     * @param placeholderBefore a key that comes before this one in {@link #KEY_SOURCES} and is set to
     *                          an unresolved placeholder, or {@code null}
     * @param issuer            whether the key is an issuer URI, which isn't lowered on a loopback host:
     *                          the metadata it serves may name endpoints on another host
     * @param consequence       what plain HTTP there lets an attacker do
     */
    private void evaluateKey(String key, String rawValue, String placeholderBefore, boolean issuer, String consequence,
                             EffectiveConfig config, List<Finding> findings) {
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
            String message = buildHighSeverityMessage(key, rawValue, isFromStaticDefault, consequence);
            if (placeholderBefore == null) {
                Finding finding = new Finding(id(), Severity.HIGH, message,
                        config.sourceFile().toString(), config.profileLabel());
                // Not an issuer URI: discovery fetches the endpoints the metadata names, which may be on
                // another host.
                boolean loopback = !issuer && ConnectionHosts.allLoopback(rawValue);
                findings.add(loopback ? ConnectionHosts.onLoopback(finding) : finding);
            } else {
                findings.add(new Finding(id(), Severity.INFO,
                        message + " Used only if '%s', an unresolved placeholder, resolves empty at runtime."
                                .formatted(placeholderBefore),
                        config.sourceFile().toString(), config.profileLabel()));
            }
        }
    }

    private String buildHighSeverityMessage(String key, String rawValue, boolean isFromStaticDefault,
                                            String consequence) {
        String baseMessage = "Insecure transport (HTTP) configured in '%s' (%s): %s".formatted(key, rawValue, consequence);

        if (isFromStaticDefault) {
            return baseMessage + " Value originates from a static placeholder fallback.";
        }
        return baseMessage;
    }
}