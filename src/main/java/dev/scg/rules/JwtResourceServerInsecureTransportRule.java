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
 * SCG017 — detects HTTP used in OAuth2 Resource Server JWT transport ({@code issuer-uri} or
 * {@code jwk-set-uri}), checked independently since either one alone lets a network-positioned
 * attacker serve a forged JWKS (directly, or via OIDC discovery for {@code issuer-uri}) and sign
 * tokens the application accepts — authentication bypass, not just traffic interception. Always
 * {@link Severity#HIGH}.
 * <p>
 * Deliberately a dedicated rule rather than an addition to {@link InsecureDatabaseTransportRule}'s
 * (SCG012) {@code uri-based}/{@code risky-schemes} list: the same {@code http://} signal causes a
 * qualitatively different, more severe outcome here that a generic scheme scanner can't express in
 * its message or severity.
 * <p>
 * Plain {@link Rule}, not {@link ConfigurableRule}: the two target keys are a fixed, closed fact of
 * Spring Security's OAuth2 Resource Server support. Zero-Trust: checked regardless of active
 * profile.
 *
 * @see EnvironmentPlaceholder
 */
public final class JwtResourceServerInsecureTransportRule implements Rule {

    // A list, not a set: iterated to generate findings, in a fixed order.
    private static final List<String> TARGET_KEYS = List.of(
            "spring.security.oauth2.resourceserver.jwt.issuer-uri",
            "spring.security.oauth2.resourceserver.jwt.jwk-set-uri"
    );

    private static final String INSECURE_SCHEME = "http://";

    @Override
    public String id() {
        return "SCG017";
    }

    @Override
    public String description() {
        return "Insecure transport (HTTP) configured for OAuth2 Resource Server JWT endpoints";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        for (String key : TARGET_KEYS) {
            String rawValue = RelaxedProperties.get(config.properties(), key);
            if (rawValue == null || rawValue.isBlank()) {
                continue;
            }

            evaluateKey(key, rawValue.strip(), config, findings);
        }

        return findings;
    }

    private void evaluateKey(String key, String rawValue, EffectiveConfig config, List<Finding> findings) {
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
            // Placeholder resolved to empty (e.g. ${VAR:}) -> treats as unconfigured feature
            return;
        }

        if (resolvedValue.toLowerCase(Locale.ROOT).startsWith(INSECURE_SCHEME)) {
            boolean isFromStaticDefault = !rawValue.equalsIgnoreCase(resolvedValue);
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    buildHighSeverityMessage(key, rawValue, isFromStaticDefault),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }
    }

    private String buildHighSeverityMessage(String key, String rawValue, boolean isFromStaticDefault) {
        String baseMessage = """
            Insecure transport (HTTP) configured in '%s' (%s). \
            A network attacker can serve a forged JWKS, enabling them to issue valid tokens \
            and achieve complete authentication bypass.\
            """.formatted(key, rawValue);

        if (isFromStaticDefault) {
            return baseMessage + " Value originates from a static placeholder fallback.";
        }
        return baseMessage;
    }
}