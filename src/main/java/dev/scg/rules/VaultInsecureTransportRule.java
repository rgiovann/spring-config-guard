package dev.scg.rules;

import dev.scg.core.*;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * SCG016 — detects an explicitly insecure transport scheme for HashiCorp Vault:
 * {@code spring.cloud.vault.scheme=http}, or {@code spring.cloud.vault.uri} starting with
 * {@code http://}.
 * <p>
 * Confirmed against Spring Cloud Vault's own {@code VaultProperties} source: {@code scheme}
 * defaults to {@code "https"} and {@code uri} is {@code @Nullable}. Unlike this project's
 * absence-is-insecure rules (SCG014/SCG015), absence here is safe — {@link #check(EffectiveConfig)}
 * only fires on an explicit opt-out.
 * <p>
 * {@code uri}, when present and non-blank after placeholder resolution, takes precedence over
 * {@code scheme} entirely — that's Spring Cloud Vault's own real precedence (the URI's own scheme
 * governs, not the separate {@code scheme} property), so this rule checks {@code uri} first and
 * only falls back to evaluating {@code scheme} when {@code uri} is absent or resolves to blank
 * (functionally the same as absent). Deliberately a dedicated rule rather than an addition to
 * {@link InsecureDatabaseTransportRule} (SCG012): {@code scheme} is a bare word
 * ({@code "http"}/{@code "https"}), not a URI, so SCG012's {@code risky-schemes} prefix-matching
 * mechanism has no way to evaluate it, and SCG012 has no concept of one property overriding
 * another the way {@code uri} overrides {@code scheme} here.
 * <p>
 * Severity {@link Severity#HIGH}: Vault carries the application's own bootstrap secrets, so an
 * unencrypted connection exposes those secrets in transit — same risk class as SCG007/SCG012. No
 * profile exemption (Zero-Trust). Plain {@link Rule}: both property keys are fixed facts of
 * Spring Cloud Vault's binding, not organization-specific.
 */
public final class VaultInsecureTransportRule implements Rule {

    private static final String RULE_NAME = "SCG016";

    private static final String SCHEME_KEY = "spring.cloud.vault.scheme";
    private static final String URI_KEY = "spring.cloud.vault.uri";

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "HashiCorp Vault connection using an unencrypted (http) transport scheme";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        String uriRaw = RelaxedProperties.get(config.properties(), URI_KEY);

        if (uriRaw != null && !uriRaw.isBlank()) {
            return evaluateUri(config, uriRaw);
        }

        return evaluateScheme(config, RelaxedProperties.get(config.properties(), SCHEME_KEY));
    }

    private List<Finding> evaluateUri(EffectiveConfig config, String uriRaw) {
        Optional<String> resolved = EnvironmentPlaceholder.resolve(uriRaw.strip());
        if (resolved.isEmpty()) {
            return List.of(infoFinding(config, URI_KEY, uriRaw));
        }

        String value = resolved.get().strip();
        if (value.isBlank()) {
            // uri effectively unset at runtime -- Spring Cloud Vault falls back to the
            // scheme/host/port properties, so the TLS decision falls back too.
            return evaluateScheme(config, RelaxedProperties.get(config.properties(), SCHEME_KEY));
        }

        if (value.toLowerCase(Locale.ROOT).startsWith("http://")) {
            return List.of(insecureUriFinding(config, uriRaw));
        }

        return List.of();
    }

    private List<Finding> evaluateScheme(EffectiveConfig config, String schemeRaw) {
        if (schemeRaw == null || schemeRaw.isBlank()) {
            return List.of(); // absent -- default 'https' applies
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(schemeRaw.strip());
        if (resolved.isEmpty()) {
            return List.of(infoFinding(config, SCHEME_KEY, schemeRaw));
        }

        String value = resolved.get().strip();
        if (value.isBlank()) {
            return List.of(); // blank resolved value -- same as absent -- default 'https' applies
        }

        if ("http".equalsIgnoreCase(value)) {
            return List.of(insecureSchemeFinding(config, schemeRaw));
        }

        return List.of();
    }

    private Finding infoFinding(EffectiveConfig config, String key, String rawValue) {
        return new Finding(
                id(),
                Severity.INFO,
                ("Vault property '%s' relies on an unresolved environment placeholder '%s'. " +
                        "Static analysis cannot verify whether TLS transport security is enforced at runtime.")
                        .formatted(key, rawValue),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }

    private Finding insecureUriFinding(EffectiveConfig config, String rawUri) {
        return new Finding(
                id(),
                Severity.HIGH,
                ("'%s=%s' connects to Vault over an unencrypted transport. Vault brokers the application's " +
                        "own bootstrap secrets, so an unencrypted connection exposes them to anyone with " +
                        "network visibility. Use an 'https://' URI.")
                        .formatted(URI_KEY, rawUri),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }

    private Finding insecureSchemeFinding(EffectiveConfig config, String rawScheme) {
        return new Finding(
                id(),
                Severity.HIGH,
                ("'%s=%s' connects to Vault over an unencrypted transport. Vault brokers the application's " +
                        "own bootstrap secrets, so an unencrypted connection exposes them to anyone with " +
                        "network visibility. Set '%s' to 'https'.")
                        .formatted(SCHEME_KEY, rawScheme, SCHEME_KEY),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }
}
