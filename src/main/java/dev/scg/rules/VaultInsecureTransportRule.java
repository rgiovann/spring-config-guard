package dev.scg.rules;

import dev.scg.core.*;

import java.util.List;
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
 * Measured on the wire with Spring Cloud 2025.1.3 (Spring Boot 4.0.8, Spring Cloud Vault 5.0.2),
 * with a listener on Vault's port recording whether the client spoke plain HTTP or started a TLS
 * handshake (VALIDATION.md, "SCG016 Vault transport scenarios"): with {@code scheme=http} or an
 * {@code http://} {@code uri}, the request carried the Vault token in the clear. The scheme is
 * compared case-sensitively, as Spring Cloud Vault does: {@code HTTP}, {@code HTTP://} or an empty
 * {@code scheme} stopped the application from starting ("Scheme must be http or https"), so they
 * are silent. {@code spring.cloud.vault.enabled=false} turned the client off, with no connection
 * made, so it is silent too.
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
 * unencrypted connection exposes those secrets in transit — same risk class as SCG007/SCG012.
 * {@link Severity#INFO} when the server is a loopback address written literally in {@code uri} or
 * {@code host} ({@link ConnectionHosts}), unless Vault is located through service discovery;
 * {@code host}'s default, {@code localhost}, doesn't count, since it is often set outside the
 * files. No profile exemption (Zero-Trust). Plain {@link Rule}: both property keys are fixed facts of
 * Spring Cloud Vault's binding, not organization-specific.
 */
public final class VaultInsecureTransportRule implements Rule {

    private static final String RULE_NAME = "SCG016";

    private static final String SCHEME_KEY = "spring.cloud.vault.scheme";
    private static final String URI_KEY = "spring.cloud.vault.uri";
    private static final String HOST_KEY = "spring.cloud.vault.host";
    private static final String DISCOVERY_ENABLED_KEY = "spring.cloud.vault.discovery.enabled";
    private static final String ENABLED_KEY = "spring.cloud.vault.enabled";

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
        String enabledRaw = RelaxedProperties.get(config.properties(), ENABLED_KEY);
        if (enabledRaw != null && EnvironmentPlaceholder.resolve(enabledRaw.strip())
                .filter(RelaxedBoolean::isFalseLiteral).isPresent()) {
            return List.of(); // Spring Cloud Vault turned off: no connection is made
        }

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

        if (value.startsWith("http://")) { // case-sensitive, as Spring Cloud Vault parses it
            Finding finding = insecureUriFinding(config, uriRaw);
            return List.of(ConnectionHosts.allLoopback(uriRaw) && !usesDiscovery(config)
                    ? ConnectionHosts.onLoopback(finding) : finding);
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
            return List.of(); // blank: the application doesn't start ("Scheme must be http or https")
        }

        if ("http".equals(value)) { // case-sensitive: "HTTP" stops the application from starting
            Finding finding = insecureSchemeFinding(config, schemeRaw);
            boolean loopback = ConnectionHosts.allLoopback(RelaxedProperties.get(config.properties(), HOST_KEY))
                    && !usesDiscovery(config);
            return List.of(loopback ? ConnectionHosts.onLoopback(finding) : finding);
        }

        return List.of();
    }

    /**
     * Whether Vault may be located through service discovery ({@code discovery.enabled} not a false
     * literal), in which case the server isn't the one {@code uri} or {@code host} names.
     */
    private static boolean usesDiscovery(EffectiveConfig config) {
        String raw = RelaxedProperties.get(config.properties(), DISCOVERY_ENABLED_KEY);
        return raw != null && !raw.isBlank()
                && EnvironmentPlaceholder.resolve(raw.strip()).filter(RelaxedBoolean::isFalseLiteral).isEmpty();
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
