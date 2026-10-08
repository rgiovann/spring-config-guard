package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * SCG015 — detects RabbitMQ connections left without TLS when expressed via
 * {@code spring.rabbitmq.host} or a scheme-less {@code spring.rabbitmq.addresses}
 * (plain {@code host:port}, no {@code amqp://}/{@code amqps://} prefix), written as one value or
 * as a list.
 * <p>
 * Confirmed against Spring Boot 4.1.1's {@code RabbitProperties.Ssl.determineEnabled()} and on the
 * wire, with a listener recording whether the client spoke plain AMQP or started a TLS handshake
 * (VALIDATION.md, "SCG015 RabbitMQ transport scenarios"): TLS is on only if
 * {@code spring.rabbitmq.ssl.enabled} is true ({@code true}, {@code yes}, ... — it is bound through
 * the Binder), or {@code spring.rabbitmq.ssl.bundle} has text ({@code StringUtils.hasText}: a
 * placeholder that resolves empty, {@code ${BUNDLE:}}, left it off, and the client spoke plain
 * AMQP; one without a default is INFO, since the bundle may be set at runtime); with
 * {@code addresses}, the scheme of the first address, when it has one, overrides both
 * ({@code amqps://} on, {@code amqp://} off).
 * Absence of all of them connected in plain AMQP. So, unlike this project's opt-in-by-default
 * rules, absence is not safe here: {@link #check(EffectiveConfig)} treats an unset/blank
 * {@code spring.rabbitmq.ssl.enabled} like an explicit {@code false}, one level lower (ADR-010).
 * Only the first address counts, so a list written in YAML ({@code addresses[0]}, ...) is read by
 * its first entry, and a comma-separated value by its start.
 * <p>
 * Deliberately complementary to, not overlapping with, {@link InsecureDatabaseTransportRule}
 * (SCG012)'s {@code risky-schemes} mechanism: when {@code addresses} itself carries an
 * {@code amqp://}/{@code amqps://} prefix, the scheme alone determines Spring's TLS decision
 * (SCG012 already flags {@code amqp://}; {@code amqps://} is inherently secure), so this rule
 * defers entirely in that case rather than duplicating or second-guessing SCG012 based on
 * {@code ssl.enabled}, which Spring ignores once a scheme is present.
 * <p>
 * Severity {@link Severity#HIGH} for an explicit {@code ssl.enabled=false}: the AMQP handshake
 * itself carries the broker credentials (the RabbitMQ Java client's default SASL mechanism is
 * {@code PLAIN}, which sends the user name and password as they are), so an unencrypted connection exposes both those
 * credentials and message payloads to anyone with network visibility — the same risk class as
 * SCG012/SCG014. {@link Severity#MEDIUM} when SSL is only not enabled: the same default applies,
 * but TLS may be enabled outside the scanned files (ARCHITECTURE.md, ADR-010). Either is
 * {@link Severity#INFO} when every broker is a loopback address ({@link ConnectionHosts}). No
 * profile exemption (Zero-Trust).
 * <p>
 * A connection that uses TLS but doesn't verify the broker is reported too (CWE-295), measured on
 * the wire with Spring AMQP 4.1.1 (VALIDATION.md, "TLS without server verification (Kafka and
 * RabbitMQ)"): {@code spring.rabbitmq.ssl.verify-hostname} false turns the host name check off,
 * with a trust store, a bundle or an {@code amqps://} address alike, and leaves the trust check on;
 * {@code spring.rabbitmq.ssl.validate-server-certificate} false accepts any server, but only when no
 * key store, trust store or bundle is set, since {@code RabbitConnectionFactoryBean.setUpSSL()}
 * ignores it otherwise ({@link #verificationFindings}). TLS is on with {@code ssl.enabled} true, a
 * bundle, or an {@code amqps://} first address; without TLS both are silent, the plaintext finding
 * covering the connection. {@link Severity#MEDIUM}, as SCG012 reports a connection URL that turns
 * certificate checks off: the traffic is encrypted, and reading it takes an active man in the
 * middle. {@link Severity#INFO} for an unresolved placeholder, or when whether TLS is on, or whether
 * a store is set, depends on one. Unlike the plaintext check, these don't need {@code host} or
 * {@code addresses}: a broker set elsewhere is still verified, or not, by these keys.
 * <p>
 * Plain {@link Rule}: the property keys are fixed facts of Spring AMQP's binding, not
 * organization-specific.
 */
public final class RabbitMqInsecureTransportRule implements Rule {

    private static final String RULE_NAME = "SCG015";

    private static final String HOST_KEY = "spring.rabbitmq.host";
    private static final String ADDRESSES_KEY = "spring.rabbitmq.addresses";
    private static final String SSL_ENABLED_KEY = "spring.rabbitmq.ssl.enabled";
    private static final String SSL_BUNDLE_KEY = "spring.rabbitmq.ssl.bundle";
    private static final String VERIFY_HOSTNAME_KEY = "spring.rabbitmq.ssl.verify-hostname";
    private static final String VALIDATE_CERTIFICATE_KEY = "spring.rabbitmq.ssl.validate-server-certificate";
    private static final List<String> STORE_KEYS = List.of("spring.rabbitmq.ssl.key-store", "spring.rabbitmq.ssl.trust-store");

    /** Whether the connection uses TLS; UNKNOWN when it depends on an unresolved placeholder. */
    private enum Tls { OFF, UNKNOWN, ON }

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "RabbitMQ connection (host/port form) without TLS transport encryption enabled, or with TLS "
                + "that doesn't verify the broker";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>(transportFindings(config));
        findings.addAll(verificationFindings(config));
        return loopbackOnly(config.properties(), RelaxedProperties.get(config.properties(), HOST_KEY))
                ? findings.stream().map(ConnectionHosts::onLoopback).toList()
                : findings;
    }

    /** The plaintext check: a {@code host} or scheme-less {@code addresses} without TLS. */
    private List<Finding> transportFindings(EffectiveConfig config) {
        String hostRaw = RelaxedProperties.get(config.properties(), HOST_KEY);
        String addressesRaw = firstAddresses(config.properties());

        boolean hostConfigured = hostRaw != null && !hostRaw.isBlank();
        boolean addressesConfigured = addressesRaw != null && !addressesRaw.isBlank();

        if (!hostConfigured && !addressesConfigured) {
            return List.of();
        }

        if (addressesConfigured && carriesExplicitScheme(addressesRaw)) {
            // The address's own scheme governs Spring's TLS decision regardless of
            // ssl.enabled; amqp:// is SCG012's concern, amqps:// is already secure.
            return List.of();
        }

        String enabledRaw = RelaxedProperties.get(config.properties(), SSL_ENABLED_KEY);
        String bundleRaw = RelaxedProperties.get(config.properties(), SSL_BUNDLE_KEY);
        if (bundleRaw != null && !bundleRaw.isBlank()) {
            Optional<String> bundle = EnvironmentPlaceholder.resolve(bundleRaw.strip());
            if (bundle.isPresent() && !bundle.get().isBlank()) {
                return List.of(); // a bundle turns TLS on, whatever ssl.enabled says
            }
            if (bundle.isEmpty() && !resolvesTrue(enabledRaw)) {
                return List.of(new Finding(
                        id(),
                        Severity.INFO,
                        ("RabbitMQ property '%s' relies on an unresolved environment placeholder '%s'. TLS is on " +
                                "only if it resolves to a bundle name (or '%s' is true); static analysis cannot " +
                                "verify that.")
                                .formatted(SSL_BUNDLE_KEY, bundleRaw, SSL_ENABLED_KEY),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }

        return evaluateSslEnabled(config, enabledRaw);
    }

    /**
     * The verification check: {@code verify-hostname} or {@code validate-server-certificate} set to
     * a false literal on a connection that uses TLS.
     */
    private List<Finding> verificationFindings(EffectiveConfig config) {
        Map<String, String> properties = config.properties();
        Tls tls = tls(properties);
        if (tls == Tls.OFF) {
            return List.of(); // no certificate to check; the plaintext finding covers the connection
        }
        List<Finding> findings = new ArrayList<>();
        String verifyRaw = RelaxedProperties.get(properties, VERIFY_HOSTNAME_KEY);
        disabled(verifyRaw).ifPresent(resolved -> findings.add(resolved
                ? verificationFinding(config, tls, verifyRaw, VERIFY_HOSTNAME_KEY,
                        "turns off the RabbitMQ client's check that the broker's certificate matches its host name: "
                                + "the connection uses TLS, but any certificate the client trusts is accepted for any "
                                + "broker, so a man in the middle holding one can read and change the traffic, "
                                + "credentials included (CWE-295). Remove the property, or set it to 'true'.", null)
                : unresolvedFinding(config, VERIFY_HOSTNAME_KEY, verifyRaw)));

        String validateRaw = RelaxedProperties.get(properties, VALIDATE_CERTIFICATE_KEY);
        disabled(validateRaw).ifPresent(resolved -> {
            Tls stores = storesSet(properties);
            if (stores == Tls.ON) {
                return; // Spring AMQP builds the trust managers from the stores and ignores the property
            }
            if (!resolved) {
                findings.add(unresolvedFinding(config, VALIDATE_CERTIFICATE_KEY, validateRaw));
                return;
            }
            findings.add(verificationFinding(config, tls, validateRaw, VALIDATE_CERTIFICATE_KEY,
                    "makes the RabbitMQ client accept any server certificate, untrusted or for another host, since "
                            + "no key store, trust store or SSL bundle is set: the connection uses TLS, but a man in "
                            + "the middle can read and change the traffic, credentials included (CWE-295). Remove the "
                            + "property, and trust the broker's certificate authority with 'spring.rabbitmq.ssl.trust-store' "
                            + "or an SSL bundle.",
                    stores == Tls.UNKNOWN ? "a key store, trust store or bundle is an unresolved placeholder, and "
                            + "Spring AMQP ignores the property when one is set" : null));
        });
        return findings;
    }

    /**
     * Whether the connection uses TLS: an {@code amqps://} first address turns it on and
     * {@code amqp://} off, whatever else is set; otherwise a bundle with text or {@code ssl.enabled}
     * true turns it on. UNKNOWN when it depends on an unresolved placeholder.
     */
    private static Tls tls(Map<String, String> properties) {
        String addressesRaw = firstAddresses(properties);
        if (addressesRaw != null && !addressesRaw.isBlank()) {
            Optional<String> resolved = EnvironmentPlaceholder.resolve(addressesRaw.strip());
            if (resolved.isPresent()) {
                String address = resolved.get().strip().toLowerCase(Locale.ROOT);
                if (address.startsWith("amqps://")) {
                    return Tls.ON;
                }
                if (address.startsWith("amqp://")) {
                    return Tls.OFF;
                }
            }
        }
        Tls bundle = hasText(RelaxedProperties.get(properties, SSL_BUNDLE_KEY));
        if (bundle == Tls.ON) {
            return Tls.ON;
        }
        String enabledRaw = RelaxedProperties.get(properties, SSL_ENABLED_KEY);
        Tls enabled = Tls.OFF;
        if (enabledRaw != null && !enabledRaw.isBlank()) {
            Optional<String> resolved = EnvironmentPlaceholder.resolve(enabledRaw.strip());
            enabled = resolved.isEmpty() ? Tls.UNKNOWN
                    : RelaxedBoolean.isTrueLiteral(resolved.get().strip()) ? Tls.ON : Tls.OFF;
        }
        if (enabled == Tls.ON) {
            return Tls.ON;
        }
        return bundle == Tls.UNKNOWN || enabled == Tls.UNKNOWN ? Tls.UNKNOWN : Tls.OFF;
    }

    /** Whether a key store, a trust store or a bundle is set: ON when one has text, UNKNOWN for a placeholder. */
    private static Tls storesSet(Map<String, String> properties) {
        Tls result = hasText(RelaxedProperties.get(properties, SSL_BUNDLE_KEY));
        for (String key : STORE_KEYS) {
            Tls store = hasText(RelaxedProperties.get(properties, key));
            if (store.compareTo(result) > 0) {
                result = store;
            }
        }
        return result;
    }

    /** ON when the value has text, as Spring's {@code StringUtils.hasText} reads it; UNKNOWN for an unresolved placeholder. */
    private static Tls hasText(String raw) {
        if (raw == null || raw.isBlank()) {
            return Tls.OFF;
        }
        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            return Tls.UNKNOWN;
        }
        return resolved.get().isBlank() ? Tls.OFF : Tls.ON;
    }

    /**
     * Empty when the value doesn't turn the check off (unset, blank, true, anything Spring wouldn't
     * read as false); true when it resolves to a false literal; false when it is an unresolved
     * placeholder, which may.
     */
    private static Optional<Boolean> disabled(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            return Optional.of(false);
        }
        return RelaxedBoolean.isFalseLiteral(resolved.get().strip()) ? Optional.of(true) : Optional.empty();
    }

    private Finding verificationFinding(EffectiveConfig config, Tls tls, String raw, String key, String consequence,
                                        String storeDoubt) {
        String message = "'%s=%s' %s".formatted(key, raw, consequence);
        if (raw.contains("${")) {
            message += " The value originates from a static placeholder default ('%s').".formatted(raw);
        }
        Severity severity = Severity.MEDIUM;
        if (tls == Tls.UNKNOWN) {
            severity = Severity.INFO;
            message += " Reported as INFO because whether the connection uses TLS depends on an unresolved placeholder.";
        } else if (storeDoubt != null) {
            severity = Severity.INFO;
            message += " Reported as INFO because " + storeDoubt + ".";
        }
        return new Finding(id(), severity, message, config.sourceFile().toString(), config.profileLabel());
    }

    private Finding unresolvedFinding(EffectiveConfig config, String key, String raw) {
        return new Finding(
                id(),
                Severity.INFO,
                ("RabbitMQ property '%s' relies on an unresolved environment placeholder '%s'. If it resolves to " +
                        "false, the client doesn't fully verify the broker's certificate (CWE-295); static analysis " +
                        "cannot verify the runtime value.").formatted(key, raw),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }

    /**
     * Whether every broker the client connects to is a loopback address: every entry of
     * {@code addresses} when it is set (Spring Boot fails over to the others), else {@code host}, as
     * written. False when a value can't be read or holds a placeholder.
     */
    private static boolean loopbackOnly(Map<String, String> properties, String hostRaw) {
        List<String> addresses = new ArrayList<>();
        for (String raw : RelaxedProperties.valuesForKeyOrListChildren(properties, ADDRESSES_KEY)) {
            if (raw != null && !raw.isBlank()) {
                addresses.add(raw.strip());
            }
        }
        if (!addresses.isEmpty()) {
            return ConnectionHosts.allLoopback(String.join(",", addresses));
        }
        return ConnectionHosts.allLoopback(hostRaw);
    }

    private static boolean resolvesTrue(String raw) {
        return raw != null && EnvironmentPlaceholder.resolve(raw.strip())
                .filter(RelaxedBoolean::isTrueLiteral)
                .isPresent();
    }

    /**
     * The {@code addresses} value Spring Boot takes its first address from: the value itself, or,
     * for a list ({@code addresses[0]}, {@code addresses[1]}, ...), the entry with the lowest index,
     * whatever order the keys come in.
     */
    private static String firstAddresses(Map<String, String> properties) {
        String scalar = RelaxedProperties.get(properties, ADDRESSES_KEY);
        if (scalar != null) {
            return scalar;
        }
        String listPrefix = RelaxedProperties.canonicalize(ADDRESSES_KEY) + "[";
        String first = null;
        int lowest = Integer.MAX_VALUE;
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            String canonical = RelaxedProperties.canonicalize(entry.getKey());
            if (!canonical.startsWith(listPrefix) || !canonical.endsWith("]")) {
                continue;
            }
            String index = canonical.substring(listPrefix.length(), canonical.length() - 1);
            if (!index.isEmpty() && index.length() <= 9 && index.chars().allMatch(Character::isDigit)
                    && Integer.parseInt(index) < lowest) {
                lowest = Integer.parseInt(index);
                first = entry.getValue();
            }
        }
        return first;
    }

    private boolean carriesExplicitScheme(String addressesRaw) {
        Optional<String> resolved = EnvironmentPlaceholder.resolve(addressesRaw.strip());
        String valueToInspect = resolved.orElse(addressesRaw).strip().toLowerCase(Locale.ROOT);
        return valueToInspect.startsWith("amqp://") || valueToInspect.startsWith("amqps://");
    }

    private List<Finding> evaluateSslEnabled(EffectiveConfig config, String rawEnabled) {
        if (rawEnabled == null || rawEnabled.isBlank()) {
            return List.of(notConfiguredFinding(config));
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(rawEnabled.strip());
        if (resolved.isEmpty()) {
            return List.of(new Finding(
                    id(),
                    Severity.INFO,
                    ("RabbitMQ property '%s' relies on an unresolved environment placeholder '%s'. " +
                            "Static analysis cannot verify whether TLS transport security is enforced at runtime.")
                            .formatted(SSL_ENABLED_KEY, rawEnabled),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }

        String value = resolved.get().strip();
        if (RelaxedBoolean.isTrueLiteral(value)) {
            return List.of();
        }

        // A blank resolved value (e.g. a placeholder default of "${VAR:}") carries no explicit
        // opt-in, same as the key being absent entirely -- both fall through to Spring's
        // insecure-by-default behavior, not a distinct state worth its own message.
        if (value.isBlank()) {
            return List.of(notConfiguredFinding(config));
        }

        return List.of(explicitlyDisabledFinding(config, rawEnabled));
    }

    /**
     * MEDIUM, not HIGH like an explicit {@code ssl.enabled=false}: the default is unencrypted, but
     * TLS may be enabled outside these files, through an environment variable SCG can't see
     * (ARCHITECTURE.md, ADR-010).
     */
    private Finding notConfiguredFinding(EffectiveConfig config) {
        return new Finding(
                id(),
                Severity.MEDIUM,
                ("RabbitMQ is configured via '%s'/'%s', but '%s' is not explicitly set. " +
                        "Spring Boot defaults to an unencrypted connection unless SSL is explicitly enabled " +
                        "(or an SSL bundle is configured). Set '%s' to 'true'. Reported as MEDIUM because " +
                        "SSL may be enabled outside these files, e.g. by an environment variable.")
                        .formatted(HOST_KEY, ADDRESSES_KEY, SSL_ENABLED_KEY, SSL_ENABLED_KEY),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }

    private Finding explicitlyDisabledFinding(EffectiveConfig config, String rawEnabled) {
        return new Finding(
                id(),
                Severity.HIGH,
                ("'%s=%s' leaves the RabbitMQ connection unencrypted. The AMQP handshake carries broker " +
                        "credentials in the clear, exposing both credentials and message payloads to anyone " +
                        "with network visibility. Set '%s' to 'true'.")
                        .formatted(SSL_ENABLED_KEY, rawEnabled, SSL_ENABLED_KEY),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }
}
