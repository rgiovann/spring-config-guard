package dev.scg.rules;

import dev.scg.core.*;

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
 * but TLS may be enabled outside the scanned files (ARCHITECTURE.md, ADR-010). No profile
 * exemption (Zero-Trust).
 * Plain {@link Rule}: the property keys are fixed facts of Spring AMQP's binding, not
 * organization-specific.
 */
public final class RabbitMqInsecureTransportRule implements Rule {

    private static final String RULE_NAME = "SCG015";

    private static final String HOST_KEY = "spring.rabbitmq.host";
    private static final String ADDRESSES_KEY = "spring.rabbitmq.addresses";
    private static final String SSL_ENABLED_KEY = "spring.rabbitmq.ssl.enabled";
    private static final String SSL_BUNDLE_KEY = "spring.rabbitmq.ssl.bundle";

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "RabbitMQ connection (host/port form) without TLS transport encryption enabled";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
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
