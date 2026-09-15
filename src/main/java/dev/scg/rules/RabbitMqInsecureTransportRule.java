package dev.scg.rules;

import dev.scg.core.*;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * SCG015 — detects RabbitMQ connections left without TLS when expressed via
 * {@code spring.rabbitmq.host} or a scheme-less {@code spring.rabbitmq.addresses}
 * (plain {@code host:port}, no {@code amqp://}/{@code amqps://} prefix).
 * <p>
 * Confirmed against Spring Boot's own {@code RabbitProperties.Ssl.determineEnabled()}: SSL is
 * enabled only if {@code spring.rabbitmq.ssl.enabled=true}, or {@code spring.rabbitmq.ssl.bundle}
 * is set, or the first parsed address carries an explicit {@code amqps://} scheme — absence of
 * all three defaults to unencrypted. So, unlike this project's opt-in-by-default rules, absence
 * is not safe here: {@link #check(EffectiveConfig)} treats an unset/blank
 * {@code spring.rabbitmq.ssl.enabled} the same as an explicit {@code false}.
 * <p>
 * Deliberately complementary to, not overlapping with, {@link InsecureDatabaseTransportRule}
 * (SCG012)'s {@code risky-schemes} mechanism: when {@code addresses} itself carries an
 * {@code amqp://}/{@code amqps://} prefix, the scheme alone determines Spring's TLS decision
 * (SCG012 already flags {@code amqp://}; {@code amqps://} is inherently secure), so this rule
 * defers entirely in that case rather than duplicating or second-guessing SCG012 based on
 * {@code ssl.enabled}, which Spring ignores once a scheme is present.
 * <p>
 * Severity {@link Severity#HIGH}: the AMQP handshake itself carries the broker credentials, so
 * an unencrypted connection exposes both those credentials and message payloads to anyone with
 * network visibility — the same risk class as SCG012/SCG014. No profile exemption (Zero-Trust).
 * Plain {@link Rule}: the property keys are fixed facts of Spring AMQP's binding, not
 * organization-specific.
 */
public final class RabbitMqInsecureTransportRule implements Rule {

    private static final String RULE_NAME = "SCG015";

    private static final String HOST_KEY = "spring.rabbitmq.host";
    private static final String ADDRESSES_KEY = "spring.rabbitmq.addresses";
    private static final String SSL_ENABLED_KEY = "spring.rabbitmq.ssl.enabled";
    private static final String SSL_BUNDLE_KEY = "spring.rabbitmq.ssl.bundle";

    private static final Set<String> TRUTHY_VALUES = Set.of("true", "yes", "on", "1");

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
        String addressesRaw = RelaxedProperties.get(config.properties(), ADDRESSES_KEY);

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

        String bundleRaw = RelaxedProperties.get(config.properties(), SSL_BUNDLE_KEY);
        if (bundleRaw != null && !bundleRaw.isBlank()) {
            return List.of();
        }

        return evaluateSslEnabled(config, RelaxedProperties.get(config.properties(), SSL_ENABLED_KEY));
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
        if (TRUTHY_VALUES.contains(value.toLowerCase(Locale.ROOT))) {
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

    private Finding notConfiguredFinding(EffectiveConfig config) {
        return new Finding(
                id(),
                Severity.HIGH,
                ("RabbitMQ is configured via '%s'/'%s', but '%s' is not explicitly set. " +
                        "Spring Boot defaults to an unencrypted connection unless SSL is explicitly enabled " +
                        "(or an SSL bundle is configured). Set '%s' to 'true'.")
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
