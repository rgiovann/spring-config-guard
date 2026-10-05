package dev.scg.rules;

import dev.scg.core.ConfigLoader;
import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers SCG015's evidence gate ({@code host}/{@code addresses} presence), the
 * {@code ssl.enabled}/{@code ssl.bundle} decision (including the three placeholder states), and
 * the deference to SCG012 when {@code addresses} carries an explicit {@code amqp://}/{@code amqps://}
 * scheme — including {@code addresses} taking precedence over {@code host} when both are set, and
 * case-insensitive scheme detection.
 */
class RabbitMqInsecureTransportRuleTest {

    private final RabbitMqInsecureTransportRule rule = new RabbitMqInsecureTransportRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");
    private static final String HOST_KEY = "spring.rabbitmq.host";
    private static final String ADDRESSES_KEY = "spring.rabbitmq.addresses";
    private static final String SSL_ENABLED_KEY = "spring.rabbitmq.ssl.enabled";
    private static final String SSL_BUNDLE_KEY = "spring.rabbitmq.ssl.bundle";

    @Test
    @DisplayName("Should stay silent when neither host nor addresses is configured")
    void shouldStaySilentWhenNoEvidenceOfUsage() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                SSL_ENABLED_KEY, "false"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report MEDIUM when host is configured but ssl.enabled is absent (unsafe default, ADR-010)")
    void shouldReportMediumWhenHostConfiguredButSslAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG015");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("'spring.rabbitmq.ssl.enabled' is not explicitly set")
                .endsWith("Reported as MEDIUM because SSL may be enabled outside these files, e.g. by an environment variable.");
    }

    @Test
    @DisplayName("Should report MEDIUM when scheme-less addresses is configured but ssl.enabled is absent")
    void shouldReportMediumWhenSchemeLessAddressesConfiguredButSslAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                ADDRESSES_KEY, "rabbit-a:5672,rabbit-b:5672"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("H2: HIGH with the explicit-disable message when ssl.enabled=false")
    void shouldReportHighWhenSslExplicitlyFalse() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("leaves the RabbitMQ connection unencrypted");
    }

    @Test
    @DisplayName("Should stay silent when ssl.enabled=true")
    void shouldStaySilentWhenSslExplicitlyTrue() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "true"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"yes", "YES", "on", "1"})
    @DisplayName("Should stay silent for Spring Boot truthy variants of ssl.enabled")
    void shouldStaySilentForTruthyVariants(String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, value
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when ssl.bundle is configured, regardless of ssl.enabled")
    void shouldStaySilentWhenSslBundleConfigured() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "false",
                SSL_BUNDLE_KEY, "rabbitmq-bundle"
        ));

        // Matches RabbitProperties.Ssl#determineEnabled(): defaultEnabled = enabled || bundle != null,
        // so a configured bundle makes SSL effectively enabled even with ssl.enabled=false.
        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("A3: defers to SCG012 when addresses carries an explicit amqp:// scheme, which overrides ssl.enabled")
    void shouldDeferWhenAddressesCarriesAmqpScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                ADDRESSES_KEY, "amqp://rabbit.internal:5672",
                SSL_ENABLED_KEY, "true"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("A2: silent when addresses carries an explicit amqps:// scheme")
    void shouldStaySilentWhenAddressesCarriesAmqpsScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                ADDRESSES_KEY, "amqps://rabbit.internal:5671",
                SSL_ENABLED_KEY, "false"
        ));

        // The address's own scheme overrides ssl.enabled in Spring's real determineSslEnabled();
        // amqps:// must not be flagged even with ssl.enabled=false.
        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should defer to the addresses scheme even when host is also present (addresses takes precedence in Spring)")
    void shouldDeferToAddressesSchemeWhenHostAlsoPresent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                ADDRESSES_KEY, "amqps://rabbit.internal:5671",
                SSL_ENABLED_KEY, "false"
        ));

        // Spring ignores spring.rabbitmq.host once addresses is set, so the scheme on addresses
        // must still govern here -- host's presence alone must not force the ssl.enabled path.
        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("A4: silent for addresses=AMQPS://..., which stopped the app from starting")
    void shouldStaySilentForUpperCaseAmqps() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                ADDRESSES_KEY, "AMQPS://127.0.0.1:5672"
        ));

        // Spring Boot's address parser compares the scheme case-sensitively, so AMQPS:// isn't
        // recognized and the host:port parse fails at startup: no connection can be made.
        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report INFO when ssl.enabled relies on an unresolved placeholder")
    void shouldReportInfoOnUnresolvedPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "${RABBIT_SSL}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder '${RABBIT_SSL}'");
    }

    @Test
    @DisplayName("Should stay silent when ssl.enabled placeholder resolves to a truthy default")
    void shouldStaySilentOnResolvedTruthyPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "${RABBIT_SSL:true}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH when ssl.enabled placeholder resolves to a falsy default")
    void shouldReportHighOnResolvedFalsyPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "${RABBIT_SSL:false}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains("leaves the RabbitMQ connection unencrypted");
    }

    @Test
    @DisplayName("Should report the MEDIUM not-configured finding when ssl.enabled placeholder resolves to an empty default")
    void shouldReportMediumOnEmptyPlaceholderDefault() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "${RABBIT_SSL:}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("'spring.rabbitmq.ssl.enabled' is not explicitly set");
    }

    @Test
    @DisplayName("Should not throw and report MEDIUM when ssl.enabled value is null but host is present")
    void shouldNotThrowWhenSslEnabledValueIsNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put(HOST_KEY, "rabbit.internal");
        properties.put(SSL_ENABLED_KEY, null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Should respect relaxed binding case-folding across segments")
    void shouldSupportRelaxedBinding() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "SPRING.RABBITMQ.HOST", "rabbit.internal",
                "spring.rabbitmq.ssl.enabled", "false"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "test", "local", "prod", "staging"})
    @DisplayName("Should report regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of(
                HOST_KEY, "rabbit.internal"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }

    private List<Finding> check(Map<String, String> properties) {
        return rule.check(new EffectiveConfig(FAKE_PATH, "prod", properties));
    }

    @Test
    @DisplayName("H0, A1, H5: MEDIUM without ssl.enabled, for host, scheme-less addresses, and the TLS port alone: all spoke plain AMQP")
    void plainWithoutSslEnabled() {
        for (Map<String, String> properties : List.of(
                Map.of(HOST_KEY, "127.0.0.1"),
                Map.of(ADDRESSES_KEY, "127.0.0.1:5672"),
                Map.of(HOST_KEY, "127.0.0.1", "spring.rabbitmq.port", "5671"))) {
            List<Finding> findings = check(properties);
            assertThat(findings).as(properties.toString()).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        }
    }

    @Test
    @DisplayName("H1, H3, H4, B1, A5, V1: silent when ssl.enabled is a true literal or a bundle is set: all started a TLS handshake")
    void silentWhenTlsIsOn() {
        for (String value : List.of("true", "yes", "TRUE")) {
            assertThat(check(Map.of(HOST_KEY, "127.0.0.1", SSL_ENABLED_KEY, value))).isEmpty();
        }
        assertThat(check(Map.of(HOST_KEY, "127.0.0.1", SSL_BUNDLE_KEY, "rabbit"))).isEmpty();
        assertThat(check(Map.of(ADDRESSES_KEY, "127.0.0.1:5672", SSL_ENABLED_KEY, "true"))).isEmpty();
        // V1: TLS without validating the server's certificate is out of this rule's scope (BACKLOG.md)
        assertThat(check(Map.of(HOST_KEY, "127.0.0.1", SSL_ENABLED_KEY, "true",
                "spring.rabbitmq.ssl.validate-server-certificate", "false"))).isEmpty();
    }

    @Test
    @DisplayName("A6, A7: the first address decides: plain first is MEDIUM, amqps:// first is silent")
    void firstAddressDecides() {
        assertThat(check(Map.of(ADDRESSES_KEY, "127.0.0.1:5672,amqps://127.0.0.1:5672")))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
        assertThat(check(Map.of(ADDRESSES_KEY, "amqps://127.0.0.1:5672,127.0.0.1:5672"))).isEmpty();
    }

    @Test
    @DisplayName("Y1: addresses written as a YAML list is read, through ConfigLoader: a scheme-less first entry is MEDIUM")
    void yamlListIsRead(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "spring.rabbitmq.addresses:\n  - 127.0.0.1:5672\n");

        List<Finding> findings = new ConfigLoader().loadDirectory(dir).stream()
                .flatMap(file -> new ProfileMerger().merge(file).stream())
                .flatMap(config -> rule.check(config).stream())
                .toList();

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("a list is read by its lowest index, whatever order the keys come in")
    void listReadByLowestIndex() {
        Map<String, String> secureFirst = new LinkedHashMap<>();
        secureFirst.put(ADDRESSES_KEY + "[1]", "127.0.0.1:5672");
        secureFirst.put(ADDRESSES_KEY + "[0]", "amqps://127.0.0.1:5671");
        Map<String, String> plainFirst = new LinkedHashMap<>();
        plainFirst.put(ADDRESSES_KEY + "[1]", "amqps://127.0.0.1:5671");
        plainFirst.put(ADDRESSES_KEY + "[0]", "127.0.0.1:5672");

        assertThat(check(secureFirst)).isEmpty();
        assertThat(check(plainFirst)).hasSize(1);
        assertThat(check(Map.of(ADDRESSES_KEY + "[0]", "127.0.0.1:5672", SSL_ENABLED_KEY, "false")))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }
}
