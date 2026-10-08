package dev.scg.rules;

import dev.scg.core.ConfigLoader;
import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ConfigFileGrouper;
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
    @DisplayName("B2: a bundle placeholder that resolves empty leaves TLS off: MEDIUM, as without a bundle")
    void bundleResolvingEmptyIsMedium() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_BUNDLE_KEY, "${SCG_BUNDLE:}"
        ));

        assertThat(rule.check(config)).singleElement()
                .extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("B2: with a bundle that resolves empty, ssl.enabled=false is still HIGH")
    void bundleResolvingEmptyWithSslDisabledIsHigh() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "false",
                SSL_BUNDLE_KEY, "${SCG_BUNDLE:}"
        ));

        assertThat(rule.check(config)).singleElement()
                .extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "${SSL_ENABLED}"})
    @DisplayName("B2u: a bundle placeholder without a default is INFO, whether ssl.enabled is false or unresolved")
    void unresolvedBundleIsInfo(String enabled) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, enabled,
                SSL_BUNDLE_KEY, "${SCG_BUNDLE}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains(SSL_BUNDLE_KEY, "${SCG_BUNDLE}");
    }

    @Test
    @DisplayName("B2u: a bundle placeholder without a default is INFO when ssl.enabled is absent")
    void unresolvedBundleWithoutSslEnabledIsInfo() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_BUNDLE_KEY, "${SCG_BUNDLE}"
        ));

        assertThat(rule.check(config)).singleElement()
                .extracting(Finding::severity).isEqualTo(Severity.INFO);
    }

    @ParameterizedTest
    @ValueSource(strings = {"${SCG_BUNDLE}", "${SCG_BUNDLE:}"})
    @DisplayName("A bundle placeholder doesn't matter when ssl.enabled is true: TLS is on either way")
    void bundlePlaceholderWithSslEnabledIsSilent(String bundle) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "true",
                SSL_BUNDLE_KEY, bundle
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("A bundle placeholder with a non-empty default sets the bundle: silent")
    void bundlePlaceholderWithDefaultIsSilent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                HOST_KEY, "rabbit.internal",
                SSL_ENABLED_KEY, "false",
                SSL_BUNDLE_KEY, "${SCG_BUNDLE:rabbit}"
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

        // Matches RabbitProperties.Ssl#determineEnabled(): enabled || StringUtils.hasText(bundle),
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
                ADDRESSES_KEY, "AMQPS://rabbit.internal:5672"
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
                Map.of(HOST_KEY, "rabbit.internal"),
                Map.of(ADDRESSES_KEY, "rabbit.internal:5672"),
                Map.of(HOST_KEY, "rabbit.internal", "spring.rabbitmq.port", "5671"))) {
            List<Finding> findings = check(properties);
            assertThat(findings).as(properties.toString()).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        }
    }

    @Test
    @DisplayName("H1, H3, H4, B1, A5: silent when ssl.enabled is a true literal or a bundle is set: all started a TLS handshake")
    void silentWhenTlsIsOn() {
        for (String value : List.of("true", "yes", "TRUE")) {
            assertThat(check(Map.of(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, value))).isEmpty();
        }
        assertThat(check(Map.of(HOST_KEY, "rabbit.internal", SSL_BUNDLE_KEY, "rabbit"))).isEmpty();
        assertThat(check(Map.of(ADDRESSES_KEY, "rabbit.internal:5672", SSL_ENABLED_KEY, "true"))).isEmpty();
    }

    @Test
    @DisplayName("V1: TLS on, validate-server-certificate=false and no store: no plaintext finding, the verification one is MEDIUM")
    void tlsOnWithoutValidation() {
        assertThat(check(Map.of(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true",
                "spring.rabbitmq.ssl.validate-server-certificate", "false")))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
                    assertThat(finding.message()).contains("validate-server-certificate=false");
                });
    }

    @Test
    @DisplayName("A6, A7: the first address decides: plain first is MEDIUM, amqps:// first is silent")
    void firstAddressDecides() {
        assertThat(check(Map.of(ADDRESSES_KEY, "rabbit.internal:5672,amqps://rabbit.internal:5672")))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
        assertThat(check(Map.of(ADDRESSES_KEY, "amqps://rabbit.internal:5672,rabbit.internal:5672"))).isEmpty();
    }

    @Test
    @DisplayName("Y1: addresses written as a YAML list is read, through ConfigLoader: a scheme-less first entry is MEDIUM")
    void yamlListIsRead(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "spring.rabbitmq.addresses:\n  - rabbit.internal:5672\n");

        List<Finding> findings = new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(dir)).stream()
                .flatMap(group -> new ProfileMerger().merge(group).stream())
                .flatMap(config -> rule.check(config).stream())
                .toList();

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("a list is read by its lowest index, whatever order the keys come in")
    void listReadByLowestIndex() {
        Map<String, String> secureFirst = new LinkedHashMap<>();
        secureFirst.put(ADDRESSES_KEY + "[1]", "rabbit.internal:5672");
        secureFirst.put(ADDRESSES_KEY + "[0]", "amqps://rabbit.internal:5671");
        Map<String, String> plainFirst = new LinkedHashMap<>();
        plainFirst.put(ADDRESSES_KEY + "[1]", "amqps://rabbit.internal:5671");
        plainFirst.put(ADDRESSES_KEY + "[0]", "rabbit.internal:5672");

        assertThat(check(secureFirst)).isEmpty();
        assertThat(check(plainFirst)).hasSize(1);
        assertThat(check(Map.of(ADDRESSES_KEY + "[0]", "rabbit.internal:5672", SSL_ENABLED_KEY, "false")))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "127.0.0.1"})
    @DisplayName("L9: a loopback host is INFO, not MEDIUM")
    void loopbackHostIsInfo(String host) {
        List<Finding> findings = check(Map.of(HOST_KEY, host));

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("loopback addresses");
    }

    @Test
    @DisplayName("L9: ssl.enabled=false on a loopback host is INFO, not HIGH")
    void loopbackHostWithSslDisabledIsInfo() {
        assertThat(check(Map.of(HOST_KEY, "localhost", SSL_ENABLED_KEY, "false")))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("L10: addresses with one remote broker keep the MEDIUM, whatever host says")
    void mixedAddressesStayMedium() {
        assertThat(check(Map.of(ADDRESSES_KEY, "localhost:5672,rabbit.internal:5672", HOST_KEY, "localhost")))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("Addresses decide over host: loopback addresses with a remote host are INFO")
    void addressesDecideOverHost() {
        assertThat(check(Map.of(ADDRESSES_KEY, "localhost:5672", HOST_KEY, "rabbit.internal")))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("L15: a loopback host from a placeholder default keeps the MEDIUM")
    void placeholderHostKeepsMedium() {
        assertThat(check(Map.of(HOST_KEY, "${RABBIT_HOST:localhost}")))
                .singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
    }

    // --- TLS without server verification (VALIDATION.md, "TLS without server verification (Kafka and RabbitMQ)")

    private static final String VERIFY = "spring.rabbitmq.ssl.verify-hostname";
    private static final String VALIDATE = "spring.rabbitmq.ssl.validate-server-certificate";
    private static final String TRUST_STORE = "spring.rabbitmq.ssl.trust-store";

    private List<Finding> verificationFindings(String... keysAndValues) {
        Map<String, String> properties = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            properties.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return check(properties).stream()
                .filter(f -> f.message().contains(VERIFY) || f.message().contains(VALIDATE))
                .toList();
    }

    @Test
    @DisplayName("R0, R1, R4, R8, RB0, RB1, R11: TLS with the checks left on reports nothing about verification")
    void checksLeftOnAreSilent() {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", TRUST_STORE, "file:/etc/trust.p12")).isEmpty();
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true")).isEmpty();
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_BUNDLE_KEY, "rabbit")).isEmpty();
        assertThat(verificationFindings(ADDRESSES_KEY, "amqps://rabbit.internal:5671", VERIFY, "true")).isEmpty();
    }

    @ParameterizedTest(name = "verify-hostname={0}")
    @ValueSource(strings = {"false", "off", "no", "FALSE"})
    @DisplayName("R2, R3: verify-hostname set to a false literal on TLS is MEDIUM")
    void verifyHostnameFalseIsMedium(String value) {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true",
                TRUST_STORE, "file:/etc/trust.p12", VERIFY, value))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
                    assertThat(finding.message()).contains(VERIFY + "=" + value).contains("host name").contains("CWE-295");
                });
    }

    @Test
    @DisplayName("RB2, R12: verify-hostname=false with a bundle or an amqps:// address is MEDIUM too")
    void verifyHostnameFalseWithBundleOrAmqps() {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_BUNDLE_KEY, "rabbit", VERIFY, "false"))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.MEDIUM));
        assertThat(verificationFindings(ADDRESSES_KEY, "amqps://rabbit.internal:5671", VERIFY, "false"))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.MEDIUM));
    }

    @Test
    @DisplayName("R7: verify-hostname=false is reported whatever the trust check does with the server")
    void verifyHostnameFalseIndependentOfTrust() {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", VERIFY, "false"))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.MEDIUM));
    }

    @Test
    @DisplayName("R9, R10, R13: validate-server-certificate=false without any store or bundle is MEDIUM: any server is accepted")
    void validateFalseWithoutStoresIsMedium() {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", VALIDATE, "false"))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
                    assertThat(finding.message()).contains(VALIDATE + "=false").contains("any server certificate");
                });
        assertThat(verificationFindings(ADDRESSES_KEY, "amqps://rabbit.internal:5671", VALIDATE, "false"))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.MEDIUM));
    }

    @Test
    @DisplayName("R5, R6, RB3: validate-server-certificate=false with a key store, trust store or bundle is ignored by Spring AMQP: silent")
    void validateFalseWithStoresIsSilent() {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", TRUST_STORE, "file:/etc/trust.p12", VALIDATE, "false")).isEmpty();
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", "spring.rabbitmq.ssl.key-store", "file:/etc/key.p12", VALIDATE, "false")).isEmpty();
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_BUNDLE_KEY, "rabbit", VALIDATE, "false")).isEmpty();
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", TRUST_STORE, "file:/etc/trust.p12", VALIDATE, "${VALIDATE}")).isEmpty();
    }

    @Test
    @DisplayName("A trust store from a placeholder without a default makes validate-server-certificate=false INFO: Spring may ignore it")
    void validateFalseWithUnknownStoreIsInfo() {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", TRUST_STORE, "${TRUST_STORE}", VALIDATE, "false"))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.INFO);
                    assertThat(finding.message()).contains("unresolved placeholder");
                });
    }

    @Test
    @DisplayName("Without TLS, the verification keys are silent: the plaintext finding covers the connection")
    void verificationWithoutTlsIsSilent() {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", VERIFY, "false", VALIDATE, "false")).isEmpty();
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "false", VERIFY, "false")).isEmpty();
        assertThat(verificationFindings(ADDRESSES_KEY, "amqp://rabbit.internal:5672", SSL_ENABLED_KEY, "true", VERIFY, "false")).isEmpty();
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_BUNDLE_KEY, "${BUNDLE:}", VERIFY, "false")).isEmpty();
    }

    @Test
    @DisplayName("Placeholders: an unresolved value is INFO, a false default MEDIUM with its origin, a true default silent; TLS from a placeholder makes it INFO")
    void verificationPlaceholders() {
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", VERIFY, "${VERIFY_HOSTNAME}"))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.INFO));
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", VERIFY, "${VERIFY_HOSTNAME:false}"))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
                    assertThat(finding.message()).contains("static placeholder default ('${VERIFY_HOSTNAME:false}')");
                });
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "true", VERIFY, "${VERIFY_HOSTNAME:true}")).isEmpty();
        assertThat(verificationFindings(HOST_KEY, "rabbit.internal", SSL_ENABLED_KEY, "${RABBIT_TLS}", VERIFY, "false"))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.INFO);
                    assertThat(finding.message()).contains("whether the connection uses TLS");
                });
    }

    @Test
    @DisplayName("Without host or addresses (a broker set elsewhere), verify-hostname=false on TLS is still MEDIUM; on a loopback host, INFO")
    void verificationWithoutHostAndOnLoopback() {
        assertThat(verificationFindings(SSL_ENABLED_KEY, "true", VERIFY, "false"))
                .singleElement().satisfies(finding -> assertThat(finding.severity()).isEqualTo(Severity.MEDIUM));
        assertThat(verificationFindings(HOST_KEY, "localhost", SSL_ENABLED_KEY, "true", VERIFY, "false"))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.INFO);
                    assertThat(finding.message()).contains("Lowered from MEDIUM");
                });
    }
}
