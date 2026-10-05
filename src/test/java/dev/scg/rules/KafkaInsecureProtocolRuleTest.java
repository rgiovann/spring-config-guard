package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KafkaInsecureProtocolRuleTest {

    private final KafkaInsecureProtocolRule rule = new KafkaInsecureProtocolRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");
    private static final String COMMON_KEY = "spring.kafka.security.protocol";

    @Test
    @DisplayName("Should stay silent when no spring.kafka.* properties are present")
    void shouldStaySilentWhenNoKafkaPropertiesPresent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "server.port", "8080"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when a key shares the 'spring.kafka' prefix as a substring but isn't actually under it")
    void shouldStaySilentOnPrefixSubstringMatch() {
        // "spring.kafkaconnect.*" is not "spring.kafka.*" -- must not be treated as evidence of
        // Spring Kafka usage just because it shares the literal characters as a substring. Same
        // boundary class of bug already fixed once in this rule (SPRING_KAFKA_PREFIX's trailing dot).
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafkaconnect.foo", "bar"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report MEDIUM when Kafka is configured but security.protocol is absent (unsafe default, ADR-010)")
    void shouldReportMediumWhenKafkaConfiguredButProtocolAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "kafka.internal:9092"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG014");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("Kafka clients default to 'PLAINTEXT'")
                .endsWith("Reported as MEDIUM because the protocol may be set outside these files, e.g. by an environment variable.");
    }

    @Test
    @DisplayName("Should report MEDIUM for the unsafe default even when the common key is present but blank")
    void shouldReportMediumWhenCommonKeyIsBlank() {
        // Distinct from the null case below: exercises isCommonProtocolConfigured()'s own
        // !common.isBlank() branch, which the null test short-circuits past without evaluating.
        // A blank value is not "configured" -- the unset finding must still fire.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "kafka.internal:9092",
                COMMON_KEY, "   "
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("'spring.kafka.security.protocol' is not explicitly set");
    }

    @Test
    @DisplayName("Should stay silent when common security.protocol is explicitly set to SSL or SASL_SSL")
    void shouldStaySilentWhenCommonProtocolIsSecure() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "kafka.internal:9092",
                COMMON_KEY, "SSL"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "plaintext", "PLAINTEXT", "plain-text", "plain_text", "plainText"
    })
    @DisplayName("Should report HIGH severity with plaintext specific message when common protocol is PLAINTEXT")
    void shouldReportHighOnPlaintextValue(String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                COMMON_KEY, value
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("transmits Kafka cluster traffic in plaintext without encryption or authentication");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "sasl_plaintext", "SASL_PLAINTEXT", "sasl-plaintext", "saslPlaintext"
    })
    @DisplayName("Should report HIGH severity with credential-leak specific message when protocol is SASL_PLAINTEXT")
    void shouldReportHighOnSaslPlaintextValue(String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                COMMON_KEY, value
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("uses SASL authentication over an unencrypted transport protocol, exposing both client credentials and payload traffic");
    }

    @ParameterizedTest
    @ValueSource(strings = {"sasl.plaintext", "sasl plaintext"})
    @DisplayName("Should report HIGH even for atypical separators, proving canonicalize() strips any non-alphanumeric char")
    void shouldReportHighOnAtypicalSeparators(String value) {
        // Not real Spring Boot authoring styles, but they prove canonicalize() (shared with
        // SCG001/SCG010/SCG013) isn't secretly hardcoded to just '-'/'_'.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                COMMON_KEY, value
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should stay fully silent (no risky finding, no unset finding) on an unrecognized protocol value")
    void shouldStaySilentOnUnrecognizedValue() {
        // A syntactically invalid property value is an application startup failure in Spring
        // Boot at runtime, not a static security-posture finding -- same stance already taken by
        // HealthDetailsExposureRule/VerboseErrorResponseRule for their own unrecognized values.
        // The key IS present and non-blank, so the "unset" finding must not fire either.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "kafka.internal:9092",
                COMMON_KEY, "sometimes"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report MEDIUM for missing common protocol even if a client-specific override (e.g. consumer) is secure")
    void shouldReportMediumWhenCommonProtocolMissingEvenIfConsumerIsSecure() {
        // Consumer is explicitly secure, but producer/admin/streams fall back to common which is missing -> unsafe default
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "kafka.internal:9092",
                "spring.kafka.consumer.security.protocol", "SASL_SSL"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("'spring.kafka.security.protocol' is not explicitly set");
    }

    @Test
    @DisplayName("Should evaluate client-specific typed and properties-map keys independently")
    void shouldEvaluateClientSpecificKeys() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                COMMON_KEY, "SSL",
                "spring.kafka.producer.security.protocol", "PLAINTEXT",
                "spring.kafka.consumer.properties.security.protocol", "SASL_PLAINTEXT"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(Finding::severity).containsExactly(Severity.HIGH, Severity.HIGH);
        assertThat(findings.get(0).message()).contains("spring.kafka.producer.security.protocol=PLAINTEXT");
        assertThat(findings.get(1).message()).contains("spring.kafka.consumer.properties.security.protocol=SASL_PLAINTEXT");
    }

    @Test
    @DisplayName("Should report INFO severity when security.protocol relies on an unresolved placeholder")
    void shouldReportInfoOnUnresolvedPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                COMMON_KEY, "${KAFKA_PROTOCOL}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder '${KAFKA_PROTOCOL}'");
    }

    @Test
    @DisplayName("Should report HIGH severity when placeholder resolves to a risky value via default")
    void shouldReportHighOnResolvedRiskyPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                COMMON_KEY, "${KAFKA_PROTOCOL:PLAINTEXT}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should stay silent when placeholder resolves to a safe value via default")
    void shouldStaySilentOnResolvedSafePlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                COMMON_KEY, "${KAFKA_PROTOCOL:SASL_SSL}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay fully silent when the common key resolves to an empty placeholder default")
    void shouldStaySilentWhenCommonResolvesToEmptyDefault() {
        // Deliberate: isCommonProtocolConfigured() reads the raw property text, not the resolved
        // placeholder value -- "${KAFKA_PROTOCOL:}" is non-blank as a literal string, so it counts
        // as "configured" and the unset finding does not fire. At runtime this would resolve to
        // security.protocol="", which is not a valid value for the native Kafka client and would
        // fail fast as an application startup error, not a silent PLAINTEXT downgrade -- same
        // "syntactically invalid = startup failure, not a security-posture finding" stance as
        // shouldStaySilentOnUnrecognizedValue above. Locking this in explicitly since the
        // interaction between the two independent checks (Step 2's placeholder resolution vs.
        // Step 3's raw-text presence check) is not obvious from reading either method alone.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "kafka.internal:9092",
                COMMON_KEY, "${KAFKA_PROTOCOL:}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should respect relaxed binding case-folding across segments")
    void shouldSupportRelaxedBinding() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "SPRING.KAFKA.SECURITY.PROTOCOL", "PLAINTEXT"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should treat properties map override spring.kafka.properties.security.protocol as common configuration")
    void shouldAcceptPropertiesMapAsCommon() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "kafka.internal:9092",
                "spring.kafka.properties.security.protocol", "SSL"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should not throw and report MEDIUM when property value is null but Kafka prefix is present")
    void shouldNotThrowWhenPropertyValueIsNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("spring.kafka.bootstrap-servers", "kafka.internal:9092");
        properties.put(COMMON_KEY, null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should report regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of(
                COMMON_KEY, "PLAINTEXT"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }

    // Precedence, confirmed by binding Spring Boot 4.1.1's KafkaProperties and building each client's
    // configuration: client properties map > client typed key > spring.kafka.properties > common typed key.

    @Test
    @DisplayName("P1: an insecure common typed key overridden by spring.kafka.properties for every client is not reported")
    void shouldNotReportCommonKeyOverriddenByCommonMap() {
        assertThat(rule.check(config(
                COMMON_KEY, "PLAINTEXT",
                "spring.kafka.properties.security.protocol", "SSL"))).isEmpty();
    }

    @Test
    @DisplayName("P2/P3: an insecure spring.kafka.properties value overrides the typed keys below it and is reported once")
    void shouldReportCommonMapOverridingTypedKeys() {
        List<Finding> findings = rule.check(config(
                COMMON_KEY, "SSL",
                "spring.kafka.consumer.security.protocol", "SSL",
                "spring.kafka.properties.security.protocol", "PLAINTEXT"));

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            assertThat(finding.message()).startsWith("'spring.kafka.properties.security.protocol=PLAINTEXT'");
        });
    }

    @Test
    @DisplayName("P4: an insecure client typed key overridden by the client's properties map is not reported; the uncovered clients are")
    void shouldNotReportClientKeyOverriddenByClientMap() {
        List<Finding> findings = rule.check(config(
                "spring.kafka.consumer.security.protocol", "PLAINTEXT",
                "spring.kafka.consumer.properties.security.protocol", "SSL"));

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
            assertThat(finding.message()).contains("covers the producer, admin, streams clients");
        });
    }

    @Test
    @DisplayName("P5: an insecure common key overridden by every client's own key is not reported")
    void shouldNotReportCommonKeyOverriddenByEveryClient() {
        assertThat(rule.check(config(
                COMMON_KEY, "PLAINTEXT",
                "spring.kafka.producer.security.protocol", "SSL",
                "spring.kafka.consumer.security.protocol", "SSL",
                "spring.kafka.admin.security.protocol", "SSL",
                "spring.kafka.streams.security.protocol", "SSL"))).isEmpty();
    }

    @Test
    @DisplayName("An insecure common key still reported when one client keeps it")
    void shouldReportCommonKeyWhenOneClientStillUsesIt() {
        List<Finding> findings = rule.check(config(
                COMMON_KEY, "PLAINTEXT",
                "spring.kafka.producer.security.protocol", "SSL",
                "spring.kafka.consumer.security.protocol", "SSL",
                "spring.kafka.admin.security.protocol", "SSL"));

        assertThat(findings).singleElement().satisfies(finding ->
                assertThat(finding.message()).startsWith("'spring.kafka.security.protocol=PLAINTEXT'"));
    }

    @Test
    @DisplayName("Every client covered by its own key, with no common key: nothing to report")
    void shouldNotReportUnsetWhenEveryClientIsCovered() {
        assertThat(rule.check(config(
                "spring.kafka.producer.security.protocol", "SSL",
                "spring.kafka.consumer.security.protocol", "SSL",
                "spring.kafka.admin.security.protocol", "SASL_SSL",
                "spring.kafka.streams.properties.security.protocol", "SSL"))).isEmpty();
    }

    @Test
    @DisplayName("P7: only the streams client uncovered is still MEDIUM, naming it (a Streams app may have no streams key)")
    void shouldReportOnlyStreamsClientUncovered() {
        List<Finding> findings = rule.check(config(
                "spring.kafka.producer.security.protocol", "SSL",
                "spring.kafka.consumer.security.protocol", "SSL",
                "spring.kafka.admin.security.protocol", "SSL"));

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
            assertThat(finding.message()).contains("covers the streams client.");
        });
    }

    @Test
    @DisplayName("An unresolved placeholder overrides an insecure value below it: only the placeholder is reported, as INFO")
    void shouldNotReportValueOverriddenByUnresolvedPlaceholder() {
        assertThat(rule.check(config(
                COMMON_KEY, "PLAINTEXT",
                "spring.kafka.properties.security.protocol", "${KAFKA_PROTOCOL}")))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.severity()).isEqualTo(Severity.INFO);
                    assertThat(finding.message()).contains("spring.kafka.properties.security.protocol");
                });
    }

    @Test
    @DisplayName("Inside a named binder's environment, the same precedence applies to its spring.kafka.* keys")
    void shouldResolvePrecedenceInsideBinderEnvironment() {
        String env = "spring.cloud.stream.binders.kafka1.environment.";
        assertThat(rule.check(config(
                "spring.cloud.stream.binders.kafka1.type", "kafka",
                env + "spring.kafka.security.protocol", "PLAINTEXT",
                env + "spring.kafka.properties.security.protocol", "SSL"))).isEmpty();
    }

    private static EffectiveConfig config(String... keysAndValues) {
        Map<String, String> properties = new java.util.LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            properties.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return new EffectiveConfig(FAKE_PATH, "prod", properties);
    }

    @Test
    @DisplayName("L5: an absent protocol with only loopback brokers written is INFO, not MEDIUM")
    void loopbackBrokersMakeAbsentProtocolInfo() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "localhost:9092"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("advertised listeners");
    }

    @Test
    @DisplayName("L6: one remote broker address anywhere keeps every finding as it is")
    void remoteBrokerKeepsFindings() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "localhost:9092",
                "spring.kafka.consumer.bootstrap-servers", "kafka.internal:9092"
        ));

        assertThat(rule.check(config)).singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("L7: a binder on loopback brokers with SASL_PLAINTEXT is INFO, not HIGH")
    void loopbackBinderBrokersMakeWrittenProtocolInfo() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.cloud.stream.kafka.binder.brokers", "localhost:9092",
                "spring.cloud.stream.kafka.binder.configuration.security.protocol", "SASL_PLAINTEXT"
        ));

        assertThat(rule.check(config)).isNotEmpty().allMatch(finding -> finding.severity() == Severity.INFO
                && finding.message().contains("Lowered from HIGH to INFO"));
    }

    @Test
    @DisplayName("L8: no broker written keeps the MEDIUM, though Spring Boot's default is localhost:9092")
    void unwrittenBrokersDontCount() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.consumer.group-id", "app"
        ));

        assertThat(rule.check(config)).singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("A broker address that is an unresolved placeholder isn't taken for loopback")
    void unresolvedBrokerDoesntCount() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "localhost:9092",
                "spring.kafka.producer.bootstrap-servers", "${KAFKA_BROKERS}"
        ));

        assertThat(rule.check(config)).singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("L15: a loopback broker from a placeholder default keeps the MEDIUM")
    void placeholderBrokerKeepsMedium() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "${KAFKA_BOOTSTRAP_SERVERS:localhost:9092}"
        ));

        assertThat(rule.check(config)).singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("A loopback address under another prefix isn't a Kafka broker: the HIGH stays")
    void foreignBrokerKeyDoesntCount() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "app.audit.kafka.bootstrap-servers", "localhost:9092",
                "spring.kafka.security.protocol", "PLAINTEXT"
        ));

        assertThat(rule.check(config)).singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Broker addresses count in a properties map and in a binder's environment")
    void brokersCountInEveryContext() {
        EffectiveConfig loopback = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.properties.bootstrap.servers", "localhost:9092",
                "spring.kafka.security.protocol", "PLAINTEXT"
        ));
        EffectiveConfig remoteInBinder = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "localhost:9092",
                "spring.kafka.security.protocol", "PLAINTEXT",
                "spring.cloud.stream.binders.k2.type", "kafka",
                "spring.cloud.stream.binders.k2.environment.spring.cloud.stream.kafka.binder.brokers", "kafka.internal:9092"
        ));

        assertThat(rule.check(loopback)).singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
        assertThat(rule.check(remoteInBinder)).extracting(Finding::severity).contains(Severity.HIGH);
    }
}
