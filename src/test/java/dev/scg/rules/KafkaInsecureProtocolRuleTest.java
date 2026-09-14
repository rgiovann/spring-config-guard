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
    @DisplayName("Should report HIGH severity when Kafka is configured but security.protocol is absent (unsafe default)")
    void shouldReportHighWhenKafkaConfiguredButProtocolAbsent() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "localhost:9092"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG014");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("Kafka clients default to 'PLAINTEXT'");
    }

    @Test
    @DisplayName("Should report HIGH for the unsafe default even when the common key is present but blank")
    void shouldReportHighWhenCommonKeyIsBlank() {
        // Distinct from the null case below: exercises isCommonProtocolConfigured()'s own
        // !common.isBlank() branch, which the null test short-circuits past without evaluating.
        // A blank value is not "configured" -- the unset finding must still fire.
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "localhost:9092",
                COMMON_KEY, "   "
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.getFirst().message()).contains("'spring.kafka.security.protocol' is not explicitly set");
    }

    @Test
    @DisplayName("Should stay silent when common security.protocol is explicitly set to SSL or SASL_SSL")
    void shouldStaySilentWhenCommonProtocolIsSecure() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "localhost:9092",
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
                "spring.kafka.bootstrap-servers", "localhost:9092",
                COMMON_KEY, "sometimes"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH for missing common protocol even if a client-specific override (e.g. consumer) is secure")
    void shouldReportHighWhenCommonProtocolMissingEvenIfConsumerIsSecure() {
        // Consumer is explicitly secure, but producer/admin/streams fall back to common which is missing -> unsafe default
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.kafka.bootstrap-servers", "localhost:9092",
                "spring.kafka.consumer.security.protocol", "SASL_SSL"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
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
                "spring.kafka.bootstrap-servers", "localhost:9092",
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
                "spring.kafka.bootstrap-servers", "localhost:9092",
                "spring.kafka.properties.security.protocol", "SSL"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should not throw and report HIGH when property value is null but Kafka prefix is present")
    void shouldNotThrowWhenPropertyValueIsNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("spring.kafka.bootstrap-servers", "localhost:9092");
        properties.put(COMMON_KEY, null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.HIGH);
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
}