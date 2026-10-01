package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SCG014 and SCG007 on the Spring Cloud Stream Kafka binders (ADR-009). A binder builds each
 * client's configuration from Spring Boot's spring.kafka.* properties, overridden by its
 * configuration map, overridden by its consumer-/producer-properties maps; a named binder's
 * environment is a context of its own on top of the main one. Confirmed in Spring Cloud Stream's
 * KafkaBinderConfigurationProperties, KafkaTopicProvisioner and DefaultBinderFactory.
 */
class KafkaBinderRulesTest {

    private static final String KB = "spring.cloud.stream.kafka.binder.";
    private static final String KS = "spring.cloud.stream.kafka.streams.binder.";
    private static final String JAAS =
            "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"u\" password=\"s3cr3t\";";

    private static EffectiveConfig config(String... keysAndValues) {
        Map<String, String> properties = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            properties.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return new EffectiveConfig(Path.of("application.yml"), "prod", properties);
    }

    @Nested
    @DisplayName("SCG014 on the binders")
    class Scg014 {

        private final KafkaInsecureProtocolRule rule = new KafkaInsecureProtocolRule();

        private List<String> messages(EffectiveConfig config) {
            return rule.check(config).stream().map(Finding::message).toList();
        }

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {
                KB + "configuration.security.protocol",
                KB + "consumer-properties.security.protocol",
                KB + "producer-properties.security.protocol",
                KS + "configuration.security.protocol"
        })
        @DisplayName("Reports SASL_PLAINTEXT written in a binder client map")
        void reportsInsecureProtocolInBinderMaps(String key) {
            List<Finding> findings = rule.check(config(key, "SASL_PLAINTEXT"));

            assertThat(findings).anySatisfy(finding -> {
                assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                assertThat(finding.message()).startsWith("'" + key + "=SASL_PLAINTEXT'");
            });
        }

        @Test
        @DisplayName("Reports a binder in use with no protocol as MEDIUM, since Kafka defaults to PLAINTEXT (ADR-010)")
        void reportsBinderWithoutProtocol() {
            List<Finding> findings = rule.check(config(KB + "brokers", "broker.example.com:9092"));

            assertThat(findings).singleElement().satisfies(finding -> {
                assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
                assertThat(finding.message())
                        .contains("Spring Cloud Stream Kafka binder (the default binder)")
                        .contains("'" + KB + "configuration.security.protocol'");
            });
        }

        @Test
        @DisplayName("Reports the Kafka Streams binder in use with no protocol")
        void reportsStreamsBinderWithoutProtocol() {
            assertThat(messages(config(KS + "application-id", "word-count")))
                    .singleElement().asString().contains("Kafka Streams binder");
        }

        @Test
        @DisplayName("The binder inherits spring.kafka.security.protocol, as it builds on Spring Boot's properties")
        void binderInheritsSpringKafkaProtocol() {
            assertThat(rule.check(config(
                    KB + "brokers", "broker.example.com:9092",
                    "spring.kafka.security.protocol", "SASL_SSL"))).isEmpty();
        }

        @Test
        @DisplayName("A secure protocol in the binder's configuration map covers all its clients")
        void binderConfigurationProtocolCoversAllClients() {
            assertThat(rule.check(config(
                    KB + "brokers", "broker.example.com:9092",
                    KB + "configuration.security.protocol", "SASL_SSL"))).isEmpty();
        }

        @Test
        @DisplayName("A consumer-only protocol doesn't cover the producer and admin clients")
        void consumerOnlyProtocolDoesNotCoverOtherClients() {
            assertThat(messages(config(
                    KB + "brokers", "broker.example.com:9092",
                    KB + "consumer-properties.security.protocol", "SASL_SSL")))
                    .singleElement().asString().contains("no security.protocol covers all its clients");
        }

        @Test
        @DisplayName("A binder's insecure value wins over a secure spring.kafka value, and is reported")
        void binderValueOverridingSecureSpringKafkaIsReported() {
            assertThat(messages(config(
                    "spring.kafka.security.protocol", "SASL_SSL",
                    KB + "configuration.security.protocol", "PLAINTEXT")))
                    .singleElement().asString().startsWith("'" + KB + "configuration.security.protocol=PLAINTEXT'");
        }

        @Test
        @DisplayName("No duplicate when Step 3 already reports spring.kafka.* without a protocol")
        void noDuplicateOfSpringKafkaUnsetFinding() {
            assertThat(messages(config(
                    "spring.kafka.bootstrap-servers", "broker.example.com:9092",
                    KB + "brokers", "broker.example.com:9092")))
                    .singleElement().asString().startsWith("Kafka is configured via 'spring.kafka.*' properties");
        }

        @Test
        @DisplayName("A named binder's environment is its own context: an insecure value there is reported as written")
        void reportsInsecureValueInsideBinderEnvironment() {
            String key = "spring.cloud.stream.binders.kafka1.environment.spring.kafka.security.protocol";
            assertThat(messages(config(
                    "spring.cloud.stream.binders.kafka1.type", "kafka",
                    key, "PLAINTEXT")))
                    .singleElement().asString().startsWith("'" + key + "=PLAINTEXT'");
        }

        @Test
        @DisplayName("Each named binder without a protocol is reported, naming the binder; the main context is not")
        void reportsEachNamedBinderWithoutProtocol() {
            List<String> messages = messages(config(
                    KB + "auto-add-partitions", "true",
                    "spring.cloud.stream.binders.kafka-a.type", "kafka",
                    "spring.cloud.stream.binders.kafka-a.environment." + KB + "brokers", "a.example.com",
                    "spring.cloud.stream.binders.kafka-b.type", "kafka",
                    "spring.cloud.stream.binders.kafka-b.environment." + KB + "brokers", "b.example.com",
                    "spring.cloud.stream.binders.kafka-b.environment." + KB + "configuration.security.protocol", "SSL"));

            assertThat(messages).singleElement().asString().contains("(binder 'kafka-a')");
        }

        @Test
        @DisplayName("A top-level insecure value inherited by several binders is reported once")
        void inheritedInsecureValueReportedOnce() {
            assertThat(messages(config(
                    KB + "configuration.security.protocol", "SASL_PLAINTEXT",
                    "spring.cloud.stream.binders.kafka1.type", "kafka",
                    "spring.cloud.stream.binders.kafka2.type", "kafka"))).hasSize(1);
        }

        @Test
        @DisplayName("With inherit-environment=false, a named binder doesn't get the top-level protocol")
        void notInheritingBinderLosesTopLevelProtocol() {
            assertThat(messages(config(
                    "spring.kafka.security.protocol", "SASL_SSL",
                    "spring.cloud.stream.binders.kafka1.type", "kafka",
                    "spring.cloud.stream.binders.kafka1.inherit-environment", "false",
                    "spring.cloud.stream.binders.kafka1.environment." + KB + "brokers", "a.example.com")))
                    .singleElement().asString().contains("(binder 'kafka1')");
        }

        @Test
        @DisplayName("An unresolved placeholder in a binder protocol key is INFO, and counts as configured")
        void unresolvedPlaceholderIsInfo() {
            List<Finding> findings = rule.check(config(
                    KB + "brokers", "broker.example.com:9092",
                    KB + "configuration.security.protocol", "${KAFKA_PROTOCOL}"));

            assertThat(findings).singleElement().satisfies(finding ->
                    assertThat(finding.severity()).isEqualTo(Severity.INFO));
        }

        @Test
        @DisplayName("A RabbitMQ binder is not a Kafka binder")
        void rabbitBinderIsIgnored() {
            assertThat(rule.check(config(
                    "spring.cloud.stream.binders.rabbit1.type", "rabbit",
                    "spring.cloud.stream.binders.rabbit1.environment.spring.rabbitmq.host", "mq.example.com"))).isEmpty();
        }
    }

    @Nested
    @DisplayName("SCG007 on the binders")
    class Scg007 {

        private final EmbeddedConnectionCredentialsRule rule = configuredScg007();

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {
                KB + "configuration.sasl.jaas.config",
                KB + "consumer-properties.sasl.jaas.config",
                KB + "producer-properties.sasl.jaas.config",
                KS + "configuration.sasl.jaas.config",
                "spring.cloud.stream.binders.kafka1.environment." + KB + "configuration.sasl.jaas.config",
                "spring.cloud.stream.binders.kafka1.environment.spring.kafka.properties.sasl.jaas.config"
        })
        @DisplayName("Reports a plaintext JAAS password in a binder client map or inside a binder's environment")
        void reportsPlaintextJaasPassword(String key) {
            assertThat(rule.check(config(key, JAAS))).singleElement().satisfies(finding -> {
                assertThat(finding.severity()).isEqualTo(Severity.HIGH);
                assertThat(finding.message()).contains("'" + key + "'");
            });
        }

        @Test
        @DisplayName("A binder environment key that isn't a JAAS target stays unchecked")
        void unrelatedEnvironmentKeyIsIgnored() {
            assertThat(rule.check(config(
                    "spring.cloud.stream.binders.kafka1.environment." + KB + "brokers", "a.example.com"))).isEmpty();
        }

        private static EmbeddedConnectionCredentialsRule configuredScg007() {
            EmbeddedConnectionCredentialsRule rule = new EmbeddedConnectionCredentialsRule();
            try (InputStream is = KafkaBinderRulesTest.class.getResourceAsStream("/rules-metadata/SCG007.yml")) {
                Map<String, List<String>> metadata = new Yaml().load(is);
                rule.configure(metadata);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to load SCG007.yml metadata", e);
            }
            return rule;
        }
    }

    @Nested
    @DisplayName("Binder contexts")
    class Contexts {

        @Test
        @DisplayName("A named binder's environment overrides the main context it inherits")
        void environmentOverridesInheritedMainContext() {
            List<KafkaBinderContexts.Context> contexts = KafkaBinderContexts.of(config(
                    "spring.kafka.security.protocol", "SASL_SSL",
                    "spring.cloud.stream.binders.kafka-a.environment.spring.kafka.security.protocol", "SSL"));

            assertThat(contexts).hasSize(2);
            assertThat(contexts.get(0).get("spring.kafka.security.protocol")).isEqualTo("SASL_SSL");
            KafkaBinderContexts.Context binder = contexts.get(1);
            assertThat(binder.binderName()).contains("kafka-a");
            assertThat(binder.get("spring.kafka.security.protocol")).isEqualTo("SSL");
            assertThat(binder.owns("spring.kafka.security.protocol")).isTrue();
            assertThat(binder.writtenKey("spring.kafka.security.protocol"))
                    .isEqualTo("spring.cloud.stream.binders.kafka-a.environment.spring.kafka.security.protocol");
        }

        @Test
        @DisplayName("Binder settings other than the environment stay out of every context's properties")
        void binderSettingsAreNotProperties() {
            List<KafkaBinderContexts.Context> contexts = KafkaBinderContexts.of(config(
                    "spring.cloud.stream.binders.kafka1.type", "kafka"));

            assertThat(contexts.get(0).properties()).isEmpty();
            assertThat(contexts.get(1).binderType()).contains("kafka");
            assertThat(contexts.get(1).properties()).isEmpty();
        }

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {
                "spring.cloud.stream.binders.kafka1.environment.spring.kafka.properties.sasl.jaas.config",
                "spring.kafka.properties.sasl.jaas.config"
        })
        @DisplayName("withoutBinderEnvironment strips a binder's environment prefix and nothing else")
        void stripsBinderEnvironmentPrefix(String key) {
            assertThat(KafkaBinderContexts.withoutBinderEnvironment(dev.scg.core.RelaxedProperties.canonicalize(key)))
                    .isEqualTo("spring.kafka.properties.sasl.jaas.config");
        }
    }
}
