package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bracketed map keys ({@code spring.kafka.properties[security.protocol]}) through the whole
 * pipeline: ConfigLoader rewrites them into dotted form, so the merge treats them as map entries
 * (merged key by key, as Spring Boot does) and rules find them under the dotted name they look up.
 * Expected Spring behavior was confirmed with Spring Boot 4.1.1's own Binder and YAML loader
 * (see ARCHITECTURE.md, ADR-007).
 */
class BracketedMapKeysTest {

    private static final String JAAS =
            "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"u\" password=\"s3cr3t\";";

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
            "spring.kafka.properties[security.protocol], spring.kafka.properties.security.protocol",
            "x.map.[a.b], x.map.a.b",
            "x.list[0], x.list[0]",
            "x.list[0].map[a.b], x.list[0].map.a.b",
            "x.map[a][b], x.map.a.b",
            "no.brackets.here, no.brackets.here",
            "x.map[unclosed, x.map[unclosed",
            "x.empty[], x.empty[]"
    })
    @DisplayName("normalizeMapKeys rewrites bracketed map keys into dotted form and keeps list indices")
    void normalizesBracketedMapKeys(String raw, String expected) {
        assertEquals(expected, ConfigLoader.normalizeMapKeys(raw));
    }

    @Test
    @DisplayName("A profile adding one bracketed map entry keeps the base's entries (YAML)")
    void profileMergesBracketedMapKeyByKeyInYaml(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                logging:
                  level:
                    "[com.foo-bar]": DEBUG
                    "[org.example]": INFO
                """);
        Files.writeString(dir.resolve("application-prod.yml"), """
                logging:
                  level:
                    "[com.acme]": WARN
                """);

        Map<String, String> prod = profile(dir, "prod");

        assertEquals("DEBUG", RelaxedProperties.get(prod, "logging.level.com.foo-bar"));
        assertEquals("INFO", RelaxedProperties.get(prod, "logging.level.org.example"));
        assertEquals("WARN", RelaxedProperties.get(prod, "logging.level.com.acme"));
    }

    @Test
    @DisplayName("A profile adding one bracketed map entry keeps the base's entries (.properties)")
    void profileMergesBracketedMapKeyByKeyInProperties(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.properties"),
                "logging.level[com.foo-bar]=DEBUG\nlogging.level[org.example]=INFO\n");
        Files.writeString(dir.resolve("application-prod.properties"), "logging.level[com.acme]=WARN\n");

        Map<String, String> prod = profile(dir, "prod");

        assertEquals("DEBUG", RelaxedProperties.get(prod, "logging.level.com.foo-bar"));
        assertEquals("INFO", RelaxedProperties.get(prod, "logging.level.org.example"));
        assertEquals("WARN", RelaxedProperties.get(prod, "logging.level.com.acme"));
    }

    @Test
    @DisplayName("A profile overriding one bracketed map entry replaces only that entry")
    void profileOverridesOnlyTheBracketedEntryItDefines(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.properties"), "x.map[a]=1\nx.map[b]=2\n");
        Files.writeString(dir.resolve("application-prod.properties"), "x.map[a]=OVERRIDE\n");

        Map<String, String> prod = profile(dir, "prod");

        assertEquals("OVERRIDE", RelaxedProperties.get(prod, "x.map.a"));
        assertEquals("2", RelaxedProperties.get(prod, "x.map.b"));
    }

    @Test
    @DisplayName("The bracketed YAML form and the dotted .properties form are the same key")
    void yamlBracketAndPropertiesDottedAreTheSameKey(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                spring:
                  kafka:
                    properties:
                      "[security.protocol]": PLAINTEXT
                """);
        Files.writeString(dir.resolve("application.properties"),
                "spring.kafka.properties.security.protocol=SASL_SSL\n");

        Map<String, String> base = profile(dir, ProfileMerger.BASE_PROFILE_LABEL);

        // .properties wins a key conflict at the same level (ADR-003), which only works if the two
        // spellings are recognized as one key.
        assertEquals("SASL_SSL", RelaxedProperties.get(base, "spring.kafka.properties.security.protocol"));
    }

    @Test
    @DisplayName("Known limitation: keys differing only by '-' or '_' collide once rewritten (ADR-007)")
    void bracketedKeysDifferingOnlyByDashCollide(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.properties"), "logging.level[com.foo-bar]=DEBUG\n");
        Files.writeString(dir.resolve("application-prod.properties"), "logging.level[com.foobar]=WARN\n");

        Map<String, String> prod = profile(dir, "prod");

        // Spring keeps two distinct map entries; relaxed binding here sees one key, overridden.
        assertEquals("WARN", RelaxedProperties.get(prod, "logging.level.com.foo-bar"));
        assertEquals(1, prod.size());
    }

    @Test
    @DisplayName("SCG007 detects a plaintext JAAS password written with the bracketed key (.properties and YAML)")
    void scg007DetectsBracketedJaasConfig(@TempDir Path dir) throws IOException {
        Path props = Files.createDirectories(dir.resolve("props"));
        Files.writeString(props.resolve("application.properties"),
                "spring.kafka.properties[sasl.jaas.config]=" + JAAS + "\n");
        Path yaml = Files.createDirectories(dir.resolve("yaml"));
        Files.writeString(yaml.resolve("application.yml"),
                "spring:\n  kafka:\n    properties:\n      \"[sasl.jaas.config]\": '" + JAAS + "'\n");

        assertTrue(ruleIds(props).contains("SCG007"));
        assertTrue(ruleIds(yaml).contains("SCG007"));
    }

    @Test
    @DisplayName("SCG014 accepts a secure protocol set with the bracketed key instead of assuming PLAINTEXT")
    void scg014HonorsBracketedSecurityProtocol(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.properties"),
                "spring.kafka.bootstrap-servers=broker.example.com:9092\n"
                        + "spring.kafka.properties[security.protocol]=SASL_SSL\n");

        assertFalse(ruleIds(dir).contains("SCG014"));
    }

    @Test
    @DisplayName("SCG006 still detects a hardcoded Kafka keystore password after the key is rewritten")
    void scg006StillDetectsRewrittenKafkaKeystorePassword(@TempDir Path dir) throws IOException {
        // Not a regression test for the bracket bug: SCG006 matches secrets by key-name pattern and
        // already caught the bracketed spelling. This guards against the rewrite breaking that.
        Files.writeString(dir.resolve("application.properties"),
                "spring.kafka.properties[ssl.keystore.password]=changeit\n");

        assertTrue(ruleIds(dir).contains("SCG006"));
    }

    private static Map<String, String> profile(Path dir, String label) throws IOException {
        return effectiveConfigs(dir).stream()
                .filter(config -> config.profileLabel().equals(label))
                .findFirst()
                .orElseThrow()
                .properties();
    }

    private static List<EffectiveConfig> effectiveConfigs(Path dir) throws IOException {
        List<EffectiveConfig> result = new ArrayList<>();
        for (GroupedConfigFile group : new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(dir))) {
            result.addAll(new ProfileMerger().merge(group.mergedFile()));
        }
        return result;
    }

    private static List<String> ruleIds(Path dir) throws IOException {
        return new RuleEngine(RuleRegistry.discoverRules()).run(effectiveConfigs(dir)).stream()
                .map(Finding::ruleId)
                .toList();
    }
}
