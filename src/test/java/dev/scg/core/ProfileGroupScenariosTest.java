package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the rows of VALIDATION.md, "Profile groups": each test writes the files of one row,
 * runs the pipeline (ConfigLoader, ConfigFileGrouper, ProfileMerger) and checks the values of
 * k1-k4 in the configuration SCG builds for the profile activated against the values Spring Boot
 * 4.1.1 resolved through /actuator/env. The base is Spring's "no profile active" row.
 */
class ProfileGroupScenariosTest {

    private static final String BASE = ProfileMerger.BASE_PROFILE_LABEL;

    @Test
    @DisplayName("G1: a group's profile files apply in activation order, on-profile blocks in file order")
    void g1(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", """
                spring.profiles.group.dev: [a, b]
                k1: base
                k2: base
                k3: base
                k4: base
                ---
                spring.config.activate.on-profile: b
                k4: b-block
                ---
                spring.config.activate.on-profile: a
                k4: a-block
                """);
        write(dir, "application-dev.yml", "k1: dev\nk2: dev\nk3: dev\n");
        write(dir, "application-a.yml", "k1: a\nk2: a\n");
        write(dir, "application-b.yml", "k1: b\n");

        List<EffectiveConfig> configs = merge(dir);

        assertThat(keys(configs, "dev")).isEqualTo(Map.of("k1", "b", "k2", "a", "k3", "dev", "k4", "a-block"));
        assertThat(keys(configs, BASE)).isEqualTo(Map.of("k1", "base", "k2", "base", "k3", "base", "k4", "base"));
        assertThat(keys(configs, "a")).isEqualTo(Map.of("k1", "a", "k2", "a", "k3", "base", "k4", "a-block"));
    }

    @Test
    @DisplayName("G2: groups nest: dev activates a, which activates b")
    void g2(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", "spring.profiles.group.dev: [a]\nspring.profiles.group.a: [b]\nk1: base\n");
        write(dir, "application-b.yml", "k1: b\n");

        assertThat(keys(merge(dir), "dev")).containsEntry("k1", "b");
    }

    @Test
    @DisplayName("G3: a group declared in a profile-specific file is ignored")
    void g3(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", "k1: base\n");
        write(dir, "application-dev.yml", "spring.profiles.group.dev: [a]\nk1: dev\n");
        write(dir, "application-a.yml", "k2: a\n");

        assertThat(keys(merge(dir), "dev")).isEqualTo(Map.of("k1", "dev"));
    }

    @Test
    @DisplayName("G4: a group declared in an on-profile document applies")
    void g4(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", """
                k1: base
                ---
                spring.config.activate.on-profile: dev
                spring.profiles.group.dev: [a]
                k1: dev
                """);
        write(dir, "application-a.yml", "k2: a\n");

        assertThat(keys(merge(dir), "dev")).isEqualTo(Map.of("k1", "dev", "k2", "a"));
    }

    @Test
    @DisplayName("G5: spring.profiles.include is not evaluated: the base keeps its own k1, where Spring has x's")
    void g5(@TempDir Path dir) throws IOException {
        // A known divergence (ARCHITECTURE.md, ADR-013): Spring activates x always, and then not
        // default. Pinned so that a change to it shows up here.
        write(dir, "application.yml", "spring.profiles.include: [x]\nk1: base\n");
        write(dir, "application-x.yml", "k1: x\n");
        write(dir, "application-default.yml", "k3: default\n");

        assertThat(keys(merge(dir), BASE)).isEqualTo(Map.of("k1", "base", "k3", "default"));
    }

    @Test
    @DisplayName("G6: a group written comma-separated in .properties")
    void g6(@TempDir Path dir) throws IOException {
        write(dir, "application.properties", "spring.profiles.group.dev=a,b\nk1=base\n");
        write(dir, "application-a.yml", "k1: a\n");
        write(dir, "application-b.yml", "k2: b\n");

        assertThat(keys(merge(dir), "dev")).isEqualTo(Map.of("k1", "a", "k2", "b"));
    }

    @Test
    @DisplayName("G7: a group for the default profile applies to the base")
    void g7(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", "spring.profiles.group.default: [a]\nk1: base\n");
        write(dir, "application-a.yml", "k1: a\n");

        assertThat(keys(merge(dir), BASE)).isEqualTo(Map.of("k1", "a"));
    }

    @Test
    @DisplayName("A document a group activates with its profile is no longer counted as not evaluated")
    void groupActivatedCombinationIsEvaluated(@TempDir Path dir) throws IOException {
        // jhipster: group.dev: [secret-samples], and an on-profile: dev document inside
        // application-secret-samples.yml.
        write(dir, "application.yml", "spring.profiles.group.dev: [secret-samples]\nk1: base\n");
        write(dir, "application-secret-samples.yml", """
                k2: samples
                ---
                spring.config.activate.on-profile: dev
                k3: samples-dev
                ---
                spring.config.activate.on-profile: prod
                k4: samples-prod
                """);

        List<GroupedConfigFile> groups = new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(dir));

        assertThat(keys(merge(dir), "dev")).isEqualTo(Map.of("k1", "base", "k2", "samples", "k3", "samples-dev"));
        assertThat(new ProfileMerger().documentsNotEvaluated(groups.getFirst()))
                .extracting(document -> document.document().properties())
                .containsExactly(Map.of("k4", "samples-prod"));
    }

    @Test
    @DisplayName("Source file: a profile's own application-P file, even when a group member's file names P later")
    void sourceFileShouldBeTheProfilesOwnFile(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", "spring.profiles.group.dev: [secret-samples]\nk1: base\n");
        write(dir, "application-dev.yml", "k1: dev\n");
        write(dir, "application-secret-samples.yml", "k2: samples\n---\nspring.config.activate.on-profile: dev\nk3: samples-dev\n");

        List<EffectiveConfig> configs = merge(dir);

        assertThat(configs.stream().filter(config -> config.profileLabel().equals("dev")).findFirst().orElseThrow().sourceFile())
                .isEqualTo(dir.resolve("application-dev.yml"));
    }

    private static void write(Path dir, String name, String content) throws IOException {
        Files.writeString(dir.resolve(name), content);
    }

    private static List<EffectiveConfig> merge(Path dir) throws IOException {
        List<GroupedConfigFile> groups = new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(dir));
        assertThat(groups).hasSize(1);
        return new ProfileMerger().merge(groups.getFirst());
    }

    /** The k1-k4 entries of the configuration with this label. */
    private static Map<String, String> keys(List<EffectiveConfig> configs, String label) {
        List<EffectiveConfig> matches = configs.stream().filter(config -> config.profileLabel().equals(label)).toList();
        assertThat(matches).hasSize(1);
        Map<String, String> keys = new java.util.TreeMap<>(matches.getFirst().properties());
        keys.keySet().retainAll(List.of("k1", "k2", "k3", "k4"));
        return keys;
    }
}
