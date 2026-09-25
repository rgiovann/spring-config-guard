package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


class ConfigFileGrouperTest {

    private final ConfigLoader loader = new ConfigLoader();
    private final ConfigFileGrouper grouper = new ConfigFileGrouper();

    @Test
    @DisplayName("Should group application.yml and application-prod.yml in the same group")
    void shouldGroupApplicationYmlAndApplicationProdYmlInSameGroup(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "*"
                """);
        Files.writeString(dir.resolve("application-prod.yml"), """
                spring:
                  h2:
                    console:
                      enabled: true
                """);

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));

        assertThat(groups).hasSize(1);
        assertThat(groups.getFirst().mergedFile().documents()).hasSize(2);
    }

    @Test
    @DisplayName("Should derive the profile from the file name, ignoring the internal on-profile")
    void shouldDeriveProfileFromFileNameIgnoringInternalOnProfile(@TempDir Path dir) throws IOException {
        // Simulates the confirmed scenario: on-profile inside a specific file
        // is invalid in real Spring, but our parser can still read the YAML.
        // The file name should take precedence, not the content.
        Files.writeString(dir.resolve("application.yml"), "server.port: 8080");
        Files.writeString(dir.resolve("application-staging.yml"), """
                spring:
                  config:
                    activate:
                      on-profile: another-name
                custom.key: value
                """);

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigFile merged = groups.getFirst().mergedFile();

        boolean hasStagingLabel = merged.documents().stream()
                .anyMatch(doc -> doc.profile().equals(java.util.Optional.of("staging")));
        boolean hasOnProfileValueAsLabel = merged.documents().stream()
                .anyMatch(doc -> doc.profile().equals(java.util.Optional.of("outro-nome-qualquer")));

        assertThat(hasStagingLabel).isTrue();
        assertThat(hasOnProfileValueAsLabel).isFalse();
    }

    @Test
    @DisplayName("Should not group files from different directories")
    void shouldNotGroupFilesFromDifferentDirectories(@TempDir Path dir) throws IOException {
        Path moduleA = Files.createDirectories(dir.resolve("module-a"));
        Path moduleB = Files.createDirectories(dir.resolve("module-b"));

        Files.writeString(moduleA.resolve("application.yml"), "a.key: valorA");
        Files.writeString(moduleB.resolve("application.yml"), "b.key: valorB");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));

        assertThat(groups).hasSize(2); // one group per directory, never mixed
    }

    @Test
    @DisplayName("Should track the correct physical file for each profile label")
    void shouldTrackCorrectPhysicalFileForEachProfileLabel(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-dev.yml"), "dev.key: valor");

        GroupedConfigFile group = grouper.group(loader.loadDirectory(dir)).getFirst();

        assertThat(group.sourceByProfileLabel().get(ProfileMerger.BASE_PROFILE_LABEL))
                .isEqualTo(dir.resolve("application.yml"));
        assertThat(group.sourceByProfileLabel().get("dev"))
                .isEqualTo(dir.resolve("application-dev.yml"));
    }

    @Test
    @DisplayName("Should fold two base files with disjoint keys into one base document, keeping both")
    void shouldFoldTwoBaseFilesWithDisjointKeysKeepingBoth(@TempDir Path dir) throws IOException {
        // Reproduces the bug found via the /actuator/env benchmark (ARCHITECTURE.md,
        // ADR-003): application.yml + application.properties coexisting as
        // base files used to silently lose one of the two files' properties
        // entirely, since ProfileMerger.findBaseProperties() only ever looked
        // at the first base document found.
        Files.writeString(dir.resolve("application.yml"), "from.yaml: valor-yaml");
        Files.writeString(dir.resolve("application.properties"), "from.properties=valor-properties");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigDocument base = onlyBaseDocument(groups.get(0));

        assertThat(base.properties())
                .containsEntry("from.yaml", "valor-yaml")
                .containsEntry("from.properties", "valor-properties");
    }

    @Test
    @DisplayName("Should let .properties win a key conflict over .yml when folding two base files")
    void shouldLetPropertiesWinKeyConflictWhenFoldingBaseFiles(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "shared.key: from-yaml");
        Files.writeString(dir.resolve("application.properties"), "shared.key=from-properties");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigDocument base = onlyBaseDocument(groups.getFirst());

        assertThat(base.properties()).containsEntry("shared.key", "from-properties");
    }

    @Test
    @DisplayName("Should fold two files naming the same profile with disjoint keys, keeping both")
    void shouldFoldTwoFilesNamingSameProfileKeepingBothDisjointKeys(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-prod.yml"), "from.yaml: valor-yaml");
        Files.writeString(dir.resolve("application-prod.properties"), "from.properties=valor-properties");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigDocument prod = onlyDocumentForProfile(groups.getFirst(), "prod");

        assertThat(prod.properties())
                .containsEntry("from.yaml", "valor-yaml")
                .containsEntry("from.properties", "valor-properties");
    }

    @Test
    @DisplayName("Should let .properties win a key conflict over .yml when folding two same-profile files")
    void shouldLetPropertiesWinKeyConflictWhenFoldingSameProfileFiles(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-prod.yml"), "shared.key: from-yaml");
        Files.writeString(dir.resolve("application-prod.properties"), "shared.key=from-properties");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigDocument prod = onlyDocumentForProfile(groups.getFirst(), "prod");

        assertThat(prod.properties()).containsEntry("shared.key", "from-properties");
    }

    @Test
    @DisplayName("Should fold an on-profile block from a base file with a same-named profile file, keeping disjoint keys from both")
    void shouldFoldOnProfileBlockWithNamedProfileFileKeepingBothDisjointKeys(@TempDir Path dir) throws IOException {
        // This and the next test encode a precedence rule the official Spring
        // Boot docs don't cover -- confirmed empirically against a real
        // Spring Boot 4.1.1 app via /actuator/env (spring-env-benchmark; see
        // ARCHITECTURE.md, ADR-003), not assumed.
        Files.writeString(dir.resolve("application.yml"), """
                base.key: valor
                ---
                spring:
                  config:
                    activate:
                      on-profile: prod
                from:
                  on-profile-block: valor-on-profile
                """);
        Files.writeString(dir.resolve("application-prod.yml"), "from.named-file: valor-named-file");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigDocument prod = onlyDocumentForProfile(groups.getFirst(), "prod");

        assertThat(prod.properties())
                .containsEntry("from.on-profile-block", "valor-on-profile")
                .containsEntry("from.named-file", "valor-named-file");
    }

    @Test
    @DisplayName("Should let a same-named profile file win a key conflict over an on-profile block in a base file")
    void shouldLetNamedProfileFileWinKeyConflictOverOnProfileBlock(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                base.key: valor
                ---
                spring:
                  config:
                    activate:
                      on-profile: prod
                shared.key: from-on-profile-block
                """);
        Files.writeString(dir.resolve("application-prod.yml"), "shared.key: from-named-file");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigDocument prod = onlyDocumentForProfile(groups.getFirst(), "prod");

        assertThat(prod.properties()).containsEntry("shared.key", "from-named-file");
    }

    @Test
    @DisplayName("Should still produce a document for an on-profile block with no same-named profile file")
    void shouldStillProduceDocumentForOnProfileBlockAlone(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                base.key: valor
                ---
                spring:
                  config:
                    activate:
                      on-profile: prod
                from.on-profile-block: valor-on-profile
                """);

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigDocument prod = onlyDocumentForProfile(groups.getFirst(), "prod");

        assertThat(prod.properties()).containsEntry("from.on-profile-block", "valor-on-profile");
    }

    @Test
    @DisplayName("Should not throw and should preserve an explicit-null override when folding two same-profile files")
    void shouldPreserveNullOverrideWhenFoldingSameProfileFiles(@TempDir Path dir) throws IOException {
        // Regression test: folding a NAMED profile's sources reuses
        // ProfileMerger's merge logic, which resolves an explicit-null
        // override to a real Java null value as part of the fold itself
        // (not deferrable). ConfigDocument must tolerate that -- it used to
        // build its properties map via Map.copyOf, which throws on a null
        // value. Found via the live /actuator/env benchmark above, not by
        // inspection -- no purely local fixture had combined a multi-source
        // fold with a null override before that run.
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-prod.yml"), "app.other: value-a");
        Files.writeString(dir.resolve("application-prod.yaml"), "app.nullable: null");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigDocument prod = onlyDocumentForProfile(groups.getFirst(), "prod");

        assertThat(prod.properties())
                .containsEntry("app.other", "value-a")
                .containsEntry("app.nullable", null);
    }

    private ConfigDocument onlyBaseDocument(GroupedConfigFile group) {
        return onlyDocumentMatching(group, doc -> doc.profile().isEmpty());
    }

    private ConfigDocument onlyDocumentForProfile(GroupedConfigFile group, String profile) {
        return onlyDocumentMatching(group, doc -> doc.profile().equals(java.util.Optional.of(profile)));
    }

    private ConfigDocument onlyDocumentMatching(GroupedConfigFile group, java.util.function.Predicate<ConfigDocument> predicate) {
        List<ConfigDocument> matches = group.mergedFile().documents().stream().filter(predicate).toList();
        assertThat(matches).hasSize(1);
        return matches.get(0);
    }

    @Test
    @DisplayName("Should treat application with a trailing hyphen and no suffix as base, not as an empty profile")
    void shouldTreatApplicationWithHyphenWithoutSuffixAsBaseNotEmptyProfile(@TempDir Path dir) throws IOException {
        // Defensive edge case, not confirmed against real Spring: "application-.yml"
        // falls into the "malformed" profile branch —
        // treated as base and should not throw an exception.
        Files.writeString(dir.resolve("application-.yml"), "key: valor");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));

        assertThat(groups).hasSize(1); // should not throw an exception
    }
}

