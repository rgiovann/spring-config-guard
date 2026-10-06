package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;


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
        assertThat(groups.getFirst().documents())
                .extracting(SourceDocument::file, SourceDocument::fileProfile)
                .containsExactly(
                        tuple(dir.resolve("application.yml"), Optional.empty()),
                        tuple(dir.resolve("application-prod.yml"), Optional.of("prod")));
    }

    @Test
    @DisplayName("P12: an on-profile inside a profile-specific file is an extra condition, on top of the file's profile")
    void onProfileInsideProfileSpecificFileShouldBeAnExtraCondition(@TempDir Path dir) throws IOException {
        // Spring Boot 4.1.1 accepts on-profile in application-x.yml and applies the document only
        // when both the file's profile and the expression match (VALIDATION.md, P12).
        Files.writeString(dir.resolve("application.yml"), "server.port: 8080");
        Files.writeString(dir.resolve("application-staging.yml"), """
                spring:
                  config:
                    activate:
                      on-profile: another-name
                custom.key: value
                """);

        SourceDocument staging = grouper.group(loader.loadDirectory(dir)).getFirst().documents().getLast();

        assertThat(staging.fileProfile()).contains("staging");
        assertThat(staging.appliesTo(Set.of("staging"))).isFalse();
        assertThat(staging.appliesTo(Set.of("another-name"))).isFalse();
        assertThat(staging.appliesTo(Set.of("staging", "another-name"))).isTrue();
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

        List<EffectiveConfig> configs = merge(dir);

        assertThat(configFor(configs, ProfileMerger.BASE_PROFILE_LABEL).sourceFile())
                .isEqualTo(dir.resolve("application.yml"));
        assertThat(configFor(configs, "dev").sourceFile())
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

        assertThat(properties(dir, ProfileMerger.BASE_PROFILE_LABEL))
                .containsEntry("from.yaml", "valor-yaml")
                .containsEntry("from.properties", "valor-properties");
    }

    @Test
    @DisplayName("Should let .properties win a key conflict over .yml when folding two base files")
    void shouldLetPropertiesWinKeyConflictWhenFoldingBaseFiles(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "shared.key: from-yaml");
        Files.writeString(dir.resolve("application.properties"), "shared.key=from-properties");

        assertThat(properties(dir, ProfileMerger.BASE_PROFILE_LABEL)).containsEntry("shared.key", "from-properties");
    }

    @Test
    @DisplayName("Should fold two files naming the same profile with disjoint keys, keeping both")
    void shouldFoldTwoFilesNamingSameProfileKeepingBothDisjointKeys(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-prod.yml"), "from.yaml: valor-yaml");
        Files.writeString(dir.resolve("application-prod.properties"), "from.properties=valor-properties");

        assertThat(properties(dir, "prod"))
                .containsEntry("from.yaml", "valor-yaml")
                .containsEntry("from.properties", "valor-properties");
    }

    @Test
    @DisplayName("Should let .properties win a key conflict over .yml when folding two same-profile files")
    void shouldLetPropertiesWinKeyConflictWhenFoldingSameProfileFiles(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-prod.yml"), "shared.key: from-yaml");
        Files.writeString(dir.resolve("application-prod.properties"), "shared.key=from-properties");

        assertThat(properties(dir, "prod")).containsEntry("shared.key", "from-properties");
    }

    @Test
    @DisplayName("Should let .yml win a key conflict over .yaml when folding two base files")
    void shouldLetYmlWinKeyConflictOverYamlWhenFoldingBaseFiles(@TempDir Path dir) throws IOException {
        // Spring Boot 4.1.1 gives application.yml precedence over application.yaml
        // (VALIDATION.md, "ProfileMerger correctness benchmark", case 35).
        Files.writeString(dir.resolve("application.yml"), "shared.key: from-yml");
        Files.writeString(dir.resolve("application.yaml"), "shared.key: from-yaml");

        assertThat(properties(dir, ProfileMerger.BASE_PROFILE_LABEL)).containsEntry("shared.key", "from-yml");
    }

    @Test
    @DisplayName("Should let .yml win a key conflict over .yaml when folding two same-profile files")
    void shouldLetYmlWinKeyConflictOverYamlWhenFoldingSameProfileFiles(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-prod.yml"), "shared.key: from-yml");
        Files.writeString(dir.resolve("application-prod.yaml"), "shared.key: from-yaml");

        assertThat(properties(dir, "prod")).containsEntry("shared.key", "from-yml");
    }

    @Test
    @DisplayName("Should fold an on-profile block from a base file with a same-named profile file, keeping disjoint keys from both")
    void shouldFoldOnProfileBlockWithNamedProfileFileKeepingBothDisjointKeys(@TempDir Path dir) throws IOException {
        // This and the next test encode a precedence rule the official Spring
        // Boot docs don't cover -- confirmed empirically against a real
        // Spring Boot 4.1.1 app via /actuator/env (spring-env-benchmark; see
        // ARCHITECTURE.md, ADR-012), not assumed.
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

        assertThat(properties(dir, "prod"))
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

        assertThat(properties(dir, "prod")).containsEntry("shared.key", "from-named-file");
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

        assertThat(properties(dir, "prod")).containsEntry("from.on-profile-block", "valor-on-profile");
    }

    @Test
    @DisplayName("Should not throw and should preserve an explicit-null override when folding two same-profile files")
    void shouldPreserveNullOverrideWhenFoldingSameProfileFiles(@TempDir Path dir) throws IOException {
        // Regression test: folding a NAMED profile's sources reuses
        // ProfileMerger's merge logic, which resolves an explicit-null
        // override as part of the fold itself (not deferrable), now to an
        // empty string, as Spring Boot loads a YAML null. It used to be a
        // Java null, which ConfigDocument's Map.copyOf threw on. Found via the
        // live /actuator/env benchmark above, not by inspection -- no purely
        // local fixture had combined a multi-source fold with a null override
        // before that run.
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-prod.yaml"), "app.other: value-a");
        Files.writeString(dir.resolve("application-prod.yml"), "app.nullable: null");

        assertThat(properties(dir, "prod"))
                .containsEntry("app.other", "value-a")
                .containsEntry("app.nullable", "");
    }

    private List<EffectiveConfig> merge(Path dir) throws IOException {
        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        assertThat(groups).hasSize(1);
        return new ProfileMerger().merge(groups.getFirst());
    }

    private Map<String, String> properties(Path dir, String label) throws IOException {
        return configFor(merge(dir), label).properties();
    }

    private static EffectiveConfig configFor(List<EffectiveConfig> configs, String label) {
        List<EffectiveConfig> matches = configs.stream().filter(config -> config.profileLabel().equals(label)).toList();
        assertThat(matches).hasSize(1);
        return matches.getFirst();
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

    @Test
    @DisplayName("Should order files as Spring Boot does: no profile in the name first, then .yaml < .yml < .properties, then profile files")
    void shouldOrderFilesAsSpringBootDoes(@TempDir Path dir) throws IOException {
        for (String name : List.of("application-b.properties", "application-a.yml", "application.properties",
                "application.yaml", "application.yml", "application-a.properties")) {
            Files.writeString(dir.resolve(name), "key: " + name);
        }

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));

        assertThat(groups.getFirst().documents())
                .extracting(document -> document.file().getFileName().toString())
                .containsExactly("application.yaml", "application.yml", "application.properties",
                        "application-a.yml", "application-a.properties", "application-b.properties");
    }

    @Test
    @DisplayName("P11: application.properties overrides an on-profile block of application.yml, as it comes later in source order")
    void propertiesBaseShouldOverrideOnProfileBlockOfYml(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                shared.key: from-yml
                ---
                spring.config.activate.on-profile: a
                shared.key: from-yml-block
                """);
        Files.writeString(dir.resolve("application.properties"), "shared.key=from-properties");

        assertThat(properties(dir, "a")).containsEntry("shared.key", "from-properties");
    }
}
