package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * One list written in different formats (comma-separated, indexed, empty), through the whole
 * pipeline on the real {@code management.endpoints.web.exposure.include} key. The comma-separated
 * and indexed spellings are different keys ({@code include} vs. {@code include[0]}), so each case
 * checks that the higher-precedence one replaces the other entirely instead of both surviving.
 * Expected behavior confirmed against Spring Boot 4.1.1 through /actuator/configprops (see
 * VALIDATION.md, "ProfileMerger correctness benchmark").
 */
class ListFormatsTest {

    private static final String KEY = "management.endpoints.web.exposure.include";
    private static final String BASE = ProfileMerger.BASE_PROFILE_LABEL;

    @Test
    @DisplayName("A comma-separated .properties list replaces an indexed .yml list in the same directory")
    void commaSeparatedPropertiesReplacesIndexedYaml(@TempDir Path dir) throws IOException {
        write(dir, "application.properties", KEY + "=health,info\n");
        write(dir, "application.yml", yamlInclude("[\"*\"]"));

        assertThat(scg001Profiles(dir)).isEmpty();
    }

    @Test
    @DisplayName("An indexed .properties list replaces a comma-separated .yml string in the same directory")
    void indexedPropertiesReplacesCommaSeparatedYaml(@TempDir Path dir) throws IOException {
        write(dir, "application.properties", KEY + "[0]=health\n");
        write(dir, "application.yml", yamlInclude("\"*\""));

        assertThat(scg001Profiles(dir)).isEmpty();
    }

    @Test
    @DisplayName("A wildcard in an indexed .properties list wins over a safe .yml value")
    void indexedPropertiesWildcardWinsOverSafeYaml(@TempDir Path dir) throws IOException {
        write(dir, "application.properties", KEY + "[0]=*\n");
        write(dir, "application.yml", yamlInclude("\"health\""));

        assertThat(scg001Profiles(dir)).containsExactly(BASE);
    }

    @Test
    @DisplayName("Spaces after the commas don't hide a sensitive endpoint")
    void spacesAfterCommasAreStripped(@TempDir Path dir) throws IOException {
        write(dir, "application.properties", KEY + "=health, env\n");

        assertThat(scg001Messages(dir)).singleElement().asString().contains("remain unrestricted: env.");
    }

    @Test
    @DisplayName("An empty .properties value clears the .yml list in the same directory")
    void emptyPropertiesValueClearsYamlList(@TempDir Path dir) throws IOException {
        write(dir, "application.properties", KEY + "=\n");
        write(dir, "application.yml", yamlInclude("[\"*\"]"));

        assertThat(scg001Profiles(dir)).isEmpty();
    }

    @Test
    @DisplayName("A profile's empty .properties value clears the base's list")
    void profileEmptyPropertiesValueClearsBaseList(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", yamlInclude("[\"*\"]"));
        write(dir, "application-prod.properties", KEY + "=\n");

        assertThat(scg001Profiles(dir)).containsExactly(BASE);
    }

    @Test
    @DisplayName("A profile's empty YAML list clears the base's list")
    void profileEmptyYamlListClearsBaseList(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", yamlInclude("[\"*\"]"));
        write(dir, "application-prod.yml", yamlInclude("[]"));

        assertThat(scg001Profiles(dir)).containsExactly(BASE);
    }

    @Test
    @DisplayName("Control: a profile that doesn't mention the key keeps the base's list")
    void profileOmittingTheKeyKeepsBaseList(@TempDir Path dir) throws IOException {
        write(dir, "application.yml", yamlInclude("[\"*\"]"));
        write(dir, "application-prod.yml", "server:\n  port: 8080\n");

        assertThat(scg001Profiles(dir)).containsExactlyInAnyOrder(BASE, "prod");
    }

    private static String yamlInclude(String value) {
        return "management:\n  endpoints:\n    web:\n      exposure:\n        include: " + value + "\n";
    }

    private static void write(Path dir, String name, String content) throws IOException {
        Files.writeString(dir.resolve(name), content);
    }

    private static List<String> scg001Profiles(Path dir) throws IOException {
        return scg001(dir).stream().map(Finding::profileLabel).toList();
    }

    private static List<String> scg001Messages(Path dir) throws IOException {
        return scg001(dir).stream().map(Finding::message).toList();
    }

    /** SCG001's sensitive-endpoint findings (the show-values one needs show-values set, never here). */
    private static List<Finding> scg001(Path dir) throws IOException {
        List<EffectiveConfig> configs = new ArrayList<>();
        for (GroupedConfigFile group : new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(dir))) {
            configs.addAll(new ProfileMerger().merge(group.mergedFile()));
        }
        return new RuleEngine(RuleRegistry.discoverRules()).run(configs).stream()
                .filter(finding -> finding.ruleId().equals("SCG001"))
                .toList();
    }
}
