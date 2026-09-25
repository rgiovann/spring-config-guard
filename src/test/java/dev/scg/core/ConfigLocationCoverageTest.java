package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for ConfigLocationCoverage — the detector behind Main's unconditional
 * "config files in more than one Spring config location" coverage warning. Only exercises the
 * detection logic; Main owns the actual stderr message. Paths are never read from disk, so
 * plain (non-existent) absolute paths are enough.
 */
class ConfigLocationCoverageTest {

    private static final Path APP = Path.of("/work/app").toAbsolutePath();
    private static final Path MAIN_RESOURCES = APP.resolve("src/main/resources");

    private static EffectiveConfig config(Path file, String profile) {
        return new EffectiveConfig(file, profile, Map.of());
    }

    private static EffectiveConfig base(Path file) {
        return config(file, ProfileMerger.BASE_PROFILE_LABEL);
    }

    @Test
    @DisplayName("A single location -> empty set")
    void singleLocationIsNotReported() {
        List<EffectiveConfig> configs = List.of(
                base(MAIN_RESOURCES.resolve("application.yml")),
                config(MAIN_RESOURCES.resolve("application-prod.yml"), "prod")
        );

        assertTrue(ConfigLocationCoverage.modulesWithMultipleLocations(configs).isEmpty());
    }

    @Test
    @DisplayName("src/main/resources + src/main/resources/config (classpath:/ + classpath:/config/) is reported")
    void classpathRootAndClasspathConfigAreReported() {
        List<EffectiveConfig> configs = List.of(
                base(MAIN_RESOURCES.resolve("application.yml")),
                base(MAIN_RESOURCES.resolve("config/application.yml"))
        );

        assertEquals(Set.of(APP), ConfigLocationCoverage.modulesWithMultipleLocations(configs));
    }

    @Test
    @DisplayName("src/main/resources + config/ at the module root (classpath:/ + file:./config/) is reported")
    void classpathRootAndExternalConfigAreReported() {
        List<EffectiveConfig> configs = List.of(
                base(MAIN_RESOURCES.resolve("application.yml")),
                config(APP.resolve("config/application-prod.yml"), "prod")
        );

        assertEquals(Set.of(APP), ConfigLocationCoverage.modulesWithMultipleLocations(configs));
    }

    @Test
    @DisplayName("All three locations of the same module count as one application")
    void allThreeLocationsCountAsOneApplication() {
        List<EffectiveConfig> configs = List.of(
                base(MAIN_RESOURCES.resolve("application.yml")),
                base(MAIN_RESOURCES.resolve("config/application.yml")),
                base(APP.resolve("config/application.yml")),
                config(APP.resolve("config/application-prod.yml"), "prod")
        );

        assertEquals(Set.of(APP), ConfigLocationCoverage.modulesWithMultipleLocations(configs));
    }

    @Test
    @DisplayName("Sibling modules of a monorepo, each with a single location, are never merged into one application")
    void siblingModulesWithSingleLocationAreNotReported() {
        Path moduleA = Path.of("/work/mono/module-a").toAbsolutePath();
        Path moduleB = Path.of("/work/mono/module-b").toAbsolutePath();
        List<EffectiveConfig> configs = List.of(
                base(moduleA.resolve("src/main/resources/application.yml")),
                base(moduleB.resolve("src/main/resources/application.yml"))
        );

        assertTrue(ConfigLocationCoverage.modulesWithMultipleLocations(configs).isEmpty());
    }

    @Test
    @DisplayName("In a monorepo, only the module that actually has multiple locations is reported")
    void onlyTheModuleWithMultipleLocationsIsReported() {
        Path moduleA = Path.of("/work/mono/module-a").toAbsolutePath();
        Path moduleB = Path.of("/work/mono/module-b").toAbsolutePath();
        List<EffectiveConfig> configs = List.of(
                base(moduleA.resolve("src/main/resources/application.yml")),
                base(moduleA.resolve("config/application.yml")),
                base(moduleB.resolve("src/main/resources/application.yml"))
        );

        assertEquals(Set.of(moduleA), ConfigLocationCoverage.modulesWithMultipleLocations(configs));
    }

    @Test
    @DisplayName("A config/ directory without a sibling src/main/resources is not evidence of a Spring module")
    void configDirectoryWithoutMainResourcesIsNotReported() {
        Path other = Path.of("/work/other").toAbsolutePath();
        List<EffectiveConfig> configs = List.of(
                base(other.resolve("config/application.yml")),
                base(other.resolve("application.yml"))
        );

        assertTrue(ConfigLocationCoverage.modulesWithMultipleLocations(configs).isEmpty());
    }

    @Test
    @DisplayName("src/test/resources is not one of the recognized locations")
    void testResourcesAreNotARecognizedLocation() {
        List<EffectiveConfig> configs = List.of(
                base(MAIN_RESOURCES.resolve("application.yml")),
                base(APP.resolve("src/test/resources/application.yml"))
        );

        assertTrue(ConfigLocationCoverage.modulesWithMultipleLocations(configs).isEmpty());
    }

    @Test
    @DisplayName("Relative source paths are resolved before comparing locations")
    void relativePathsAreResolved() {
        List<EffectiveConfig> configs = List.of(
                base(Path.of("rel-app/src/main/resources/application.yml")),
                base(Path.of("rel-app/./config/application.yml"))
        );

        assertEquals(Set.of(Path.of("rel-app").toAbsolutePath().normalize()),
                ConfigLocationCoverage.modulesWithMultipleLocations(configs));
    }
}
