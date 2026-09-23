package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ConfigImportCoverage — the detector behind Main's unconditional
 * "spring.config.import was not scanned" coverage warning. Only exercises the
 * detection/aggregation logic; Main owns the actual stderr message.
 */
class ConfigImportCoverageTest {

    private static final Path FILE_A = Path.of("application.yml");
    private static final Path FILE_B = Path.of("application-prod.yml");

    @Test
    @DisplayName("No EffectiveConfig declares spring.config.import -> empty set")
    void noImportKeyPresentReturnsEmptySet() {
        List<EffectiveConfig> configs = List.of(
                new EffectiveConfig(FILE_A, ProfileMerger.BASE_PROFILE_LABEL, Map.of("server.port", "8080"))
        );

        assertTrue(ConfigImportCoverage.filesWithUnfollowedImport(configs).isEmpty());
    }

    @Test
    @DisplayName("A file declaring spring.config.import is reported")
    void fileWithImportKeyIsReported() {
        List<EffectiveConfig> configs = List.of(
                new EffectiveConfig(FILE_A, ProfileMerger.BASE_PROFILE_LABEL,
                        Map.of("spring.config.import", "file:./secrets.yml"))
        );

        Set<String> result = ConfigImportCoverage.filesWithUnfollowedImport(configs);
        assertEquals(1, result.size());
        assertTrue(result.contains(FILE_A.toString()));
    }

    @Test
    @DisplayName("Same file counted once even if the key is inherited across multiple profiles")
    void sameFileAcrossProfilesCountsOnce() {
        List<EffectiveConfig> configs = List.of(
                new EffectiveConfig(FILE_A, ProfileMerger.BASE_PROFILE_LABEL,
                        Map.of("spring.config.import", "file:./secrets.yml")),
                new EffectiveConfig(FILE_A, "prod",
                        Map.of("spring.config.import", "file:./secrets.yml"))
        );

        assertEquals(1, ConfigImportCoverage.filesWithUnfollowedImport(configs).size());
    }

    @Test
    @DisplayName("Only files that actually declare the key are reported, not every scanned file")
    void onlyFlagsFilesThatDeclareTheKey() {
        List<EffectiveConfig> configs = List.of(
                new EffectiveConfig(FILE_A, ProfileMerger.BASE_PROFILE_LABEL,
                        Map.of("spring.config.import", "file:./secrets.yml")),
                new EffectiveConfig(FILE_B, "prod", Map.of("server.port", "8080"))
        );

        Set<String> result = ConfigImportCoverage.filesWithUnfollowedImport(configs);
        assertEquals(1, result.size());
        assertTrue(result.contains(FILE_A.toString()));
        assertFalse(result.contains(FILE_B.toString()));
    }
}
