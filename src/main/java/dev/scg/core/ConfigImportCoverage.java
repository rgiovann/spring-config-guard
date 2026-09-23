package dev.scg.core;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Detects {@code spring.config.import} present in a scanned file, so its silent absence from the
 * report doesn't read as if the file were fully covered. Does not resolve or follow the import --
 * see BACKLOG.md for the five concrete reasons the full import graph stays out of scope
 * (recursive resolution, per-file base-dir relativity, precedence interacting with profile merge,
 * and network-backed locations like {@code configserver:} that aren't statically resolvable at
 * any effort level).
 */
public final class ConfigImportCoverage {

    private static final String IMPORT_KEY = "spring.config.import";

    private ConfigImportCoverage() {
    }

    /**
     * Distinct source files (by {@link EffectiveConfig#sourceFile()}) whose effective configuration
     * declares {@code spring.config.import}. A file with multiple profiles only counts once, even
     * if every one of its {@link EffectiveConfig}s carries the same inherited key.
     */
    public static Set<String> filesWithUnfollowedImport(List<EffectiveConfig> effectiveConfigs) {
        Set<String> files = new LinkedHashSet<>();
        for (EffectiveConfig config : effectiveConfigs) {
            if (RelaxedProperties.get(config.properties(), IMPORT_KEY) != null) {
                files.add(config.sourceFile().toString());
            }
        }
        return files;
    }
}
