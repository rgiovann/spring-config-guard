package dev.scg.core;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Detects an application whose config files sit in more than one of the locations Spring Boot
 * merges at runtime, so a clean report doesn't read as if their combined effect had been checked.
 * {@link ConfigFileGrouper} evaluates each directory independently (merging across locations is
 * deliberately out of scope -- a heuristic that guesses wrong would silently fuse two unrelated
 * modules of a monorepo), so a risky combination split across two locations -- e.g.
 * {@code allowed-origins: "*"} in {@code src/main/resources/application.yml} and
 * {@code allow-credentials: true} in {@code config/application-prod.yml} -- produces no finding.
 * This class only makes that gap visible; it does not merge anything. See ARCHITECTURE.md,
 * ADR-005.
 * <p>
 * Deliberately narrow, recognizing only locations that are structurally tied to the same module
 * root {@code R}, so sibling modules of a monorepo never count as one application:
 * <ul>
 *   <li>{@code R/src/main/resources} ({@code classpath:/})</li>
 *   <li>{@code R/src/main/resources/config} ({@code classpath:/config/})</li>
 *   <li>{@code R/config} ({@code file:./config/} when the app starts from {@code R} -- the usual
 *       case, though the actual working directory isn't knowable statically)</li>
 * </ul>
 * {@code R/config} only counts when {@code R/src/main/resources} is also present: without it,
 * a {@code config/} directory is not evidence of a Spring module root.
 */
public final class ConfigLocationCoverage {

    private static final Path MAIN_RESOURCES = Path.of("src", "main", "resources");
    private static final String CONFIG_DIR = "config";

    private ConfigLocationCoverage() {
    }

    /**
     * Module roots (absolute, normalized) with config files in two or more of the recognized
     * locations. Derived from {@link EffectiveConfig#sourceFile()}'s parent directories, so a
     * directory with several profiles or files counts as one location.
     */
    public static Set<Path> modulesWithMultipleLocations(List<EffectiveConfig> effectiveConfigs) {
        Set<Path> directories = new LinkedHashSet<>();
        for (EffectiveConfig config : effectiveConfigs) {
            Path parent = config.sourceFile().toAbsolutePath().normalize().getParent();
            if (parent != null) {
                directories.add(parent);
            }
        }

        Map<Path, Set<Path>> locationsByModule = new LinkedHashMap<>();
        for (Path directory : directories) {
            if (!directory.endsWith(MAIN_RESOURCES)) {
                continue;
            }
            Path moduleRoot = moduleRootOf(directory);
            if (moduleRoot == null) {
                continue;
            }
            Set<Path> locations = locationsByModule.computeIfAbsent(moduleRoot, root -> new LinkedHashSet<>());
            locations.add(directory);
            addIfScanned(directories, directory.resolve(CONFIG_DIR), locations);
            addIfScanned(directories, moduleRoot.resolve(CONFIG_DIR), locations);
        }

        Set<Path> result = new LinkedHashSet<>();
        locationsByModule.forEach((moduleRoot, locations) -> {
            if (locations.size() > 1) {
                result.add(moduleRoot);
            }
        });
        return result;
    }

    /** {@code R} for {@code R/src/main/resources}, or null when the path is too short to have one. */
    private static Path moduleRootOf(Path mainResources) {
        Path root = mainResources;
        for (int i = 0; i < MAIN_RESOURCES.getNameCount(); i++) {
            root = root.getParent();
            if (root == null) {
                return null;
            }
        }
        return root;
    }

    private static void addIfScanned(Set<Path> directories, Path candidate, Set<Path> locations) {
        if (directories.contains(candidate)) {
            locations.add(candidate);
        }
    }
}
