package dev.scg.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Assembles {@link EffectiveConfig}s for a Spring Cloud Config Server-style repository: a flat
 * directory where {@code application*.{yml,yaml,properties}} is the Global config shared by every
 * client, and every other {@code .yml}/{@code .yaml}/{@code .properties} file is one service's own
 * config, keyed by its filename (without extension) as the service name.
 * <p>
 * Deliberately does NOT split a filename into {@code {service}-{profile}} parts the way
 * {@link ConfigFileGrouper} splits {@code application-{profile}}: unlike the fixed
 * {@code "application"} prefix, a service name is arbitrary and routinely contains hyphens itself
 * (e.g. {@code customers-service}), so {@code customers-service-mysql.yml} can't be split into
 * service + profile without already knowing the set of valid service names. Profiles for a service
 * are only read from {@code spring.config.activate.on-profile} documents inside that service's own
 * file — the same mechanism {@link ConfigLoader} already handles.
 * <p>
 * Deliberately not recursive, unlike {@link ConfigLoader#loadDirectory}: a Config Server repository
 * is conventionally a single flat directory, and walking subdirectories risks picking up unrelated
 * YAML (CI workflows, docker-compose.yml, etc.) and misreading it as Spring configuration.
 */
public final class ConfigServerAssembler {

    private final ConfigLoader configLoader = new ConfigLoader();
    private final ProfileMerger profileMerger = new ProfileMerger();

    public List<EffectiveConfig> assemble(Path repoDir) throws IOException {
        List<ConfigFile> topLevelFiles = loadTopLevelFiles(repoDir);

        ConfigFile global = null;
        Map<String, ConfigFile> byService = new LinkedHashMap<>();
        for (ConfigFile file : topLevelFiles) {
            if (isGlobalFile(file.path())) {
                global = file; // a second application*.ext present would silently win-last; not handled, same as elsewhere in this codebase (e.g. ProfileMerger.findBaseProperties).
            } else {
                byService.put(serviceName(file.path()), file);
            }
        }

        Map<String, String> globalBase = global == null ? Map.of() : profileMerger.findBaseProperties(global);

        List<EffectiveConfig> result = new ArrayList<>();
        for (ConfigFile serviceFile : byService.values()) {
            Map<String, String> serviceBase = profileMerger.findBaseProperties(serviceFile);
            result.add(new EffectiveConfig(
                    serviceFile.path(),
                    ProfileMerger.BASE_PROFILE_LABEL,
                    profileMerger.mergeProperties(globalBase, serviceBase)
            ));

            Set<String> profiles = new LinkedHashSet<>(namedProfiles(global));
            profiles.addAll(namedProfiles(serviceFile));

            for (String profile : profiles) {
                // Cascade precedence, lowest to highest (confirmed against the Spring Cloud Config
                // reference doc: "the server creates an Environment from application.yml (shared)
                // and foo.yml (with foo.yml taking precedence)... these same rules apply in a
                // standalone Spring Boot application" -- i.e. spring.config.name=application,{app}):
                // Global-base < Global-profile < Service-base < Service-profile.
                Map<String, String> effective = Stream.of(
                        globalBase,
                        profileProperties(global, profile),
                        serviceBase,
                        profileProperties(serviceFile, profile)
                ).reduce(Map.of(), profileMerger::mergeProperties);

                result.add(new EffectiveConfig(serviceFile.path(), profile, effective));
            }
        }
        return result;
    }

    private static Set<String> namedProfiles(ConfigFile file) {
        if (file == null) {
            return Set.of();
        }
        Set<String> profiles = new LinkedHashSet<>();
        for (ConfigDocument document : file.documents()) {
            document.profile().ifPresent(profiles::add);
        }
        return profiles;
    }

    /** ConfigLoader already merges same-labeled documents within one file, so at most one matches. */
    private static Map<String, String> profileProperties(ConfigFile file, String profile) {
        if (file == null) {
            return Map.of();
        }
        return file.documents().stream()
                .filter(document -> document.profile().equals(Optional.of(profile)))
                .findFirst()
                .map(ConfigDocument::properties)
                .orElse(Map.of());
    }

    private List<ConfigFile> loadTopLevelFiles(Path repoDir) throws IOException {
        List<ConfigFile> result = new ArrayList<>();
        if (!Files.isDirectory(repoDir)) {
            return result;
        }
        try (Stream<Path> paths = Files.list(repoDir)) {
            List<Path> candidates = paths
                    .filter(Files::isRegularFile)
                    .filter(ConfigServerAssembler::isConfigFile)
                    .toList();
            for (Path p : candidates) {
                result.add(configLoader.loadFile(p));
            }
        }
        return result;
    }

    private static boolean isConfigFile(Path p) {
        String name = p.getFileName().toString();
        return name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml");
    }

    private static boolean isGlobalFile(Path p) {
        return p.getFileName().toString().startsWith("application");
    }

    private static String serviceName(Path p) {
        String name = p.getFileName().toString();
        int dotIndex = name.lastIndexOf('.');
        return dotIndex >= 0 ? name.substring(0, dotIndex) : name;
    }
}
