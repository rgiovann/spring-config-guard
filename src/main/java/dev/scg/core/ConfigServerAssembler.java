package dev.scg.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Assembles {@link EffectiveConfig}s for a Spring Cloud Config Server-style repository: a flat
 * directory where {@code application*.{yml,yaml,properties}} is the Global config shared by every
 * client, and every other {@code .yml}/{@code .yaml}/{@code .properties} file is one service's own
 * config, keyed by its filename (without extension) as the service name.
 * <p>
 * Each service is one {@link GroupedConfigFile}, evaluated by {@link ProfileMerger} like a
 * directory in the regular mode (ARCHITECTURE.md, ADR-012). Its documents, lowest precedence
 * first: the Global files without a profile in their name, then the service's files, then the
 * Global profile-specific files ({@code application-{profile}.ext}); within each, {@code .yaml}
 * &lt; {@code .yml} &lt; {@code .properties}, and a file's documents in the order written. The
 * Spring Cloud Config reference says the server resolves {@code application.yml} and
 * {@code foo.yml} as a standalone Spring Boot application with
 * {@code spring.config.name=application,foo} would; that order was measured that way, against
 * Spring Boot 4.1.1 (VALIDATION.md, "Profile expressions in {@code on-profile}", P15): every
 * document of the service's file overrides the Global file's, {@code on-profile} blocks included,
 * and {@code application-dev.yml} overrides both.
 * <p>
 * Deliberately does NOT split a filename into {@code {service}-{profile}} parts the way
 * {@link ConfigFileGrouper} splits {@code application-{profile}}: unlike the fixed
 * {@code "application"} prefix, a service name is arbitrary and routinely contains hyphens itself
 * (e.g. {@code customers-service}), so {@code customers-service-mysql.yml} can't be split into
 * service + profile without already knowing the set of valid service names. Profiles for a service
 * are only read from {@code spring.config.activate.on-profile} documents inside that service's own
 * file, and from the Global files.
 * <p>
 * Deliberately not recursive, unlike {@link ConfigLoader#loadDirectory}: a Config Server repository
 * is conventionally a single flat directory, and walking subdirectories risks picking up unrelated
 * YAML (CI workflows, docker-compose.yml, etc.) and misreading it as Spring configuration.
 */
public final class ConfigServerAssembler {

    private final ConfigLoader configLoader = new ConfigLoader();
    private final ProfileMerger profileMerger = new ProfileMerger();

    public List<EffectiveConfig> assemble(Path repoDir) throws IOException {
        return assemble(group(repoDir));
    }

    /**
     * Every configuration of each service. Its source file is always the service's own file, the
     * one that names the service in the report, even for a value set in a Global file.
     */
    public List<EffectiveConfig> assemble(List<GroupedConfigFile> services) {
        List<EffectiveConfig> result = new ArrayList<>();
        for (GroupedConfigFile service : services) {
            for (EffectiveConfig config : profileMerger.merge(service)) {
                result.add(new EffectiveConfig(service.path(), config.profileLabel(), config.properties()));
            }
        }
        return result;
    }

    /** One group per service, its path the service's highest-precedence file. */
    public List<GroupedConfigFile> group(Path repoDir) throws IOException {
        List<ConfigFile> globalFiles = new ArrayList<>();
        Map<String, List<ConfigFile>> byService = new LinkedHashMap<>();
        for (ConfigFile file : loadTopLevelFiles(repoDir)) {
            if (isGlobalFile(file.path())) {
                globalFiles.add(file);
            } else {
                byService.computeIfAbsent(serviceName(file.path()), name -> new ArrayList<>()).add(file);
            }
        }
        globalFiles.sort(Comparator
                .comparing((ConfigFile file) -> ConfigFileGrouper.profileFromFilename(file.path()).orElse(""))
                .thenComparingInt(file -> ConfigFileGrouper.extensionRank(file.path()))
                .thenComparing(file -> file.path().getFileName().toString()));

        List<GroupedConfigFile> result = new ArrayList<>();
        for (List<ConfigFile> serviceFiles : byService.values()) {
            serviceFiles.sort(Comparator.comparingInt(file -> ConfigFileGrouper.extensionRank(file.path())));
            List<SourceDocument> documents = new ArrayList<>();
            for (ConfigFile global : globalFiles) {
                if (ConfigFileGrouper.profileFromFilename(global.path()).isEmpty()) {
                    documents.addAll(ConfigFileGrouper.sourceDocuments(global, Optional.empty()));
                }
            }
            for (ConfigFile serviceFile : serviceFiles) {
                documents.addAll(ConfigFileGrouper.sourceDocuments(serviceFile, Optional.empty()));
            }
            for (ConfigFile global : globalFiles) {
                Optional<String> profile = ConfigFileGrouper.profileFromFilename(global.path());
                if (profile.isPresent()) {
                    documents.addAll(ConfigFileGrouper.sourceDocuments(global, profile));
                }
            }
            result.add(new GroupedConfigFile(serviceFiles.getLast().path(), documents));
        }
        return result;
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
                    .sorted()
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
