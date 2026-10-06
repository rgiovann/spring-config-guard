package dev.scg.core;

import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Groups ConfigFiles loaded individually by ConfigLoader.loadDirectory() into
 * logical Spring Boot configuration units, one per directory: application.{ext}
 * plus every application-{profile}.{ext} next to it. Within a unit, it puts every
 * document in Spring Boot's source order, lowest precedence first; ProfileMerger
 * then folds, in that order, the documents that apply to each set of active
 * profiles (ARCHITECTURE.md, ADR-012).
 * <p>
 * The order, measured against Spring Boot 4.1.1 through {@code /actuator/env}
 * (VALIDATION.md, "ProfileMerger correctness benchmark" and "Profile expressions
 * in {@code on-profile}"):
 * <ul>
 *   <li>files without a profile in their name before profile-specific files
 *       (application-{profile}.ext), whatever {@code on-profile} their documents
 *       carry: an {@code on-profile: prod} block in application.yml loses to
 *       application-prod.yml and to application.properties (P11);</li>
 *   <li>within each of the two, {@code .yaml} &lt; {@code .yml} &lt; {@code .properties};</li>
 *   <li>within a file, the documents in the order written: a later document
 *       overrides an earlier one, conditioned or not (P10).</li>
 * </ul>
 * Profile-specific files of different profiles are ordered by profile name, for
 * a deterministic result; when a profile group makes several of them apply,
 * ProfileMerger puts them in activation order instead (ARCHITECTURE.md, ADR-013).
 * <p>
 * A profile-specific file's documents may carry their own {@code on-profile}:
 * Spring Boot applies them only when both the file's profile and the expression
 * match (P12); it rejects only {@code spring.profiles.active} and
 * {@code spring.profiles.default} in such a file.
 * <p>
 * Scope: grouping by simple convention (same directory; "application" prefix
 * already guaranteed by ConfigLoader.isSpringConfigFile). Custom base name
 * (spring.config.name) and multiple directories with precedence are out of
 * scope — see ARCHITECTURE.md, ADR-005, and ConfigLocationCoverage, which warns
 * when one module has config files in more than one Spring location.
 */
public final class ConfigFileGrouper {

    private static final String PROFILE_SPECIFIC_PREFIX = "application-";

    public List<GroupedConfigFile> group(List<ConfigFile> rawFiles) {
        Map<Path, List<ConfigFile>> byDirectory = rawFiles.stream()
                .collect(Collectors.groupingBy(
                        file -> file.path().toAbsolutePath().getParent(),
                        LinkedHashMap::new,
                        Collectors.toList()
                ));

        List<GroupedConfigFile> result = new ArrayList<>();
        for (List<ConfigFile> filesInDirectory : byDirectory.values()) {
            List<ConfigFile> ordered = filesInDirectory.stream().sorted(SOURCE_ORDER).toList();
            List<SourceDocument> documents = new ArrayList<>();
            for (ConfigFile file : ordered) {
                documents.addAll(sourceDocuments(file, profileFromFilename(file.path())));
            }
            result.add(new GroupedConfigFile(ordered.getFirst().path(), documents));
        }
        return result;
    }

    /** Spring Boot's order for the files of one directory, lowest precedence first. */
    private static final Comparator<ConfigFile> SOURCE_ORDER = Comparator
            .comparing((ConfigFile file) -> profileFromFilename(file.path()).isPresent())
            .thenComparing(file -> profileFromFilename(file.path()).orElse(""))
            .thenComparingInt(file -> extensionRank(file.path()))
            .thenComparing(file -> file.path().getFileName().toString());

    static List<SourceDocument> sourceDocuments(ConfigFile file, Optional<String> fileProfile) {
        return file.documents().stream()
                .map(document -> new SourceDocument(file.path(), fileProfile, document))
                .toList();
    }

    /**
     * Precedence rank of a file's extension among files of the same kind, as Spring Boot
     * orders them: {@code .properties} outranks {@code .yml}, which outranks {@code .yaml}, on
     * a key conflict. Measured against Spring Boot 4.1.1 through {@code /actuator/env}
     * (VALIDATION.md, "ProfileMerger correctness benchmark", case 35, for {@code .yml} vs.
     * {@code .yaml}).
     */
    static int extensionRank(Path path) {
        String name = path.getFileName().toString();
        if (name.endsWith(".properties")) {
            return 2;
        }
        if (name.endsWith(".yml")) {
            return 1;
        }
        return 0; // .yaml
    }

    /**
     * Extracts the profile from the filename, following the application-{profile}.{ext} convention.
     * Optional.empty() for the base file (application.{ext}, with no suffix) or
     * for a malformed empty suffix (application-.yml — untested edge case,
     * defensively treated as "no profile" instead of throwing an exception).
     */
    static Optional<String> profileFromFilename(Path path) {
        String filename = path.getFileName().toString();
        if (!filename.startsWith(PROFILE_SPECIFIC_PREFIX)) {
            return Optional.empty();
        }

        int dotIndex = filename.lastIndexOf('.');
        String nameWithoutExtension = dotIndex >= 0 ? filename.substring(0, dotIndex) : filename;
        String profile = nameWithoutExtension.substring(PROFILE_SPECIFIC_PREFIX.length());

        return profile.isBlank() ? Optional.empty() : Optional.of(profile);
    }
}
