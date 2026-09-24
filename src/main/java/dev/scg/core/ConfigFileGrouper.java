package dev.scg.core;

import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Groups ConfigFiles loaded individually by ConfigLoader.loadDirectory()
 * into logical Spring Boot configuration units: application.{ext} (base) +
 * application-{profile}.{ext} (overlay), in the same directory. ConfigLoader
 * and ProfileMerger each operate on a single physical file; this class is
 * the only one that combines documents across multiple physical files, and
 * it does so without changing either of their contracts.
 * <p>
 * Profile rule for a profile-specific file (application-{profile}.ext): the
 * filename is the ONLY source of truth. Confirmed that a real Spring Boot
 * rejects (InvalidConfigDataPropertyException) any
 * spring.config.activate.on-profile inside this type of file — the two
 * mechanisms (filename vs. on-profile) are mutually exclusive by design
 * of the framework itself, not a precedence issue to resolve.
 * <p>
 * Scope: grouping by simple convention (same directory; "application"
 * prefix already guaranteed by ConfigLoader.isSpringConfigFile). Custom base
 * name (spring.config.name) and multiple directories with precedence are
 * out of scope — see BL-17.
 * <p>
 * When more than one physical file resolves to the same label (base, or the
 * same named profile) — e.g. application.yml + application.properties both
 * acting as base — their documents are folded into one via
 * {@link ProfileMerger#mergeProperties}, in ascending precedence order
 * ({@link #precedenceRank}): {@code .properties} wins a key conflict over
 * {@code .yml}/{@code .yaml}. The fold is scoped to a single pass: filename-profile
 * files fold only with other filename-profile files naming the same profile;
 * base files fold only with other base files. A document carrying a profile
 * from an internal on-profile block inside a base file is passed through
 * unchanged, never folded with a same-named profile-specific file — this
 * class does not resolve precedence between those two mechanisms.
 */
public final class ConfigFileGrouper {

    private static final String PROFILE_SPECIFIC_PREFIX = "application-";

    private final ProfileMerger profileMerger = new ProfileMerger();

    public List<GroupedConfigFile> group(List<ConfigFile> rawFiles) {
        Map<Path, List<ConfigFile>> byDirectory = rawFiles.stream()
                .collect(Collectors.groupingBy(
                        file -> file.path().toAbsolutePath().getParent(),
                        LinkedHashMap::new,
                        Collectors.toList()
                ));

        List<GroupedConfigFile> result = new ArrayList<>();
        for (List<ConfigFile> filesInDirectory : byDirectory.values()) {
            result.add(mergeGroup(filesInDirectory));
        }
        return result;
    }

    private GroupedConfigFile mergeGroup(List<ConfigFile> filesInDirectory) {
        // Ascending precedence: folded as base -> overlay, in this order, so the
        // last (highest-precedence) file wins both key conflicts and the
        // traceability pointer below.
        List<ConfigFile> orderedFiles = filesInDirectory.stream()
                .sorted(Comparator.comparingInt(file -> precedenceRank(file.path())))
                .toList();

        Map<String, Path> sourceByProfileLabel = new LinkedHashMap<>();

        // First pass: profile-specific files. Multiple physical files naming the
        // SAME profile (e.g. application-prod.yml + application-prod.properties)
        // are folded into a single document. The path recorded for traceability
        // is the highest-precedence file — the one more likely to be "where to
        // fix it".
        Map<String, Map<String, String>> foldedByFilenameProfile = new LinkedHashMap<>();
        for (ConfigFile file : orderedFiles) {
            Optional<String> filenameProfile = extractProfileFromFilename(file.path());
            if (filenameProfile.isEmpty()) {
                continue;
            }
            String label = filenameProfile.get();
            for (ConfigDocument document : file.documents()) {
                foldedByFilenameProfile.merge(label, document.properties(), profileMerger::mergeProperties);
            }
            sourceByProfileLabel.put(label, file.path());
        }

        List<ConfigDocument> combinedDocuments = new ArrayList<>();
        foldedByFilenameProfile.forEach((label, properties) ->
                combinedDocuments.add(new ConfigDocument(Optional.of(label), properties)));

        // Second pass: base file(s). A document carrying a profile from an
        // internal on-profile block is passed through unchanged — not folded
        // with the first pass above (see class Javadoc). True base documents
        // (no profile at all) from multiple physical base files ARE folded
        // the same way as the first pass.
        Map<String, String> foldedBase = null;
        for (ConfigFile file : orderedFiles) {
            if (extractProfileFromFilename(file.path()).isPresent()) {
                continue; // already handled in the first pass
            }
            for (ConfigDocument document : file.documents()) {
                if (document.profile().isPresent()) {
                    combinedDocuments.add(document);
                    sourceByProfileLabel.put(document.profile().get(), file.path());
                    continue;
                }
                foldedBase = foldedBase == null
                        ? document.properties()
                        : profileMerger.mergeProperties(foldedBase, document.properties());
            }
            sourceByProfileLabel.put(ProfileMerger.BASE_PROFILE_LABEL, file.path());
        }
        if (foldedBase != null) {
            combinedDocuments.add(new ConfigDocument(Optional.empty(), foldedBase));
        }

        Path representativePath = filesInDirectory.getFirst().path();
        return new GroupedConfigFile(
                new ConfigFile(representativePath, combinedDocuments),
                sourceByProfileLabel
        );
    }

    /**
     * Precedence rank used to fold multiple physical files resolving to the
     * same label (base, or the same named profile) into one document.
     * {@code .properties} outranks {@code .yml}/{@code .yaml} on a key
     * conflict; {@code .yml} vs. {@code .yaml} between themselves is an
     * arbitrary but deterministic tie-break.
     */
    private static int precedenceRank(Path path) {
        String name = path.getFileName().toString();
        if (name.endsWith(".properties")) {
            return 2;
        }
        if (name.endsWith(".yaml")) {
            return 1;
        }
        return 0; // .yml
    }

    /**
     * Extracts the profile from the filename, following the application-{profile}.{ext} convention.
     * Optional.empty() for the base file (application.{ext}, with no suffix) or
     * for a malformed empty suffix (application-.yml — untested edge case,
     * defensively treated as "no profile" instead of throwing an exception).
     */
    private Optional<String> extractProfileFromFilename(Path path) {
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