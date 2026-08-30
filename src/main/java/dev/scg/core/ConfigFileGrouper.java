package dev.scg.core;

import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Groups ConfigFiles loaded individually by ConfigLoader.loadDirectory()
 * into logical Spring Boot configuration units: application.{ext} (base) +
 * application-{profile}.{ext} (overlay), in the same directory.
 * <p>
 * Motivation (BL-15): ConfigLoader treats each physical file as an independent
 * ConfigFile, so ProfileMerger never merges application.yml with
 * application-prod.yml — each one becomes an isolated "effective config",
 * unaware of the other's contents. This class fixes that in a separate layer,
 * without reopening the already-validated ConfigLoader/ProfileMerger contract.
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
            result.add(mergeGroup(filesInDirectory));
        }
        return result;
    }

    private GroupedConfigFile mergeGroup(List<ConfigFile> filesInDirectory) {
        List<ConfigDocument> combinedDocuments = new ArrayList<>();
        Map<String, Path> sourceByProfileLabel = new LinkedHashMap<>();

        // First pass: profile-specific files. The path of these
        // files takes priority for traceability — if a property
        // appears both in the profile-specific file and in a multi-document
        // base file for the same profile (rare case), we prefer pointing to
        // the profile-specific file, which is more likely to be "where to fix it".

        for (ConfigFile file : filesInDirectory) {
            Optional<String> filenameProfile = extractProfileFromFilename(file.path());
            if (filenameProfile.isEmpty()) {
                continue;
            }
            for (ConfigDocument document : file.documents()) {
                combinedDocuments.add(new ConfigDocument(filenameProfile, document.properties()));
                sourceByProfileLabel.put(filenameProfile.get(), file.path());
            }
        }

        // Second pass: base file(s). Multi-document behavior
        // via on-profile has already been correctly resolved by ConfigLoader — we do not
        // reprocess the profile here; we only record the physical source.
        for (ConfigFile file : filesInDirectory) {
            if (extractProfileFromFilename(file.path()).isPresent()) {
                continue; // already handled in the first pass
            }
            for (ConfigDocument document : file.documents()) {
                combinedDocuments.add(document);
                String label = document.profile().orElse(ProfileMerger.BASE_PROFILE_LABEL);
                sourceByProfileLabel.putIfAbsent(label, file.path());
            }
        }

        Path representativePath = filesInDirectory.get(0).path();
        return new GroupedConfigFile(
                new ConfigFile(representativePath, combinedDocuments),
                sourceByProfileLabel
        );
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