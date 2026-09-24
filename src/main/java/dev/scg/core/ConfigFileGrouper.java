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
 * When more than one physical source resolves to the same label, their
 * documents are folded into one via
 * {@link ProfileMerger#mergeWithoutStrippingSentinels} (not
 * {@code mergeProperties} — this fold is an intermediate step, not the
 * final one, and stripping sentinels here would lose information the later,
 * real {@link ProfileMerger#merge} pass still needs), in ascending
 * precedence order. Two tiers of fold exist:
 * <ul>
 *   <li>Base documents (no profile at all) from multiple physical base
 *       files — e.g. application.yml + application.properties both acting
 *       as base — fold together ({@link #precedenceRank}): {@code .properties}
 *       wins a key conflict over {@code .yml}/{@code .yaml}.</li>
 *   <li>Documents for the same NAMED profile fold together regardless of
 *       whether they come from a filename-profile file
 *       (application-{profile}.ext) or from an on-profile block inside a
 *       base file ({@link #namedSourceRank}): a filename-profile file
 *       always outranks an on-profile block in a base file, confirmed
 *       against a real Spring Boot app (see BACKLOG.md, "Caso 3"); within
 *       either source, {@code .properties} still outranks
 *       {@code .yml}/{@code .yaml}.</li>
 * </ul>
 */
public final class ConfigFileGrouper {

    private static final String PROFILE_SPECIFIC_PREFIX = "application-";

    /** Precedence-rank offset that puts every filename-profile source above every on-profile-in-base source. */
    private static final int NAMED_FILE_TIER = 3;

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
        Map<String, Path> sourceByProfileLabel = new LinkedHashMap<>();

        // Every document that resolves to a NAMED profile label -- whether from
        // a filename-profile file or from an on-profile block inside a base
        // file -- tagged with its combined precedence rank (namedSourceRank)
        // and folded together, ascending, regardless of physical origin.
        record NamedSource(String label, ConfigDocument document, Path path, int rank) {}
        List<NamedSource> namedSources = new ArrayList<>();

        // True base documents (no profile at all) from multiple physical base
        // files, tagged with their own rank and folded separately.
        record BaseSource(ConfigDocument document, Path path, int rank) {}
        List<BaseSource> baseSources = new ArrayList<>();

        for (ConfigFile file : filesInDirectory) {
            Optional<String> filenameProfile = extractProfileFromFilename(file.path());
            if (filenameProfile.isPresent()) {
                String label = filenameProfile.get();
                int rank = namedSourceRank(file.path(), true);
                for (ConfigDocument document : file.documents()) {
                    namedSources.add(new NamedSource(label, document, file.path(), rank));
                }
                continue;
            }
            for (ConfigDocument document : file.documents()) {
                if (document.profile().isPresent()) {
                    namedSources.add(new NamedSource(
                            document.profile().get(), document, file.path(), namedSourceRank(file.path(), false)));
                } else {
                    baseSources.add(new BaseSource(document, file.path(), precedenceRank(file.path())));
                }
            }
        }

        List<ConfigDocument> combinedDocuments = new ArrayList<>();

        // Traceability path recorded per label is the highest-precedence
        // source -- the one more likely to be "where to fix it".
        namedSources.sort(Comparator.comparingInt(NamedSource::rank));
        Map<String, Map<String, String>> foldedByLabel = new LinkedHashMap<>();
        for (NamedSource source : namedSources) {
            foldedByLabel.merge(source.label(), source.document().properties(), profileMerger::mergeWithoutStrippingSentinels);
            sourceByProfileLabel.put(source.label(), source.path());
        }
        foldedByLabel.forEach((label, properties) ->
                combinedDocuments.add(new ConfigDocument(Optional.of(label), properties)));

        baseSources.sort(Comparator.comparingInt(BaseSource::rank));
        Map<String, String> foldedBase = null;
        for (BaseSource source : baseSources) {
            foldedBase = foldedBase == null
                    ? source.document().properties()
                    : profileMerger.mergeWithoutStrippingSentinels(foldedBase, source.document().properties());
            sourceByProfileLabel.put(ProfileMerger.BASE_PROFILE_LABEL, source.path());
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
     * Precedence rank used to fold multiple physical base files (no profile
     * at all) resolving to the same label into one document. {@code .properties}
     * outranks {@code .yml}/{@code .yaml} on a key conflict; {@code .yml} vs.
     * {@code .yaml} between themselves is an arbitrary but deterministic
     * tie-break.
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
     * Precedence rank used to fold multiple sources of the same NAMED profile
     * into one document -- {@link #precedenceRank}'s format tie-break, offset
     * by {@link #NAMED_FILE_TIER} when the source is a filename-profile file
     * rather than an on-profile block inside a base file. A filename-profile
     * file always outranks an on-profile block, confirmed against a real
     * Spring Boot app (see BACKLOG.md, "Caso 3").
     */
    private static int namedSourceRank(Path path, boolean isFilenameProfileFile) {
        return (isFilenameProfileFile ? NAMED_FILE_TIER : 0) + precedenceRank(path);
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