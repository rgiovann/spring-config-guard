package dev.scg.core;

import java.nio.file.Path;
import java.util.*;

/**
 * Builds the EffectiveConfigs of one GroupedConfigFile, as Spring Boot would
 * resolve them (ARCHITECTURE.md, ADR-012): one for no active profile, labeled
 * {@link #BASE_PROFILE_LABEL}, and one per known profile P, labeled P. Each is the
 * fold, in the group's source order, of every document that applies when those
 * profiles are active: with none active, Spring activates the {@code default}
 * profile, so the base is evaluated with {@code {default}}; profile P with
 * {@code {P}}.
 * <p>
 * The known profiles are every name the group's conditions refer to (file names
 * like application-prod.yml and {@code on-profile} expressions, including names
 * only negated, as {@code api-docs} in {@code !api-docs}), except {@code default},
 * which belongs to the base. Several profiles active together are not evaluated;
 * {@link #documentsNotEvaluated} lists the documents only such a combination
 * activates.
 * <p>
 * Merge rule (between two documents of the fold): a scalar key from the later
 * document overrides the earlier one; an entire list (identified by the prefix
 * before the first '[') is REPLACED, never merged index by index — this reflects
 * the actual Spring runtime behavior, where redefining a list discards the
 * previous list completely.
 */
public final class ProfileMerger {

    /**
     * Synthetic label used for "no active profile". Deliberately
     * an unlikely name to collide with a real Spring profile:
     * previously it was the simple string "base", which could collide if a
     * real profile were literally named "base" (syntactically valid in Spring,
     * although rare in practice).
     * <p>
     * Package-visible by design, so that
     * ProfileMergerTest references this constant instead of duplicating the
     * string literal — avoiding the same kind of fragility if the value changes
     * again in the future.
     */
    public static final String BASE_PROFILE_LABEL = "__spring_config_guard_base__";

    /** The profile Spring Boot activates when no profile is active. */
    static final String DEFAULT_PROFILE = "default";

    /**
     * The value of a key written as a YAML null ({@code debug:}, {@code debug: ~}): an empty string,
     * as Spring Boot's {@code OriginTrackedYamlLoader} loads it (checked in 4.1.1). The key stays
     * present: Spring reads {@code debug=""} as debug logging on (VALIDATION.md, "SCG009 verbose
     * logging scenarios", Y4 and Y5), so dropping it would hide the finding.
     */
    static final String NULL_VALUE = "";

    /**
     * The base configuration first, then one per known profile.
     * <p>
     * Each one's source file is where its configuration is most likely fixed: for a profile P,
     * the file of the last applied document whose condition names P; otherwise, and for the
     * base, the file of the last applied document.
     */
    public List<EffectiveConfig> merge(GroupedConfigFile group) {
        List<EffectiveConfig> result = new ArrayList<>();
        result.add(evaluate(group, Set.of(DEFAULT_PROFILE), BASE_PROFILE_LABEL, Optional.empty()));
        for (String profile : knownProfiles(group)) {
            result.add(evaluate(group, Set.of(profile), profile, Optional.of(profile)));
        }
        return result;
    }

    /**
     * The conditioned documents that apply to none of the configurations {@link #merge} builds:
     * those only several profiles active together activate ({@code a & b}, or an
     * {@code on-profile} inside application-x.yml naming another profile).
     */
    public List<SourceDocument> documentsNotEvaluated(GroupedConfigFile group) {
        List<Set<String>> evaluated = new ArrayList<>();
        evaluated.add(Set.of(DEFAULT_PROFILE));
        knownProfiles(group).forEach(profile -> evaluated.add(Set.of(profile)));
        return group.documents().stream()
                .filter(SourceDocument::isConditional)
                .filter(document -> evaluated.stream().noneMatch(document::appliesTo))
                .toList();
    }

    private static Set<String> knownProfiles(GroupedConfigFile group) {
        Set<String> profiles = new LinkedHashSet<>();
        group.documents().forEach(document -> profiles.addAll(document.profileNames()));
        profiles.remove(DEFAULT_PROFILE);
        return profiles;
    }

    private EffectiveConfig evaluate(GroupedConfigFile group, Set<String> activeProfiles,
                                     String label, Optional<String> profile) {
        Map<String, String> folded = null;
        Path lastApplied = group.path();
        Path lastNamingProfile = null;
        for (SourceDocument document : group.documents()) {
            if (!document.appliesTo(activeProfiles)) {
                continue;
            }
            Map<String, String> properties = document.document().properties();
            // The first document starts the fold as written, so a null's key takes its sentinel's place.
            folded = folded == null ? new LinkedHashMap<>(properties) : mergeWithoutStrippingSentinels(folded, properties);
            lastApplied = document.file();
            if (profile.isPresent() && document.profileNames().contains(profile.get())) {
                lastNamingProfile = document.file();
            }
        }
        Path sourceFile = lastNamingProfile != null ? lastNamingProfile : lastApplied;
        Map<String, String> properties = folded == null ? Map.of() : stripInternalSentinels(folded);
        return new EffectiveConfig(sourceFile, label, Collections.unmodifiableMap(properties));
    }

    /**
     * Merges an earlier document's properties (base) with a later one's (overlay), for
     * {@link #merge}'s ordered fold. Scalar keys from the overlay override those from the base.
     * List keys (format "root[n]" or "root[n].subkey") in the overlay cause the entire list for
     * that root to be REMOVED from the base before the overlay is applied — no orphaned base index
     * is left mixed with the new overlay index. An explicit-null override resolves to
     * {@link #NULL_VALUE} immediately.
     * <p>
     * The internal sentinel keys are kept, and stripped only once the fold is complete: an
     * empty-list sentinel stripped mid-fold would never purge a conflicting list of an earlier
     * document at a later step.
     */
    Map<String, String> mergeWithoutStrippingSentinels(Map<String, String> base, Map<String, String> overlay) {
        Map<String, String> merged = new LinkedHashMap<>(base);

        Set<String> canonicalListRootsInOverlay = new LinkedHashSet<>();
        Set<String> canonicalDotPrefixesInOverlay = new LinkedHashSet<>();
        Map<String, String> nullOverrides = new LinkedHashMap<>();

        for (String key : overlay.keySet()) {
            if (key.endsWith(ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX)) {
                String targetKey = key.substring(0, key.length() - ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX.length());
                nullOverrides.put(targetKey, NULL_VALUE);

                String canonicalTarget = RelaxedProperties.canonicalize(targetKey);
                canonicalListRootsInOverlay.add(canonicalTarget);
                canonicalDotPrefixesInOverlay.add(canonicalTarget + ".");
            } else {
                int bracketIdx = key.indexOf('[');
                if (bracketIdx >= 0) {
                    String root = key.substring(0, bracketIdx);
                    canonicalListRootsInOverlay.add(RelaxedProperties.canonicalize(root));
                } else if (key.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX)) {
                    String root = key.substring(0, key.length() - ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX.length());
                    canonicalListRootsInOverlay.add(RelaxedProperties.canonicalize(root));
                } else if (overlayKeyMatchesAnyBaseKeyCanonically(key, base)) {
                    canonicalListRootsInOverlay.add(RelaxedProperties.canonicalize(key));
                }
            }
        }

        // Canonical purge: removes inherited indexed list keys or dot-separated sub-properties
        // from the base that were redefined in the overlay
        merged.keySet().removeIf(baseKey -> {
            String canonicalBaseKey = RelaxedProperties.canonicalize(baseKey);
            String canonicalBaseRoot = extractCanonicalRoot(baseKey);

            boolean isListMatch = canonicalListRootsInOverlay.contains(canonicalBaseRoot);
            boolean isDotMatch = canonicalDotPrefixesInOverlay.stream().anyMatch(canonicalBaseKey::startsWith);

            return isListMatch || isDotMatch;
        });

        merged.putAll(overlay);
        merged.putAll(nullOverrides);
        return merged;
    }
    private String extractCanonicalRoot(String key) {
        String cleanKey = key;
        if (cleanKey.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX)) {
            cleanKey = cleanKey.substring(0, cleanKey.length() - ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX.length());
        } else if (cleanKey.endsWith(ConfigLoader.EMPTY_MAP_SENTINEL_SUFFIX)) {
            cleanKey = cleanKey.substring(0, cleanKey.length() - ConfigLoader.EMPTY_MAP_SENTINEL_SUFFIX.length());
        } else if (cleanKey.endsWith(ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX)) {
            cleanKey = cleanKey.substring(0, cleanKey.length() - ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX.length());
        }

        int bracketIdx = cleanKey.indexOf('[');
        if (bracketIdx >= 0) {
            cleanKey = cleanKey.substring(0, bracketIdx);
        }

        return RelaxedProperties.canonicalize(cleanKey);
    }

    /**
     * Checks whether the overlay key canonically matches ANY key
     * already present in the base — not just keys that represented a list there.
     * Deliberately covers two distinct scenarios:
     * 1. The overlay redefines as a scalar something that was a LIST
     *    in the base (e.g., base has "cors.origins[0]"/"[1]", overlay defines
     *    "cors.origins" as a single string — Spring's relaxed binding for List<String>).
     * 2. The overlay redefines a pure scalar that is also a pure scalar in the base,
     *    but with different casing (e.g., base "spring.h2.console.enabled",
     *    overlay "spring.h2.console.ENABLED"). Without this check, merged.putAll(overlay)
     *    would treat the two as DIFFERENT keys (String.equals is case-sensitive),
     *    and the base key would survive alongside the overlay — RelaxedProperties.get()
     *    could then return the wrong value (the base one) depending on the iteration
     *    order of the LinkedHashMap. Empirically verified before this fix: without
     *    this check covering the second case, the bug would actually manifest.
     *    <p>
     * The old name of this method (isScalarRedefiningListInBase) described only
     * scenario 1 — but the implementation has always covered both, because
     * extractCanonicalRoot() only removes brackets IF PRESENT; for a base key that
     * is already scalar, the "canonical root" is the key itself. Renamed to
     * reflect what the method actually does, preventing someone from "fixing" the
     * implementation to match the old name and reintroducing the scenario 2 bug.
     */
    private boolean overlayKeyMatchesAnyBaseKeyCanonically(String overlayKey, Map<String, String> base) {
        String canonicalOverlayKey = RelaxedProperties.canonicalize(overlayKey);
        return base.keySet().stream().anyMatch(baseKey -> {
            String canonicalBaseRoot = extractCanonicalRoot(baseKey);
            return canonicalBaseRoot.equals(canonicalOverlayKey);
        });
    }

    /**
     * Removes the internal sentinel keys. A null-scalar sentinel left in place (a YAML null in the
     * base that no profile redefined) becomes its key with {@link #NULL_VALUE}, where the sentinel
     * was, unless the key is also written with a value.
     */
    private static Map<String, String> stripInternalSentinels(Map<String, String> map) {
        Map<String, String> stripped = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String key = entry.getKey();
            if (key.endsWith(ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX)) {
                String targetKey = key.substring(0, key.length() - ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX.length());
                if (!map.containsKey(targetKey)) {
                    stripped.put(targetKey, NULL_VALUE);
                }
            } else if (!key.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX)
                    && !key.endsWith(ConfigLoader.EMPTY_MAP_SENTINEL_SUFFIX)) {
                stripped.put(key, entry.getValue());
            }
        }
        return stripped;
    }
}