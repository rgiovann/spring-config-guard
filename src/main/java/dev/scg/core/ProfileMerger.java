package dev.scg.core;

import java.util.*;

/**
 * Merges the base document (without a profile) from a ConfigFile with each
 * named profile document, producing one EffectiveConfig per profile found
 * + always one EffectiveConfig for the base alone ("no active profile").
 * ConfigLoader already guarantees that there is at most 1 ConfigDocument per
 * profile label (duplicate documents with the same label have already been
 * merged there). ProfileMerger does not need to handle this case — it only
 * combines the base with one profile at a time.
 * <p>
 * Merge rule: a scalar key from the profile overrides the one from the base;
 * an entire list (identified by the prefix before the first '[') is REPLACED,
 * never merged index by index — this reflects the actual Spring runtime
 * behavior, where redefining a list discards the previous list completely.
 */
public final class ProfileMerger {

    /**
     * Synthetic label used for "no active profile". Deliberately
     * an unlikely name to collide with a real Spring profile (BL-02):
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

    public List<EffectiveConfig> merge(ConfigFile configFile) {
        Map<String, String> baseProperties = findBaseProperties(configFile);

        List<EffectiveConfig> result = new ArrayList<>();
        result.add(new EffectiveConfig(
                configFile.path(),
                BASE_PROFILE_LABEL,
                Collections.unmodifiableMap(stripInternalSentinels(baseProperties))
        ));

        for (ConfigDocument document : configFile.documents()) {
            if (document.profile().isEmpty()) {
                continue;
            }
            String profileLabel = document.profile().get();
            Map<String, String> merged = mergeProperties(baseProperties, document.properties());
            result.add(new EffectiveConfig(configFile.path(), profileLabel, Collections.unmodifiableMap(merged)));
        }

        return result;
    }

    private Map<String, String> findBaseProperties(ConfigFile configFile) {
        for (ConfigDocument document : configFile.documents()) {
            if (document.profile().isEmpty()) {
                return document.properties();
            }
        }
        return Map.of();
    }

    /**
     * Merges base + overlay (profile document). Scalar keys from the
     * overlay override those from the base. List keys (format "root[n]"
     * or "root[n].subkey") in the overlay cause the entire list for that root
     * to be REMOVED from the base before the overlay is applied — no orphaned
     * base index is left mixed with the new overlay index.
     */
    private Map<String, String> mergeProperties(Map<String, String> base, Map<String, String> overlay) {
        Map<String, String> merged = new LinkedHashMap<>(base);

        Set<String> canonicalListRootsInOverlay = new LinkedHashSet<>();
        Set<String> canonicalDotPrefixesInOverlay = new LinkedHashSet<>();
        Map<String, String> nullOverrides = new LinkedHashMap<>();

        for (String key : overlay.keySet()) {
            if (key.endsWith(ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX)) {
                String targetKey = key.substring(0, key.length() - ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX.length());
                nullOverrides.put(targetKey, null);

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
        return stripInternalSentinels(merged);
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
     * 1. BL-03(b): the overlay redefines as a scalar something that was a LIST
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

    private static Map<String, String> stripInternalSentinels(Map<String, String> map) {
        Map<String, String> stripped = new LinkedHashMap<>(map);
        stripped.keySet().removeIf(k -> k.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX)
                || k.endsWith(ConfigLoader.EMPTY_MAP_SENTINEL_SUFFIX)
                || k.endsWith(ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX));
        return stripped;
    }
}