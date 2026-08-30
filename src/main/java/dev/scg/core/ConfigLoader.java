package dev.scg.core;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

import java.nio.charset.StandardCharsets;

/**
 * Finds and loads Spring Boot configuration files
 * (application*.properties / application*.yml / .yaml) within a directory,
 * flattening each one into one (or more) Map<String,String> of dotted key -> value.
 * <p>
 * A YAML file can contain multiple documents separated by "---", each
 * optionally associated with a profile via spring.config.activate.on-profile.
 * loadYaml returns one ConfigDocument per profile label FOUND in the file
 * (documents without a profile — including multiple such documents — are all
 * merged into the same "base"; documents with the same named profile are also
 * merged together).
 * <p>
 * Important: this method does NOT merge base with profile — that is the
 * responsibility of ProfileMerger, which consumes the List<ConfigDocument>
 * produced here.
 */
public final class ConfigLoader {

    /** Spring metadata key indicating which profile a document belongs to. */
    private static final String ON_PROFILE_KEY = "spring.config.activate.on-profile";

    /** Internal label used in the grouping structure to represent "no profile" (base). */
    private static final String BASE_LABEL = "";

    /**
     * Sentinel key suffix emitted when YAML explicitly defines an
     * EMPTY list (e.g., "allowed-origins: []"). Without this, an empty
     * list produces zero flattened keys — indistinguishable from "the key was
     * never mentioned" — and ProfileMerger would have no way to know that the
     * profile intended to clear the list inherited from the base (BL-03, scenario a).
     * <p>
     * Package-visible by design: ProfileMerger needs to recognize and then
     * remove this key before exposing the result to any Rule — it is an
     * internal infrastructure signal, not actual configuration data.
     */
    static final String EMPTY_LIST_SENTINEL_SUFFIX = ".__empty_list__";

    /**
     * BL-08: sentinel key suffix for an explicitly empty YAML Map/object
     * (e.g., "headers: {}"). Emitted by flatten() for the same reason as the
     * list sentinel — an empty Map leaves no trace in the flattened map
     * without it.
     * <p>
     * CRUCIAL DIFFERENCE from EMPTY_LIST_SENTINEL_SUFFIX: this sentinel is
     * INFORMATIONAL ONLY. It NEVER triggers purging in ProfileMerger,
     * because Map and List behave DIFFERENTLY across profiles in actual Spring
     * behavior:
     *   - List: the higher-priority profile REPLACES the entire list
     *     (officially documented) — therefore the list sentinel triggers
     *     purging of orphaned base indices.
     *   - Map: keys are composed from MULTIPLE sources — each key survives
     *     or is overridden individually, never the entire object at once
     *     (also officially documented). "headers: {}" in a profile does NOT
     *     remove sub-keys already defined by the base.
     * <p>
     * If someone ever tries to "complete the analogy" with the list and adds
     * purging here, it would introduce a bug: the merge would then diverge from
     * actual Spring behavior, potentially hiding (false negative) dangerous
     * configuration that Spring itself would actually retain.
     */
    static final String  EMPTY_MAP_SENTINEL_SUFFIX = ".__empty_map__";

    static final String NULL_SCALAR_SENTINEL_SUFFIX = ".__null_scalar__";

    public List<ConfigFile> loadDirectory(Path dir) throws IOException {
        List<ConfigFile> result = new ArrayList<>();
        if (!Files.isDirectory(dir)) {
            return result;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            List<Path> candidates = paths
                    .filter(Files::isRegularFile)
                    .filter(ConfigLoader::isSpringConfigFile)
                    .toList();

            for (Path p : candidates) {
                List<ConfigDocument> documents = p.toString().endsWith(".properties")
                        ? loadProperties(p)
                        : loadYaml(p);
                result.add(new ConfigFile(p, documents));
            }
        }
        return result;
    }

    private static boolean isSpringConfigFile(Path p) {
        String name = p.getFileName().toString();
        return name.startsWith("application")
                && (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml"));
    }

    private List<ConfigDocument> loadProperties(Path p) throws IOException {
        List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);

        // Intermediate structure for grouping documents by profile
        Map<String, List<Map<String, String>>> groupedByLabel = new LinkedHashMap<>();

        StringBuilder currentDocBuilder = new StringBuilder();

        for (String line : lines) {
            // Spring Boot requires the separator to be exactly '#---' or "!---"
            // (ignoring surrounding whitespace) (Spring Boot docs)
            if (line.trim().equals("#---") || line.trim().equals("!---"))  {
                processPropertiesDocument(currentDocBuilder.toString(), groupedByLabel);
                currentDocBuilder.setLength(0); // Clear the buffer for the next document
            } else {
                currentDocBuilder.append(line).append("\n");
            }
        }
        // Process the last (or only) block of the file
        processPropertiesDocument(currentDocBuilder.toString(), groupedByLabel);

        return buildConfigDocuments(groupedByLabel);
    }

    private void processPropertiesDocument(
            String rawContent,
            Map<String, List<Map<String, String>>> groupedByLabel
    ) throws IOException {
        if (rawContent.isBlank()) {
            return;
        }

        Properties props = new Properties();
        props.load(new StringReader(rawContent));

        if (props.isEmpty()) {
            return;
        }

        Map<String, String> flatDocument = new LinkedHashMap<>();
        for (String name : props.stringPropertyNames()) {
            flatDocument.put(name, props.getProperty(name));
        }

        // Extracts the profile using relaxed binding — spring.config.activate.on-profile,
        // onProfile, ON_PROFILE, etc. are the same key for the actual Spring implementation.
        Optional<String> onProfileActualKey = RelaxedProperties.findActualKey(flatDocument, ON_PROFILE_KEY);
        String profileValue = onProfileActualKey.map(flatDocument::get).orElse(null);
        String label = (profileValue == null || profileValue.isBlank())
                ? BASE_LABEL
                : profileValue.strip();

        // Remove the actual infrastructure key (it may not be the literal ON_PROFILE_KEY)
        // to avoid polluting the linting rules
        onProfileActualKey.ifPresent(flatDocument::remove);

        groupedByLabel
                .computeIfAbsent(label, key -> new ArrayList<>())
                .add(flatDocument);
    }

    private List<ConfigDocument> buildConfigDocuments(
            Map<String, List<Map<String, String>>> groupedByLabel
    ) {
        List<ConfigDocument> result = new ArrayList<>();

        for (var entry : groupedByLabel.entrySet()) {
            String label = entry.getKey();
            List<Map<String, String>> mapsForLabel = entry.getValue();

            Map<String, String> merged = new LinkedHashMap<>();
            for (Map<String, String> flatDocument : mapsForLabel) {
                merged.putAll(flatDocument); // Last value wins in case of duplicate keys within the same profile
            }

            Optional<String> profile = label.equals(BASE_LABEL)
                    ? Optional.empty()
                    : Optional.of(label);

            result.add(new ConfigDocument(profile, merged));
        }

        // Maintains the invariant: every ConfigFile has at least 1 ConfigDocument
        if (result.isEmpty()) {
            result.add(new ConfigDocument(Optional.empty(), new LinkedHashMap<>()));
        }

        return result;
    }

    /**
     * Loads a YAML file that may contain multiple documents ("---"),
     * returning one ConfigDocument per distinct profile label found.
     * <p>
     * Step A/B/C (per raw document): flattens, extracts
     * spring.config.activate.on-profile (treating missing/empty as base,
     * risk point 5 — TODO warning for when we work on Finding), removes
     * the metadata key from the flattened map (risk point 4).
     * <p>
     * Step D (grouping): documents with the SAME label (including multiple "base"
     * documents) are merged together, in the order they appear in the file —
     * the last value for a duplicate key wins, the same rule already used
     * for duplicate keys within a single document.
     */
    private List<ConfigDocument> loadYaml(Path p) throws IOException {
        try (var in = Files.newInputStream(p)) {
            Yaml yaml = new Yaml();
            Iterable<Object> rawDocuments = yaml.loadAll(in);

            // LinkedHashMap preserves the order of FIRST appearance of each label in the file.
            Map<String, List<Map<String, String>>> groupedByLabel = new LinkedHashMap<>();

            for (Object rawDocument : rawDocuments) {
                if (rawDocument == null) {
                    // Risk point 1: empty document (e.g., "---" alone at the end of the file).
                    // It does not generate any ConfigDocument — we simply ignore it.
                    continue;
                }

                Map<String, String> flatDocument = new LinkedHashMap<>();
                flatten(rawDocument, "", flatDocument);

                Optional<String> onProfileActualKey = RelaxedProperties.findActualKey(flatDocument, ON_PROFILE_KEY);
                String profileValue = onProfileActualKey.map(flatDocument::get).orElse(null);
                String label = (profileValue == null || profileValue.isBlank())
                        ? BASE_LABEL
                        : profileValue.strip();

                // Risk point 4: removes the metadata from the data map — consumers of
                // ConfigDocument should not see this key as if it were a regular business
                // property. Removes the ACTUAL key found (it may be on-profile, onProfile,
                // ON_PROFILE, etc.), not the literal constant —
                // relaxed binding is also applied when detecting the profile activation
                // metadata itself.

                onProfileActualKey.ifPresent(flatDocument::remove);

                groupedByLabel
                        .computeIfAbsent(label, key -> new ArrayList<>())
                        .add(flatDocument);
            }

            return buildConfigDocuments(groupedByLabel);

        }  catch (YAMLException e) {

        // SnakeYAML parsing is lazy (it happens during iteration of the for loop
        // above, not in loadAll() itself), so YAMLException — which is a
        // RuntimeException, not IOException — may be thrown here and
        // would propagate unhandled to Main.main() without this catch. Translated
        // to IOException here, at the source, so Main can continue relying solely
        // on the IOException contract it already knows how to handle (USAGE_ERROR,
        // readable message) — without having to catch generic RuntimeException there,
        // which would hide real bugs behind the same usage-error message.

        throw new IOException("YAML inválido em '%s': %s".formatted(p, e.getMessage()), e);
    }
    }

    private void flatten(Object yamlNode,
                         String prefix,
                         Map<String, String> flat) {

        if (yamlNode == null) {
            if (!prefix.isEmpty()) {
                flat.put(prefix + NULL_SCALAR_SENTINEL_SUFFIX, "true");
            }
            return;
        }

        if (yamlNode instanceof Map<?, ?> map) {

            if (map.isEmpty()) {
                flat.put(prefix + EMPTY_MAP_SENTINEL_SUFFIX, "true");
                return;
            }

            for (var entry : map.entrySet()) {

                String child = prefix.isEmpty()
                        ? entry.getKey().toString()
                        : prefix + "." + entry.getKey();

                flatten(entry.getValue(), child, flat);
            }

        } else if (yamlNode instanceof List<?> list) {

            if (list.isEmpty()) {
            // BL-03 (scenario a): an explicitly empty list leaves
            // no trace if we simply iterate over nothing. Emit
            // a sentinel so ProfileMerger can distinguish
            // "profile redefined as empty" from "profile did not mention it at all".
                flat.put(prefix + EMPTY_LIST_SENTINEL_SUFFIX, "true");
            } else {
                for (int i = 0; i < list.size(); i++) {
                    flatten(list.get(i), prefix + "[" + i + "]", flat);
                }
            }

        } else {

            flat.put(prefix, String.valueOf(yamlNode));

        }
    }
}