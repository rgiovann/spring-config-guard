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
 * A file can contain multiple documents ("---" in YAML, "#---" or "!---" in
 * .properties), each optionally conditioned by spring.config.activate.on-profile.
 * Each document becomes one ConfigDocument, in file order, with its condition
 * parsed into a {@link ProfileExpression}; documents are never merged here.
 * <p>
 * Important: this class does NOT decide which documents apply or merge them —
 * that is the responsibility of ConfigFileGrouper (source order) and
 * ProfileMerger (the fold per set of active profiles).
 */
public final class ConfigLoader {

    /** Spring metadata key indicating which profile a document belongs to. */
    private static final String ON_PROFILE_KEY = "spring.config.activate.on-profile";

    /**
     * Sentinel key suffix emitted when YAML explicitly defines an
     * EMPTY list (e.g., "allowed-origins: []"). Without this, an empty
     * list produces zero flattened keys — indistinguishable from "the key was
     * never mentioned" — and ProfileMerger would have no way to know that the
     * profile intended to clear the list inherited from the base.
     * <p>
     * Package-visible by design: ProfileMerger needs to recognize and then
     * remove this key before exposing the result to any Rule — it is an
     * internal infrastructure signal, not actual configuration data.
     */
    static final String EMPTY_LIST_SENTINEL_SUFFIX = ".__empty_list__";

    /**
     * Sentinel key suffix for an explicitly empty YAML Map/object
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

    /** Build-output directory names, excluded only when a sibling build file marks them as such. */
    private static final Set<String> BUILD_OUTPUT_DIRS = Set.of("target", "build");

    private static final List<String> BUILD_FILES = List.of("pom.xml", "build.gradle", "build.gradle.kts");

    /**
     * Walks {@code dir} recursively, skipping two kinds of directory whose config files never ship
     * with the application (see ARCHITECTURE.md, ADR-006):
     * <ul>
     *   <li>Build output: a {@code target/} or {@code build/} directory next to a Maven or Gradle
     *       build file. It holds copies of {@code src/main/resources} (possibly stale, or filtered
     *       with substituted values), which would duplicate or contradict the real source.</li>
     *   <li>Test source sets: {@code src/test/}. Test-only config (H2 console on, fixed passwords)
     *       isn't packaged, and a Policy can't suppress it without also suppressing the same rule
     *       for the main config, since suppression is per rule + profile, not per directory.</li>
     * </ul>
     * Only directories strictly below {@code dir} are considered, so passing one of them directly
     * as the scan root still scans it.
     */
    public List<ConfigFile> loadDirectory(Path dir) throws IOException {
        List<ConfigFile> result = new ArrayList<>();
        if (!Files.isDirectory(dir)) {
            return result;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            List<Path> candidates = paths
                    .filter(Files::isRegularFile)
                    .filter(ConfigLoader::isSpringConfigFile)
                    .filter(p -> !isUnderExcludedDirectory(dir, p))
                    .toList();

            for (Path p : candidates) {
                result.add(loadFile(p));
            }
        }
        return result;
    }

    /**
     * Parses a single file, already known to be YAML or properties, into a ConfigFile.
     * Package-visible so ConfigServerAssembler can reuse this exact parsing (multi-document
     * profile extraction, relaxed on-profile key lookup, sentinel handling) for files that
     * don't match the "application" prefix loadDirectory requires.
     */
    ConfigFile loadFile(Path p) throws IOException {
        List<ConfigDocument> documents = p.toString().endsWith(".properties")
                ? loadProperties(p)
                : loadYaml(p);
        return new ConfigFile(p, documents);
    }

    private static boolean isUnderExcludedDirectory(Path root, Path file) {
        Path relative = root.relativize(file);
        Path parent = root;
        // The last name is the file itself; only its ancestor directories are checked.
        for (int i = 0; i < relative.getNameCount() - 1; i++) {
            String name = relative.getName(i).toString();
            if (BUILD_OUTPUT_DIRS.contains(name) && hasBuildFile(parent)) {
                return true;
            }
            if ("test".equals(name) && parent.getFileName() != null
                    && "src".equals(parent.getFileName().toString())) {
                return true;
            }
            parent = parent.resolve(name);
        }
        return false;
    }

    private static boolean hasBuildFile(Path directory) {
        return BUILD_FILES.stream().anyMatch(buildFile -> Files.isRegularFile(directory.resolve(buildFile)));
    }

    private static boolean isSpringConfigFile(Path p) {
        String name = p.getFileName().toString();
        return name.startsWith("application")
                && (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml"));
    }

    private List<ConfigDocument> loadProperties(Path p) throws IOException {
        List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
        List<ConfigDocument> documents = new ArrayList<>();
        StringBuilder currentDocBuilder = new StringBuilder();

        for (String line : lines) {
            // Spring Boot requires the separator to be exactly '#---' or "!---"
            // (ignoring surrounding whitespace) (Spring Boot docs)
            if (line.trim().equals("#---") || line.trim().equals("!---"))  {
                addPropertiesDocument(p, currentDocBuilder.toString(), documents);
                currentDocBuilder.setLength(0); // Clear the buffer for the next document
            } else {
                currentDocBuilder.append(line).append("\n");
            }
        }
        // Process the last (or only) block of the file
        addPropertiesDocument(p, currentDocBuilder.toString(), documents);

        return atLeastOneDocument(documents);
    }

    private void addPropertiesDocument(Path p, String rawContent, List<ConfigDocument> documents) throws IOException {
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
            flatDocument.put(normalizeMapKeys(name), props.getProperty(name));
        }
        documents.add(toDocument(p, flatDocument));
    }

    /**
     * Loads a YAML file that may contain multiple documents ("---"), returning
     * one ConfigDocument per non-empty document, in file order. Documents are
     * never merged here, not even two with the same {@code on-profile}: which
     * documents apply, and in which order, is decided per set of active profiles
     * by ProfileMerger.
     */
    private List<ConfigDocument> loadYaml(Path p) throws IOException {
        try (var in = Files.newInputStream(p)) {
            Yaml yaml = new Yaml();
            Iterable<Object> rawDocuments = yaml.loadAll(in);
            List<ConfigDocument> documents = new ArrayList<>();

            for (Object rawDocument : rawDocuments) {
                if (rawDocument == null) {
                    // Empty document (e.g., "---" alone at the end of the file).
                    // It does not generate any ConfigDocument — we simply ignore it.
                    continue;
                }

                Map<String, String> rawFlat = new LinkedHashMap<>();
                flatten(rawDocument, "", rawFlat);
                Map<String, String> flatDocument = new LinkedHashMap<>();
                rawFlat.forEach((key, value) -> flatDocument.put(normalizeMapKeys(key), value));
                documents.add(toDocument(p, flatDocument));
            }

            return atLeastOneDocument(documents);

        }  catch (YAMLException e) {

        // SnakeYAML parsing is lazy (it happens during iteration of the for loop
        // above, not in loadAll() itself), so YAMLException — which is a
        // RuntimeException, not IOException — may be thrown here and
        // would propagate unhandled to Main.main() without this catch. Translated
        // to IOException here, at the source, so Main can continue relying solely
        // on the IOException contract it already knows how to handle (USAGE_ERROR,
        // readable message) — without having to catch generic RuntimeException there,
        // which would hide real bugs behind the same usage-error message.

        throw new IOException("Invalid YAML in '%s': %s".formatted(p, e.getMessage()), e);
    }
    }

    /** Keeps the invariant that every ConfigFile has at least one ConfigDocument. */
    private static List<ConfigDocument> atLeastOneDocument(List<ConfigDocument> documents) {
        if (documents.isEmpty()) {
            documents.add(new ConfigDocument(Optional.empty(), Map.of()));
        }
        return documents;
    }

    /**
     * Separates a flattened document's {@code spring.config.activate.on-profile} from its
     * properties, and parses it as Spring Boot does (ARCHITECTURE.md, ADR-012). The key is
     * matched with relaxed binding ({@code onProfile}, {@code ON_PROFILE}) and in every form
     * flattening gives it: a scalar, a YAML list ({@code on-profile[0]}, {@code [1]}, read as
     * the comma-separated list it binds to), a YAML null or an empty list. Measured against
     * Spring Boot 4.1.1 (VALIDATION.md, "Profile expressions in {@code on-profile}"):
     * <ul>
     *   <li>a null, empty string or empty list is no condition: the document always applies;</li>
     *   <li>a blank value ({@code " "}), an empty list item or a malformed expression stops
     *       the application, so it is an input error here too, as invalid YAML is.</li>
     * </ul>
     * Every form of the key is removed from the properties, so no rule sees it.
     */
    private static ConfigDocument toDocument(Path p, Map<String, String> flatDocument) throws IOException {
        String target = RelaxedProperties.canonicalize(ON_PROFILE_KEY);
        String scalar = null;
        TreeMap<Integer, String> items = new TreeMap<>();

        var iterator = flatDocument.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            String key = entry.getKey();
            boolean isNull = key.endsWith(NULL_SCALAR_SENTINEL_SUFFIX);
            String bare = stripSentinelSuffix(key);
            int bracket = bare.indexOf('[');
            String root = bracket >= 0 ? bare.substring(0, bracket) : bare;
            if (!RelaxedProperties.canonicalize(root).equals(target)) {
                continue;
            }
            Integer index = bracket < 0 ? null : listIndex(bare.substring(bracket));
            if (bracket >= 0 && index == null) {
                continue; // not a list item ("[]", an unclosed "["): left among the properties, as any key
            }
            iterator.remove();
            String value = isNull ? "" : entry.getValue();
            if (index == null) {
                if (!key.endsWith(EMPTY_LIST_SENTINEL_SUFFIX) && !key.endsWith(EMPTY_MAP_SENTINEL_SUFFIX)) {
                    scalar = value;
                }
            } else {
                items.put(index, value);
            }
        }

        String text = items.isEmpty() ? scalar : String.join(",", items.values());
        if (text == null || text.isEmpty()) {
            return new ConfigDocument(Optional.empty(), flatDocument);
        }
        try {
            return new ConfigDocument(Optional.of(ProfileExpression.parse(text)), flatDocument);
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid %s in '%s': %s".formatted(ON_PROFILE_KEY, p, e.getMessage()), e);
        }
    }

    /** The index of a {@code [n]} suffix, or null when the suffix is anything else. */
    private static Integer listIndex(String suffix) {
        if (!suffix.matches("\\[\\d{1,9}]")) {
            return null;
        }
        return Integer.parseInt(suffix.substring(1, suffix.length() - 1));
    }

    private static String stripSentinelSuffix(String key) {
        for (String suffix : List.of(NULL_SCALAR_SENTINEL_SUFFIX, EMPTY_LIST_SENTINEL_SUFFIX, EMPTY_MAP_SENTINEL_SUFFIX)) {
            if (key.endsWith(suffix)) {
                return key.substring(0, key.length() - suffix.length());
            }
        }
        return key;
    }

    /**
     * Rewrites every bracketed map key into dotted form ({@code spring.kafka.properties[security.protocol]}
     * becomes {@code spring.kafka.properties.security.protocol}), leaving numeric list indices
     * ({@code [0]}) untouched. See ARCHITECTURE.md, ADR-007.
     * <p>
     * Spring Boot binds both forms to the same map entry for a {@code Map<String, ...>} property, and
     * its own YAML loader turns a quoted {@code "[a.b]"} key into {@code x.map[a.b]}, as this
     * project's YAML flattening does (ADR-008). Without this rewrite, rules only recognized the dotted
     * form, and ProfileMerger treated a bracketed map key as a list index — replacing the whole map
     * across profiles instead of merging it key by key.
     * <p>
     * Accepted trade-off: the bracket form preserves characters that relaxed binding otherwise
     * ignores, so {@code [com.foo-bar]} and {@code [com.foobar]} are distinct keys in Spring but
     * canonicalize to the same key here.
     */
    static String normalizeMapKeys(String key) {
        if (key.indexOf('[') < 0) {
            return key;
        }
        StringBuilder result = new StringBuilder(key.length());
        int i = 0;
        while (i < key.length()) {
            char c = key.charAt(i);
            int close = c == '[' ? key.indexOf(']', i + 1) : -1;
            if (close < 0) {
                result.append(c);
                i++;
                continue;
            }
            String content = key.substring(i + 1, close);
            if (content.isEmpty() || content.chars().allMatch(Character::isDigit)) {
                result.append(key, i, close + 1); // list index (or empty brackets): keep as is
            } else {
                if (!result.isEmpty() && result.charAt(result.length() - 1) != '.') {
                    result.append('.');
                }
                result.append(content);
            }
            i = close + 1;
        }
        return result.toString();
    }

    private void flatten(Object yamlNode,
                         String prefix,
                         Map<String, String> flat) {

        switch (yamlNode) {
            case null -> {
                if (!prefix.isEmpty()) {
                    flat.put(prefix + NULL_SCALAR_SENTINEL_SUFFIX, "true");
                }
            }
            case Map<?, ?> map -> {

                if (map.isEmpty()) {
                    flat.put(prefix + EMPTY_MAP_SENTINEL_SUFFIX, "true");
                    return;
                }

                for (var entry : map.entrySet()) {

                    // Same join rule as Spring's own YAML loader: a key starting with '[' (a quoted
                    // "[0]" index or "[a.b]" map key) attaches to its parent without a dot, so
                    // "x" + "[0]" is x[0], not x.[0]. See ARCHITECTURE.md, ADR-008.
                    String key = entry.getKey().toString();
                    String child = prefix.isEmpty() || key.startsWith("[")
                            ? prefix + key
                            : prefix + "." + key;

                    flatten(entry.getValue(), child, flat);
                }
            }
            case List<?> list -> {

                if (list.isEmpty()) {
                    // An explicitly empty list leaves
                    // no trace if we simply iterate over nothing. Emit
                    // a sentinel so ProfileMerger can distinguish
                    // "profile redefined as empty" from "profile did not mention it at all".
                    flat.put(prefix + EMPTY_LIST_SENTINEL_SUFFIX, "true");
                } else {
                    for (int i = 0; i < list.size(); i++) {
                        flatten(list.get(i), prefix + "[" + i + "]", flat);
                    }
                }
            }
            default -> flat.put(prefix, String.valueOf(yamlNode));
        }

    }
}