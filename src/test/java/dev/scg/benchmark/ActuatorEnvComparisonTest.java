package dev.scg.benchmark;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.scg.core.*;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Validation harness for ProfileMerger against a real Spring Boot application
 * ({@code spring-env-benchmark}, a plain sibling directory at the repository
 * root -- not a Maven module of this build, the same way demo-project/ and
 * demo-project-clean/ aren't: SCG's own build never resolves or depends on
 * Spring Boot because of it. See VALIDATION.md, "ProfileMerger correctness
 * benchmark", for the full rationale and steps).
 *
 * <p>Prerequisite: start the 'spring-env-benchmark' application on port 8081
 * with the 'prod' profile active
 * (e.g.: {@code cd spring-env-benchmark && mvn spring-boot:run "-Dspring-boot.run.profiles=prod"}).
 *
 * <p>The comparison can't be a raw key-by-key diff: real Spring keeps
 * {@code app.relaxed-binding-test} (from the base) and {@code app.relaxedBindingTest}
 * (from the profile) as two separate physical entries in different
 * PropertySources -- relaxed-binding resolution only happens when the
 * property is *read*, not physically. SCG's {@code ProfileMerger} already
 * resolves this statically (only one key survives, the profile's). That's
 * why the map extracted from Actuator is canonicalized ({@link RelaxedProperties#canonicalize})
 * before comparing, and the value kept per canonical key is the one from the
 * HIGHEST-precedence source that declares it -- just taking the last raw
 * occurrence isn't enough.
 *
 * <p>Tagged {@code "benchmark"} instead of {@code @Disabled}: this class must
 * never run as part of the regular build (it always fails without the app
 * above running), but unlike {@code @Disabled}, a tag can be excluded or
 * selected from the command line -- no source edit needed to turn it on or
 * off.
 * <ul>
 *   <li>{@code mvn test} (or any plain build) -- this class does NOT run.
 *       The root {@code pom.xml}'s {@code excludedGroups} property defaults
 *       to {@code benchmark}, and surefire is wired to that property.</li>
 *   <li>{@code mvn test -Dgroups=benchmark -DexcludedGroups=} -- runs ONLY
 *       this class (with the app already up on port 8081). {@code groups}
 *       selects the {@code benchmark} tag; {@code -DexcludedGroups=} (empty)
 *       is required too, to override the pom's default exclusion of that
 *       same tag -- without it, surefire ends up with "include benchmark AND
 *       exclude benchmark", which runs nothing.</li>
 * </ul>
 */
@Tag("benchmark")
class ActuatorEnvComparisonTest {

    private static final String ACTUATOR_URL = "http://localhost:8081/actuator/env";
    private static final String CONFIGPROPS_URL = "http://localhost:8081/actuator/configprops";
    private static final String BRACKET_MAP_PREFIX = "app.bracket-map.";
    private static final Path BENCHMARK_RESOURCES_PATH =
            Path.of("spring-env-benchmark/src/main/resources");

    @Test
    void compareProfileMergerWithActuatorEnv() throws Exception {
        Map<String, String> scgProperties = scgEffectiveConfigForProfile("prod").properties();

        System.out.println("=== SCG EffectiveConfig (profile: prod) ===");
        new LinkedHashMap<>(scgProperties).forEach((k, v) -> System.out.println(k + " = " + v));
        System.out.println("============================================\n");

        String actuatorJson = fetchActuatorEnv();
        System.out.println("=== Spring Boot /actuator/env (raw) ===");
        System.out.println(actuatorJson);
    }

    @Test
    void validateProfileMergerAgainstSpringActuator() throws Exception {
        EffectiveConfig scgConfig = scgEffectiveConfigForProfile("prod");
        Map<String, String> scg = scgConfig.properties();

        String actuatorJson = fetchActuatorEnv();
        Map<String, String> spring = canonicalConfigResourceProperties(actuatorJson);

        // 1. Simple scalar override
        assertEquals(
                spring.get(RelaxedProperties.canonicalize("app.scalar-property")),
                RelaxedProperties.get(scg, "app.scalar-property"),
                "Simple scalar override must be identical"
        );

        // 2. List redefinition -- the base had 2 items, the profile redefines it to 1;
        // the result must be exactly the new item, with no leftover from the old index.
        assertEquals("prod-single-item", scg.get("app.list-property[0]"),
                "First list item must be the value redefined by the profile");
        assertNull(scg.get("app.list-property[1]"),
                "SCG must not keep the base list's second element after the override");

        // 3. Relaxed binding: the base writes 'relaxed-binding-test' (kebab-case), the
        // profile overrides it as 'relaxedBindingTest' (camelCase) -- both sides must
        // resolve to the SAME value (the profile's), despite the different spelling.
        String canonicalRelaxedKey = RelaxedProperties.canonicalize("app.relaxed-binding-test");
        assertEquals("camel-override", spring.get(canonicalRelaxedKey),
                "Real Spring must resolve the canonical key to the profile's value, not the base's");
        assertEquals("camel-override", RelaxedProperties.get(scg, "app.relaxed-binding-test"),
                "SCG must resolve the same canonical key, written in kebab-case, to the profile's value");
        assertEquals("camel-override", RelaxedProperties.get(scg, "app.relaxedBindingTest"),
                "And also written in camelCase -- it's the same property");

        // 4. Override to an explicit null. /actuator/env serializes a null value
        // as an empty string (a limitation of the comparison technique itself,
        // not of SCG -- documented in VALIDATION.md); in SCG, the key remains
        // in the map with a real Java null value.
        assertEquals("", spring.get(RelaxedProperties.canonicalize("app.nullable-override")),
                "Real Spring serializes the null override as an empty string in the /actuator/env JSON");
        assertTrue(scg.containsKey("app.nullable-override"),
                "SCG must keep the key (not remove it) when the profile overrides it with null");
        assertNull(scg.get("app.nullable-override"),
                "SCG must resolve the null override as a real Java null, not an empty string");

        // 5. Placeholder with a default, environment variable undefined on
        // both sides -- Spring resolves it at runtime; SCG keeps the raw
        // placeholder in EffectiveConfig and only resolves it on demand, via
        // EnvironmentPlaceholder.resolve() (each Rule calls that, not the
        // merge) -- so the comparison needs to explicitly resolve the SCG
        // side before comparing it to Spring's already-resolved value.
        String scgRawPlaceholder = RelaxedProperties.get(scg, "app.placeholder-with-default");
        assertEquals(
                spring.get(RelaxedProperties.canonicalize("app.placeholder-with-default")),
                EnvironmentPlaceholder.resolve(scgRawPlaceholder).orElseThrow(),
                "Without the env var defined, both sides must resolve to the same default value"
        );

        // 6. Named profile file (application-prod.yml) vs. an on-profile block
        // inside the base file, both targeting "prod". Both sources must
        // contribute (the on-profile-only key must survive), and on a key
        // conflict the named file must win over the on-profile block.
        assertEquals("from-internal-on-profile",
                RelaxedProperties.get(scg, "app.on-profile-only-property"),
                "A key that only exists in the on-profile block must still survive the fold");
        assertEquals("from-named-file", scg.get("app.file-vs-on-profile-conflict"),
                "The named profile file must win a key conflict over an on-profile block in the base file");

        System.out.println("All ProfileMerger benchmark criteria matched real Spring Boot.");
    }

    /**
     * Bracketed map keys (ADR-007). /actuator/env can't be the oracle here: it lists each
     * property source's raw keys separately, while merging map entries across sources and
     * treating {@code [a.b]} and {@code a.b} as one key happen in Spring's Binder. So the map is
     * compared against /actuator/configprops, which shows {@code app.bracket-map} as bound into
     * {@code BenchmarkProperties} in the benchmark app: Spring's final answer.
     */
    @Test
    void validateBracketedMapKeysAgainstSpringConfigprops() throws Exception {
        Map<String, String> scgProperties = scgEffectiveConfigForProfile("prod").properties();
        Map<String, String> scg = bracketMapEntries(scgProperties);
        Map<String, String> spring = boundBracketMap(fetch(CONFIGPROPS_URL));

        // 8. A profile adding an entry keeps the base's entries (merged key by key, not replaced
        // like a list).
        for (String key : List.of("com.acme-core", "org.example", "com.other")) {
            assertNotNull(spring.get(key), "Spring must bind entry '" + key + "'");
            assertEquals(spring.get(key), scg.get(key), "Entry '" + key + "' must survive the merge");
        }
        // 9. A profile overriding one entry replaces only that entry.
        assertEquals("from-prod", spring.get("override.me"));
        assertEquals("from-prod", scg.get("override.me"));
        // 10. "[security.protocol]" (application.yml) and "security.protocol" (application.properties)
        // are the same key, so .properties wins the conflict.
        assertEquals("SASL_SSL", spring.get("security.protocol"));
        assertEquals("SASL_SSL", scg.get("security.protocol"));
        // 12. A dotted key without brackets, nested in YAML, is one map entry too.
        assertEquals("nested-dotted", spring.get("plain.dotted"));
        assertEquals("nested-dotted", scg.get("plain.dotted"));
        // 13. A bracketed key in .properties is overridden by the profile's bracketed YAML key.
        assertEquals("from-prod-yml", spring.get("props.bracketed"));
        assertEquals("from-prod-yml", scg.get("props.bracketed"));
        // 14. A bracketed entry only defined in the on-profile block survives the fold.
        assertEquals("on-profile-entry", spring.get("from.on-profile"));
        assertEquals("on-profile-entry", scg.get("from.on-profile"));

        // 11. Known divergence, accepted in ADR-007: Spring keeps "[com.foo-bar]" and
        // "[com.foobar]" as two entries; once rewritten into dotted form, SCG's relaxed binding
        // sees one key and the profile's value wins. Asserted on both sides, so a change in either
        // one fails here instead of passing unnoticed.
        assertEquals("dash-from-base", spring.get("com.foo-bar"));
        assertEquals("no-dash-from-prod", spring.get("com.foobar"));
        assertEquals("no-dash-from-prod", RelaxedProperties.get(scgProperties, "app.bracket-map.com.foo-bar"),
                "SCG resolves the base's spelling to the profile's value");
        assertEquals(1, scg.keySet().stream()
                        .filter(k -> RelaxedProperties.canonicalize(k).equals(RelaxedProperties.canonicalize("com.foobar")))
                        .count(),
                "SCG keeps a single entry for the two colliding keys");

        // Every other entry: the two maps must be identical, so an entry SCG drops or invents
        // fails even if no assertion above names it.
        Map<String, String> springWithoutCollision = new LinkedHashMap<>(spring);
        Map<String, String> scgWithoutCollision = new LinkedHashMap<>(scg);
        springWithoutCollision.keySet().removeAll(List.of("com.foo-bar", "com.foobar"));
        scgWithoutCollision.keySet().removeAll(List.of("com.foo-bar", "com.foobar"));
        assertEquals(new TreeMap<>(springWithoutCollision), new TreeMap<>(scgWithoutCollision),
                "Apart from the accepted collision, SCG's map must be the one Spring binds");

        // The raw spelling the YAML loader produces is "x.map[a.b]", not "x.map.[a.b]": the second
        // half of the original bug, where the two formats never matched.
        String env = fetch(ACTUATOR_URL);
        assertTrue(env.contains("\"app.bracket-map[com.acme-core]\""),
                "Spring's YAML loader keeps the bracket attached to the map name");
        assertFalse(env.contains("app.bracket-map.["), "No source spells the key with a dot before the bracket");

        System.out.println("All bracketed map key criteria matched real Spring Boot.");
    }
    @SuppressWarnings("SameParameterValue")
    private EffectiveConfig scgEffectiveConfigForProfile(String profile) throws Exception {
        List<GroupedConfigFile> groups = new ConfigFileGrouper()
                .group(new ConfigLoader().loadDirectory(BENCHMARK_RESOURCES_PATH));

        for (GroupedConfigFile group : groups) {
            for (EffectiveConfig ec : new ProfileMerger().merge(group.mergedFile())) {
                if (profile.equalsIgnoreCase(ec.profileLabel())) {
                    return ec;
                }
            }
        }
        throw new IllegalStateException("Profile '" + profile + "' was not found in SCG's merge");
    }

    private String fetchActuatorEnv() throws Exception {
        return fetch(ACTUATOR_URL);
    }

    private String fetch(String url) throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), "Spring server must be up on port 8081");
            return response.body();
        }
    }

    /** SCG's {@code app.bracket-map.*} entries, keyed by the map key (the part after the prefix). */
    private static Map<String, String> bracketMapEntries(Map<String, String> scgProperties) {
        Map<String, String> entries = new LinkedHashMap<>();
        scgProperties.forEach((key, value) -> {
            if (key.startsWith(BRACKET_MAP_PREFIX)) {
                entries.put(key.substring(BRACKET_MAP_PREFIX.length()), value);
            }
        });
        return entries;
    }

    /** The {@code bracketMap} of the bean bound to prefix {@code app}, as /actuator/configprops shows it. */
    private static Map<String, String> boundBracketMap(String configpropsJson) throws Exception {
        for (JsonNode context : new ObjectMapper().readTree(configpropsJson).get("contexts")) {
            for (JsonNode bean : context.get("beans")) {
                if ("app".equals(bean.path("prefix").asText())) {
                    Map<String, String> map = new LinkedHashMap<>();
                    bean.path("properties").path("bracketMap").fields()
                            .forEachRemaining(entry -> map.put(entry.getKey(), entry.getValue().asText()));
                    assertFalse(map.isEmpty(), "configprops must show the bound bracketMap");
                    return map;
                }
            }
        }
        throw new IllegalStateException("No bean bound to prefix 'app' in /actuator/configprops");
    }

    /**
     * Extracts only the file-based PropertySources (covers both the old
     * Spring Boot spelling, {@code "applicationConfig: [...]"}, and the
     * current Boot 4.x one, {@code "Config resource '...' via location '...'"} --
     * confirmed against a real app, not assumed from docs), ignores
     * systemEnvironment/systemProperties/etc., and resolves by CANONICAL key
     * (relaxed binding), keeping the value from the highest-precedence
     * source -- the /actuator/env array already comes ordered from highest
     * to lowest precedence, so processing it in order and never overwriting
     * an already-seen canonical key gets this right without reimplementing
     * Spring's own merge.
     */
    private Map<String, String> canonicalConfigResourceProperties(String jsonResponse) throws Exception {
        Map<String, String> canonical = new LinkedHashMap<>();
        JsonNode root = new ObjectMapper().readTree(jsonResponse);

        for (JsonNode source : root.get("propertySources")) {
            String name = source.get("name").asText();
            if (!name.contains("Config resource") && !name.startsWith("applicationConfig:")) {
                continue;
            }

            JsonNode properties = source.get("properties");
            var fields = properties.fields();
            while (fields.hasNext()) {
                var entry = fields.next();
                String rawKey = entry.getKey();
                String canonicalKey = rawKey.contains("[")
                        ? rawKey // list index keys already match SCG's own bracket notation; don't canonicalize
                        : RelaxedProperties.canonicalize(rawKey);

                // First occurrence wins -- propertySources is already ordered
                // highest-precedence first by Spring itself.
                canonical.putIfAbsent(canonicalKey, entry.getValue().path("value").asText(""));
            }
        }
        return canonical;
    }
}
