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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Validation harness for ProfileMerger against a real Spring Boot application
 * ({@code spring-env-benchmark}, a plain sibling directory at the repository
 * root -- not a Maven module of this build, the same way demo-project/ and
 * demo-project-clean/ aren't: SCG's own build never resolves or depends on
 * Spring Boot because of it. See BACKLOG.md and VALIDATION.md for the full
 * rationale and steps).
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

        System.out.println("All ProfileMerger benchmark criteria matched real Spring Boot.");
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
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(ACTUATOR_URL)).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), "Spring server must be up on port 8081");
            return response.body();
        }
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
