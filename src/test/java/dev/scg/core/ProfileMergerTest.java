package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes do ProfileMerger — a peça que funde o documento base (sem profile)
 * de um ConfigFile com cada documento de profile nomeado, produzindo a
 * List<EffectiveConfig> que o RuleEngine efetivamente avalia.
  * Diferente de ConfigLoaderTest, aqui construímos ConfigFile/ConfigDocument
 * diretamente em memória (sem passar por parsing de YAML/properties), para
 * isolar e testar só a lógica de merge, não a leitura de arquivo.
 */
class ProfileMergerTest {

    private static final Path FAKE_PATH = Path.of("application.yml");

    private final ProfileMerger merger = new ProfileMerger();

    @Test
    @DisplayName("File with only the base document (without a named profile) should generate exactly 1 EffectiveConfig")
    void fileWithOnlyBaseShouldGenerateSingleEffectiveConfig() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("server.port", "8080"))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        assertEquals(1, result.size());
        assertEquals(ProfileMerger.BASE_PROFILE_LABEL, result.getFirst().profileLabel());
        assertEquals("8080", result.getFirst().properties().get("server.port"));
    }

    @Test
    @DisplayName("Should merge base with named profile without cross-contamination, inheriting what the profile does not override")
    void shouldMergeBaseWithNamedProfileWithoutCrossContamination() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of(
                        "server.port", "8080",
                        "management.endpoint.env.enabled", "false"
                ))),
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of(
                        "management.endpoints.web.exposure.include", "*"
                )))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        assertEquals(2, result.size());

        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig dev = findByLabel(result, "dev");

        // base should not have been contaminated by the dev profile
        assertFalse(base.properties().containsKey("management.endpoints.web.exposure.include"));
        assertEquals("8080", base.properties().get("server.port"));

        // dev should have BOTH what belongs to it and what it inherited from base
        assertEquals("*", dev.properties().get("management.endpoints.web.exposure.include"));
        assertEquals("8080", dev.properties().get("server.port"));
        assertEquals("false", dev.properties().get("management.endpoint.env.enabled"));
    }

    @Test
    @DisplayName("Profile should override a scalar key that also exists in the base")
    void profileShouldOverrideScalarKeyThatAlsoExistsInBase() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of("logging.level.root", "INFO"))),
                new ConfigDocument(Optional.of("prod"), new LinkedHashMap<>(Map.of("logging.level.root", "WARN")))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        assertEquals("WARN", findByLabel(result, "prod").properties().get("logging.level.root"));
        assertEquals("INFO", findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL).properties().get("logging.level.root"));
    }

    @Test
    @DisplayName("List should be replaced entirely by the profile, not merged index by index")
    void listShouldBeReplacedEntirelyByProfileNotMergedIndexByIndex() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins[0]", "a.com");
        baseProps.put("cors.allowed-origins[1]", "b.com");
        baseProps.put("cors.allowed-origins[2]", "c.com");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.allowed-origins[0]", "x.com"); // profile only redefines index 0

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("x.com", dev.properties().get("cors.allowed-origins[0]"));
        assertFalse(dev.properties().containsKey("cors.allowed-origins[1]"),
                "Base index [1] should not remain when the profile redefines the list");
        assertFalse(dev.properties().containsKey("cors.allowed-origins[2]"),
                "Base index [2] should not remain when the profile redefines the list");

        // base should not have been affected by the merge performed for "dev"
        assertEquals(3, findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL).properties().size());
    }

    @Test
    @DisplayName("Map lists (Level B) should also be replaced entirely, not merged by sub-key")
    void mapListsShouldAlsoBeReplacedEntirely() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.origins[0].name", "production");
        baseProps.put("cors.origins[0].url", "https://a.com");
        baseProps.put("cors.origins[1].name", "staging");
        baseProps.put("cors.origins[1].url", "https://b.com");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.origins[0].name", "local");
        devProps.put("cors.origins[0].url", "http://localhost");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("local", dev.properties().get("cors.origins[0].name"));
        assertFalse(dev.properties().containsKey("cors.origins[1].name"));
        assertFalse(dev.properties().containsKey("cors.origins[1].url"));
    }

    @Test
    @DisplayName("File where EVERY block declares a profile (no explicit base) should generate a base with an empty map")
    void fileWithoutExplicitBaseShouldGenerateBaseWithEmptyMap() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of("server.port", "9090"))),
                new ConfigDocument(Optional.of("prod"), new LinkedHashMap<>(Map.of("logging.level.root", "WARN")))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        assertEquals(3, result.size()); // empty base + dev + prod
        assertTrue(findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL).properties().isEmpty());

        EffectiveConfig dev = findByLabel(result, "dev");
        assertEquals("9090", dev.properties().get("server.port"));
        assertFalse(dev.properties().containsKey("logging.level.root"));
    }

    @Test
    @DisplayName("Merges of different profiles should not share state or mutate the original base map")
    void mergesOfDifferentProfilesShouldNotShareState() {
        Map<String, String> baseProps = new LinkedHashMap<>(Map.of("a", "1"));
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of("b", "2"))),
                new ConfigDocument(Optional.of("prod"), new LinkedHashMap<>(Map.of("c", "3")))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        EffectiveConfig dev = findByLabel(result, "dev");
        EffectiveConfig prod = findByLabel(result, "prod");

        assertFalse(dev.properties().containsKey("c"), "dev should not see prod's exclusive key");
        assertFalse(prod.properties().containsKey("b"), "prod should not see dev's exclusive key");
        assertEquals(1, baseProps.size(), "the original base document map should not be mutated by the merge");
    }

    @Test
    @DisplayName("Base + two named profiles in the same file should generate 3 complete and independent EffectiveConfigs")
    void baseWithTwoNamedProfilesShouldGenerateThreeIndependentEffectiveConfigs() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of(
                        "server.port", "8080",
                        "logging.level.root", "INFO"
                ))),
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of(
                        "management.endpoints.web.exposure.include", "*"
                ))),
                new ConfigDocument(Optional.of("prod"), new LinkedHashMap<>(Map.of(
                        "logging.level.root", "WARN"
                )))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        assertEquals(3, result.size()); // base + dev + prod

        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig dev = findByLabel(result, "dev");
        EffectiveConfig prod = findByLabel(result, "prod");

        // base: only what belongs to it, intact
        assertEquals("8080", base.properties().get("server.port"));
        assertEquals("INFO", base.properties().get("logging.level.root"));
        assertFalse(base.properties().containsKey("management.endpoints.web.exposure.include"));

        // dev: inherits port and logging from base, gains its own exposure
        assertEquals("8080", dev.properties().get("server.port"));
        assertEquals("INFO", dev.properties().get("logging.level.root"));
        assertEquals("*", dev.properties().get("management.endpoints.web.exposure.include"));

        // prod: inherits port from base, but OVERRIDES logging.level.root, and has no exposure
        assertEquals("8080", prod.properties().get("server.port"));
        assertEquals("WARN", prod.properties().get("logging.level.root"));
        assertFalse(prod.properties().containsKey("management.endpoints.web.exposure.include"));
    }

    @Test
    @DisplayName("Profile should be able to add a new list even if the base does not have it")
    void profileAddsNewListThatDoesNotExistInBase() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("server.port", "8080")),
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of(
                        "cors.origins[0]", "http://localhost"
                )))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("8080", dev.properties().get("server.port"));
        assertEquals("http://localhost", dev.properties().get("cors.origins[0]"));
    }

    @Test
    @DisplayName("Profile should be able to expand a list with more indices than the base had")
    void profileShouldExpandListWithMoreIndicesThanBase() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("app.tags[0]", "v1");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("app.tags[0]", "v2");
        devProps.put("app.tags[1]", "v3");
        devProps.put("app.tags[2]", "v4");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);

        // dev should have the 3 NEW elements from the profile, not a mixture with the base
        assertEquals(3, dev.properties().size());
        assertEquals("v2", dev.properties().get("app.tags[0]"));
        assertEquals("v3", dev.properties().get("app.tags[1]"));
        assertEquals("v4", dev.properties().get("app.tags[2]"));

        // base should not have been affected by the merge performed for "dev"
        assertEquals(1, base.properties().size());
        assertEquals("v1", base.properties().get("app.tags[0]"));
    }

    @Test
    @DisplayName("Profile should be able to override two distinct lists simultaneously, without cross-interference")
    void profileOverridesMultipleDistinctListsSimultaneously() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.origins[0]", "a.com");
        baseProps.put("cors.origins[1]", "b.com");
        baseProps.put("logging.ignored[0]", "foo");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.origins[0]", "x.com");
        devProps.put("logging.ignored[0]", "bar");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals(2, dev.properties().size());
        assertEquals("x.com", dev.properties().get("cors.origins[0]"));
        assertFalse(dev.properties().containsKey("cors.origins[1]"),
                "cors.origins[1] from the base should have been removed along with the purge of cors.origins[0]");
        assertEquals("bar", dev.properties().get("logging.ignored[0]"));
    }

    @Test
    @DisplayName("BL-03(b): scalar key (relaxed-binding) redefining the base list should purge orphaned indices")
    void scalarKeyRedefiningBaseListShouldPurgeOrphanedIndices() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins[0]", "a.com");
        baseProps.put("cors.allowed-origins[1]", "b.com");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.allowed-origins", "explicit-value"); // Spring relaxed-binding

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("explicit-value", dev.properties().get("cors.allowed-origins"));
        assertFalse(dev.properties().containsKey("cors.allowed-origins[0]"),
                "The orphaned base index should not survive when the profile redefines it via a scalar");
        assertFalse(dev.properties().containsKey("cors.allowed-origins[1]"));
        assertEquals(1, dev.properties().size());
    }

    @Test
    @DisplayName("BL-03(b): scalar redefinition of a list should not affect another unrelated list")
    void scalarRedefinitionShouldNotAffectUnrelatedList() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.origins[0]", "a.com");
        baseProps.put("cors.origins[1]", "b.com");
        baseProps.put("logging.ignored[0]", "foo");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.origins", "escalar-novo");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("escalar-novo", dev.properties().get("cors.origins"));
        assertFalse(dev.properties().containsKey("cors.origins[0]"));
        assertEquals("foo", dev.properties().get("logging.ignored[0]"), "Unrelated list " +
                "should remain inherited intact");
    }


    @Test
    @DisplayName("KNOWN LIMITATION: if there are 2 base documents (violating the ConfigLoader invariant)," +
            "only the first is used and the second is silently lost")
    void twoBaseDocumentsOnlyFirstIsUsedSecondIsLost() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of("a", "1"))),
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of("b", "2"))), // ignored
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of("c", "3")))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig dev = findByLabel(result, "dev");

        // TODO(backlog): this violates the invariant that ConfigLoader
        // guarantees in practice (it never provides 2 documents with an empty
        // profile in the same ConfigFile). This test documents the CURRENT
        // behavior of ProfileMerger under this violation — it is not the desired behavior.
        // See backlog item "findBaseProperties silently loses data
        // if the single-base-document invariant is violated".
        assertEquals("1", base.properties().get("a"));
        assertNull(base.properties().get("b"), "'b' from the second base document is lost — known, unfixed behavior");

        assertEquals("1", dev.properties().get("a"));
        assertNull(dev.properties().get("b"), "'b' never reaches the dev profile because it never reached the base");
        assertEquals("3", dev.properties().get("c"));
    }

    @Test
    @DisplayName("Base document positioned after named profiles should still be found and used as the base, regardless of order")
    void baseAfterProfilesShouldBeFoundRegardlessOfOrder() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of("x", "1"))),
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of("base-only", "true")))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("true", base.properties().get("base-only"));
        assertEquals("true", dev.properties().get("base-only"), "dev should inherit base-only even though the base comes later in the list");
        assertEquals("1", dev.properties().get("x"));
    }

    @Test
    @DisplayName("Merge should not mutate the original profile document map")
    void mergeShouldNotMutateProfileMap() {
        Map<String, String> profileProps = new LinkedHashMap<>(Map.of("x", "1"));
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("a", "1")),
                new ConfigDocument(Optional.of("dev"), profileProps)
        ));

        merger.merge(file);

        assertEquals(1, profileProps.size());
        assertEquals("1", profileProps.get("x"));
    }
    @Test
    @DisplayName("EffectiveConfig.properties() should be protected against external mutation (BL-01 fixed)")
    void effectiveConfigShouldBeProtectedAgainstExternalMutation() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("a", "1")),
                new ConfigDocument(Optional.of("dev"), Map.of("x", "1"))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertThrows(UnsupportedOperationException.class,
                () -> base.properties().put("chave-maliciosa", "valor-injetado"),
                "EffectiveConfig for the base should block external mutation");

        assertThrows(UnsupportedOperationException.class,
                () -> dev.properties().put("chave-maliciosa", "valor-injetado"),
                "EffectiveConfig for the profile should block external mutation");
    }

    @Test
    @DisplayName("BL-03(a): profile with an explicit empty list should clear the dangerous list inherited from the base")
    void profileWithExplicitEmptyListShouldClearBaseList() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins[0]", "*");

        Map<String, String> prodProps = new LinkedHashMap<>();
        prodProps.put("cors.allowed-origins.__empty_list__", "true");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("prod"), prodProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig prod = findByLabel(result, "prod");
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);

        assertFalse(prod.properties().containsKey("cors.allowed-origins[0]"));
        assertFalse(prod.properties().containsKey("cors.allowed-origins.__empty_list__"),
                "the sentinel should never remain in the final result exposed to a Rule");
        assertEquals("*", base.properties().get("cors.allowed-origins[0]"),
                "base should not be affected by the merge performed for prod");
    }

    @Test
    @DisplayName("BL-03(a): profile can redefine an empty list as non-empty, replacing it completely")
    void profileRedefinesEmptyListAsNonEmpty() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins[0]", "a.com");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.allowed-origins[0]", "novo.com");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("novo.com", dev.properties().get("cors.allowed-origins[0]"));
    }

    @Test
    @DisplayName("BL-03(a): base with an explicit empty list, profile that does not mention the key, should inherit empty without leaking the sentinel")
    void baseWithEmptyListInheritsEmptyWithoutLeakingSentinel() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins.__empty_list__", "true");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("server.port", "9090");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);

        assertFalse(dev.properties().containsKey("cors.allowed-origins[0]"));
        assertFalse(dev.properties().containsKey("cors.allowed-origins.__empty_list__"));
        assertFalse(base.properties().containsKey("cors.allowed-origins.__empty_list__"));
        assertEquals("9090", dev.properties().get("server.port"));
    }

    @Test
    @DisplayName("BL-03(a): empty object list (not just a scalar list) should also be correctly purged via the sentinel")
    void emptyObjectListShouldAlsoBeCorrectlyPurged() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("users[0].name", "admin");
        baseProps.put("users[0].role", "SUPERUSER");
        baseProps.put("users[1].name", "guest");
        baseProps.put("users[1].role", "READONLY");

        Map<String, String> prodProps = new LinkedHashMap<>();
        prodProps.put("users.__empty_list__", "true");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("prod"), prodProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig prod = findByLabel(result, "prod");
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);

        assertTrue(prod.properties().isEmpty(), "the entire object list should have been purged");
        assertEquals(4, base.properties().size(), "base should not be affected by the merge performed for prod");
    }

    @Test
    @DisplayName("BL-02 resolved: profile explicitly named 'base' no longer collides with the synthetic label")
    void profileExplicitlyNamedBaseNoLongerCollidesWithSyntheticLabel() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("a", "1")),
                new ConfigDocument(Optional.of("base"), Map.of("b", "2"))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        assertEquals(2, result.size());

        EffectiveConfig sintetico = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig doUsuario = findByLabel(result, "base");

        assertFalse(sintetico.properties().containsKey("b"), "the synthetic label should not have inherited anything from the real 'base' profile");
        assertEquals("1", doUsuario.properties().get("a"));
        assertEquals("2", doUsuario.properties().get("b"));
    }

    @Test
    @DisplayName("BL-08: Empty map in profile should NOT purge base keys (unlike a list)")
    void emptyMapInProfileShouldNotPurgeBaseKeys() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("headers.x-app-name", "minha-app");
        baseProps.put("headers.x-region", "brasil");

        Map<String, String> prodProps = new LinkedHashMap<>();
        prodProps.put("headers.__empty_map__", "true"); // "headers: {}" in the profile

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("prod"), prodProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig prod = findByLabel(result, "prod");

        assertEquals("minha-app", prod.properties().get("headers.x-app-name"),
                "Map merges by key — unlike List, headers:{} does not erase what the base defined");
        assertEquals("brasil", prod.properties().get("headers.x-region"));
        assertFalse(prod.properties().containsKey("headers.__empty_map__"),
                "the sentinel should never remain in the result exposed to a Rule");
    }

    @Test
    @DisplayName("BL-09: Profile with explicit scalar null should redefine the base key to null")
    void profileWithExplicitNullShouldRedefineKeyToNull() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("app.feature-x.enabled", "true");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("app.feature-x.enabled.__null_scalar__", "true");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertTrue(dev.properties().containsKey("app.feature-x.enabled"), "The key should exist in the map");
        assertNull(dev.properties().get("app.feature-x.enabled"), "The key value should be null");
    }

    @Test
    @DisplayName("BL-09: Profile with scalar null at a node that was an object in the base should purge sub-keys and result in null")
    void profileWithNullAtObjectNodeShouldPurgeSubKeys() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("db.connection.timeout", "30");
        baseProps.put("db.connection.host", "localhost");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("db.connection.__null_scalar__", "true");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertFalse(dev.properties().containsKey("db.connection.timeout"));
        assertFalse(dev.properties().containsKey("db.connection.host"));
        assertTrue(dev.properties().containsKey("db.connection"));
        assertNull(dev.properties().get("db.connection"));
    }

    @Test
    @DisplayName("List Purge: Profile with a smaller list should completely remove extra indices from the base")
    void profileWithSmallerListShouldPurgeExtraIndicesFromBase() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("management.endpoints.web.exposure.include[0]", "health");
        baseProps.put("management.endpoints.web.exposure.include[1]", "info");
        baseProps.put("management.endpoints.web.exposure.include[2]", "env");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("management.endpoints.web.exposure.include[0]", "*");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("*", dev.properties().get("management.endpoints.web.exposure.include[0]"));
        assertFalse(dev.properties().containsKey("management.endpoints.web.exposure.include[1]"));
        assertFalse(dev.properties().containsKey("management.endpoints.web.exposure.include[2]"));
    }

    @Test
    @DisplayName("Canonical List Purge: camelCase list redefinition in dev should purge kebab-case list from the base")
    void camelCaseListRedefinitionShouldPurgeKebabCaseListFromBase() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("my-custom-list[0]", "item1");
        baseProps.put("my-custom-list[1]", "item2");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("myCustomList[0]", "overrideItem");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("overrideItem", dev.properties().get("myCustomList[0]"));
        assertFalse(dev.properties().containsKey("my-custom-list[0]"));
        assertFalse(dev.properties().containsKey("my-custom-list[1]"));
    }

    @Test
    @DisplayName("Overlay should override a scalar from the base even with different casing, without leaving both keys coexisting")
    void overlayShouldOverrideBaseScalarWithDifferentCasingWithoutDuplicatingKey() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("spring.h2.console.enabled", "true");

        Map<String, String> prodProps = new LinkedHashMap<>();
        prodProps.put("spring.h2.console.ENABLED", "false"); // same property, different casing

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("prod"), prodProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig prod = findByLabel(result, "prod");

        // The two keys should not coexist — only the resolution via
        // RelaxedProperties would matter, but the goal here is to ensure that
        // the merge already resolves this at the source, without relying on
        // RelaxedProperties.get() to "choose correctly" between two remaining conflicting keys.
        assertEquals(1, prod.properties().size(),
                "Base and overlay represent the SAME Spring property — only one key should survive");
        assertEquals("false", RelaxedProperties.get(prod.properties(), "spring.h2.console.enabled"),
                "the profile value should take precedence over the inherited base value");
    }

    private EffectiveConfig findByLabel(List<EffectiveConfig> configs, String label) {
        return configs.stream()
                .filter(e -> e.profileLabel().equals(label))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No EffectiveConfig found with label: " + label));    }

}