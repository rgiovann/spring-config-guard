package dev.scg.core;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the manual YAML parser in ConfigLoader.loadYaml.
 * Each test isolates a specific behavior of the indentation logic
 * (stack), comment separation, or value handling — so that,
 * if any of them breaks in the future (e.g., when refactoring to use snakeyaml),
 * it is obvious exactly which behavior regressed.
 */
class ConfigLoaderTest {

    @Test
    @DisplayName("Should flatten YAML even with complex indentation levels")
    void shouldFlattenYamlWithComplexIndentationLevels(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                server:
                  port: 8080
                  servlet:
                    context-path: /api
                """);

        assertEquals("8080", values.get("server.port"));
        assertEquals("/api", values.get("server.servlet.context-path"));
    }

    @Test
    @DisplayName("Should flatten multiple levels of nesting in YAML")
    void shouldFlattenMultipleLevelsOfNesting(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  database:
                    connection:
                      timeout: 30
                """);

        assertEquals("30", values.get("app.database.connection.timeout"));
    }

    @Test
    @DisplayName("Should pop multiple nesting levels when returning to the YAML root")
    void shouldPopMultipleNestingLevelsAtOnceWhenReturningToRoot(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                a:
                  b:
                    c:
                      d: value
                e: another
                """);

        assertEquals("value", values.get("a.b.c.d"));
        assertEquals("another", values.get("e"));
    }

    @Test
    @DisplayName("Should ignore blank lines and comments when processing the file")
    void shouldIgnoreCommentsAndBlankLines(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                # Top comment
                server:
                  # Block comment
                  port: 8080 # main port

                  host: localhost
                """);

        assertEquals("8080", values.get("server.port"));
        assertEquals("localhost", values.get("server.host"));
    }

    @Test
    @DisplayName("Should remove quotes and extra spaces from the ends of values")
    void shouldTrimQuotesAndExtraSpacesFromValues(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  name:   "My System"
                  version: '1.0.0'
                """);

        assertEquals("My System", values.get("app.name"));
        assertEquals("1.0.0", values.get("app.version"));
    }

    @Test
    @DisplayName("Should keep colons (:) as part of the value when they are inside a String in YAML")
    void shouldTreatColonsInsideTheValueAsPartOfTheValue(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                server:
                  url: https://api.example.com:443/v1
                  time: "10:30"
                """);

        assertEquals("https://api.example.com:443/v1", values.get("server.url"));
        assertEquals("10:30", values.get("server.time"));
    }

    @Test
    @DisplayName("Should return an empty map when processing a file containing only comments")
    void shouldReturnEmptyMapForFileContainingOnlyComments(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                # Only comments

                # Another comment
                """);

        assertTrue(values.isEmpty());
    }

    @Test
    @DisplayName("Should not create a map entry for a parent key that has no children in YAML")
    void parentKeyWithoutChildrenShouldNotCreateMapEntry(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                banco:
                  host: localhost
                config:
                """);

        assertEquals("localhost", values.get("banco.host"));
        assertFalse(values.containsKey("config"), "parent key without children should not become an entry with an empty value");
    }

    @Test
    @DisplayName("Should correctly concatenate an already dotted key with the parent node prefix in YAML")
    void shouldConcatenateAlreadyDottedKeyWithNestingPrefix(@TempDir Path tempDir) throws IOException {
        // Common pattern in real Spring config: mixing "server.port: 8080" (already
        // dotted, single-line key) with actual nested blocks in the same file.
        Map<String, String> values = parse(tempDir, """
                server.port: 8080
                management:
                  endpoint:
                    health.show-details: always
                """);

        assertEquals("8080", values.get("server.port"));
        assertEquals("always", values.get("management.endpoint.health.show-details"));
    }

    @Test
    @DisplayName("Should reset the key path when switching between sibling blocks in YAML")
    void shouldResetKeyPathBetweenSiblingBlocks(@TempDir Path tempDir) throws IOException {
        // Unlike the linear dedent case: here two child blocks of the SAME parent
        // appear in sequence. Ensures that keyStack does not "leak" moduleA into moduleB.
        Map<String, String> values = parse(tempDir, """
                app:
                  moduleA:
                    enabled: true
                  moduleB:
                    enabled: false
                """);

        assertEquals("true", values.get("app.moduleA.enabled"));
        assertEquals("false", values.get("app.moduleB.enabled"));
    }

    @Test
    @DisplayName("Should overwrite the value, keeping the last occurrence when there is a duplicate key at the same level")
    void duplicateKeyAtSameLevelShouldUseLastValue(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  name: First
                  name: Second
                """);

        assertEquals("Second", values.get("app.name"));
    }

    @Test
    @DisplayName("Should distinguish an explicit quoted empty String from a parent node without a value in YAML")
    void explicitQuotedEmptyStringShouldDifferFromParentNodeWithoutValue(@TempDir Path tempDir) throws IOException {
        // "" (with quotes) is a valid VALUE (empty string). It differs from a parent key
        // pai sem filhos (como no teste parentKeyWithoutChildrenShouldNotCreateMapEntry).
        Map<String, String> values = parse(tempDir, """
                app:
                  description: ""
                  metadata:
                    owner: time-x
                """);

        assertTrue(values.containsKey("app.description"));
        assertEquals("", values.get("app.description"));
        assertEquals("time-x", values.get("app.metadata.owner"));
    }

    @Test
    @DisplayName("Should correctly process YAML files with non-standard indentation levels")
    void shouldWorkWithNonStandardIndentationWidths(@TempDir Path tempDir) throws IOException {
        // YAML does not require fixed-width indentation — it only requires that children have
        // indentation GREATER than the parent. The stack compares relative indentation, not multiples of 2.
        Map<String, String> values = parse(tempDir, """
                app:
                      database:
                            timeout: 30
                """);

        assertEquals("30", values.get("app.database.timeout"));
    }

    @Test
    @DisplayName("Should convert a list of simple values into indexed keys [0], [1] in YAML")
    void shouldSupportListOfSimpleValuesAsIndexedKeys(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
            app:
              tags:
                - java
                - spring
              name: Test
            """);

        assertEquals("java", values.get("app.tags[0]"));
        assertEquals("spring", values.get("app.tags[1]"));
        assertEquals("Test", values.get("app.name"));
    }

    @Test
    @DisplayName("Should reset indices [0], [1] for each new list found in YAML")
    void twoConsecutiveListsShouldResetIndexBetweenThem(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
            app:
              first:
                - a
                - b
              second:
                - x
                - y
                - z
            """);

        assertEquals("a", values.get("app.first[0]"));
        assertEquals("b", values.get("app.first[1]"));
        assertEquals("x", values.get("app.second[0]"));
        assertEquals("z", values.get("app.second[2]"));
    }

    @Test
    @DisplayName("Should preserve the hash character (#) in the value when it is inside quotes in YAML")
    void hashInsideQuotesShouldBePreserved(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  password: "secr3t#123"
                """);

        // CURRENT behavior (incorrect): the value is truncated and has a leftover quote.
        assertEquals("secr3t#123", values.get("app.password"),
                "Should have preserved the hash inside quotes.");
    }

    @Test
    @DisplayName("Should correctly load and process a valid .properties file")
    void shouldLoadPropertiesFileCorrectly(@TempDir Path tempDir) throws IOException {
        // 1. Arrange: Creates the temporary application.properties file
        Path propertiesFile = tempDir.resolve("application.properties");
        String content = """
            # Comment that should be ignored
            server.port=8080
            spring.datasource.url: jdbc:postgresql://localhost:5432/db
            app.description = Test Application
            """;
        Files.writeString(propertiesFile, content);

        ConfigLoader configLoader = new ConfigLoader();

        // 2. Act
        List<ConfigFile> configFiles = configLoader.loadDirectory(tempDir);

        // 3. Assert (using org.junit.jupiter.api.Assertions.*)
        assertEquals(1, configFiles.size(), "Should have found exactly 1 file");

        ConfigFile configFile = configFiles.getFirst();
        assertEquals(propertiesFile, configFile.path());

        Map<String, String> properties = configFile.documents().getFirst().properties();

        assertNotNull(properties);
        assertEquals("8080", properties.get("server.port"));
        assertEquals("jdbc:postgresql://localhost:5432/db", properties.get("spring.datasource.url"));
        assertEquals("Test Application", properties.get("app.description"));
    }

    @Test
    @DisplayName("Should load .properties and .yml files from the same directory")
    void shouldLoadBothYamlAndPropertiesFilesFromDirectory(@TempDir Path tempDir) throws IOException {
        // Arrange
        Path propFile = tempDir.resolve("application.properties");
        Files.writeString(propFile, "server.port=8080\n");

        Path yamlFile = tempDir.resolve("application.yml");
        Files.writeString(yamlFile, "server:\n  port: 9090\n");

        ConfigLoader configLoader = new ConfigLoader();

        // Act
        List<ConfigFile> configFiles = configLoader.loadDirectory(tempDir);

        // Assert
        assertEquals(2, configFiles.size(), "Should have loaded 2 configuration files");
    }

    @Test
    @DisplayName("Should load and flatten YAML lists with index notation [0], [1]")
    void shouldFlattenYamlListsWithIndexNotation(@TempDir Path tempDir) throws IOException {
        String content = """
            spring:
              profiles:
                active:
                  - dev
                  - local
            management:
              endpoints:
                web:
                  exposure:
                    include:
                      - health
                      - info
            """;

        Map<String, String> props = parse(tempDir, content);

        assertEquals("dev", props.get("spring.profiles.active[0]"));
        assertEquals("local", props.get("spring.profiles.active[1]"));
        assertEquals("health", props.get("management.endpoints.web.exposure.include[0]"));
        assertEquals("info", props.get("management.endpoints.web.exposure.include[1]"));
    }

    @Test
    @DisplayName("Should process an empty YAML file without throwing exceptions")
    void shouldHandleEmptyYamlFileWithoutExceptions(@TempDir Path tempDir) throws IOException {
        Map<String, String> props = parse(tempDir, "");

        assertTrue(props.isEmpty(), "The property map for empty YAML should be empty");
    }

    @Test
    @DisplayName("Should load a .properties file preserving characters and accents in UTF-8")
    void shouldLoadPropertiesFileWithUtf8Encoding(@TempDir Path tempDir) throws IOException {
        Path propFile = tempDir.resolve("application.properties");
        String content = """
            # Configuration with accents
            server.port=8080
            app.description=Test Application com Acentuação
            app.empty-value=
            """;
        Files.writeString(propFile, content);

        List<ConfigFile> result = new ConfigLoader().loadDirectory(tempDir);

        assertEquals(1, result.size());
        Map<String, String> props = result.getFirst().documents().getFirst().properties();

        assertEquals("8080", props.get("server.port"));
        assertEquals("Test Application com Acentuação", props.get("app.description"));
        assertEquals("", props.get("app.empty-value"));
    }

    @Test
    @DisplayName("Should ignore files that do not follow the application*.properties/yml/yaml convention")
    void shouldIgnoreNonSpringConfigFiles(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("readme.txt"), "instructions=true");
        Files.writeString(tempDir.resolve("config.yml"), "server:\n  port: 8080");
        Files.writeString(tempDir.resolve("application.json"), "{}");

        List<ConfigFile> result = new ConfigLoader().loadDirectory(tempDir);

        assertTrue(result.isEmpty(), "No file outside the Spring convention should be loaded");
    }

    @Test
    @DisplayName("Should automatically flatten a list of maps (Level B) via snakeyaml")
    void shouldSupportListOfMapsWithSnakeyaml(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
            cors:
              origins:
                - name: producao
                  url: https://a.com
                - name: staging
                  url: https://b.com
            """);

        assertEquals("producao", values.get("cors.origins[0].name"));
        assertEquals("https://a.com", values.get("cors.origins[0].url"));
        assertEquals("staging", values.get("cors.origins[1].name"));
        assertEquals("https://b.com", values.get("cors.origins[1].url"));
    }

    @Test
    @DisplayName("Empty or missing YAML document after separator '---' should not break parsing")
    void emptyDocumentAfterLastSeparatorShouldNotBreakParsing(@TempDir Path tempDir) throws IOException {
        // Sub-case A: "---" alone at the end of the file (ghost document at the end)
        List<ConfigDocument> docsA = parseYaml(tempDir, "caseA", """
            server:
              port: 8080
            ---
            """);

        assertEquals(1, docsA.size(), "the final '---' alone should not generate a ghost document");
        assertTrue(docsA.getFirst().profile().isEmpty());
        assertEquals("8080", docsA.getFirst().properties().get("server.port"));

        // Sub-case B: two consecutive "---" (empty document in the middle of the file)
        List<ConfigDocument> docsB = parseYaml(tempDir, "caseB", """
            server:
              port: 8080
            ---
            ---
            spring:
              config:
                activate:
                  on-profile: dev
            management:
              endpoints:
                web:
                  exposure:
                    include: "*"
            """);

        assertEquals(2, docsB.size(), "the empty block between the two '---' should be ignored, not become a document");
        assertTrue(docsB.get(0).profile().isEmpty());
        assertEquals("8080", docsB.get(0).properties().get("server.port"));
        assertEquals(Optional.of("dev"), docsB.get(1).profile());
        assertEquals("*", docsB.get(1).properties().get("management.endpoints.web.exposure.include"));
    }

    //===============================================================================================//
    //===============================================================================================//

    @Test
    @DisplayName("Should split a .properties file into 2 documents using '#---' as separator")
    void shouldSplitPropertiesWithHashThreeDashesIntoTwoDocuments(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            server.port=8080
            #---
            spring.config.activate.on-profile=dev
            management.endpoints.web.exposure.include=*
            """);

        assertEquals(2, docs.size());
        assertTrue(docs.get(0).profile().isEmpty());
        assertEquals("8080", docs.get(0).properties().get("server.port"));

        assertEquals(Optional.of("dev"), docs.get(1).profile());
        assertEquals("*", docs.get(1).properties().get("management.endpoints.web.exposure.include"));
    }

    /**
     * This is the regression test for the bug we found: Spring Boot accepts
     * both "#---" and "!---" as document separators in .properties.
     * Before the fix, "!---" was treated as a regular comment line
     * (ignored), and the two blocks were incorrectly merged into one.
     */
    @Test
    @DisplayName("Should split a .properties file into 2 documents using '!---' as separator (same behavior as '#---')")
    void shouldSplitPropertiesWithExclamationThreeDashesIntoTwoDocuments(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            server.port=8080
            !---
            spring.config.activate.on-profile=dev
            management.endpoints.web.exposure.include=*
            """);

        assertEquals(2, docs.size());
        assertTrue(docs.get(0).profile().isEmpty());
        assertEquals(Optional.of("dev"), docs.get(1).profile());
        assertEquals("*", docs.get(1).properties().get("management.endpoints.web.exposure.include"));

        // Critical point of the original bug: without the "dev" profile, exposure.include=*
        // should not "leak" into the base document.
        assertFalse(docs.get(0).properties().containsKey("management.endpoints.web.exposure.include"));
    }

    @Test
    @DisplayName("Should merge two .properties blocks that share the same named profile")
    void twoPropertiesBlocksWithSameProfileShouldBeMerged(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            #---
            spring.config.activate.on-profile=dev
            server.port=9090
            #---
            spring.config.activate.on-profile=dev
            management.endpoints.web.exposure.include=*
            """);

        assertEquals(1, docs.size());
        assertEquals(Optional.of("dev"), docs.getFirst().profile());
        assertEquals("9090", docs.getFirst().properties().get("server.port"));
        assertEquals("*", docs.getFirst().properties().get("management.endpoints.web.exposure.include"));
    }

    @Test
    @DisplayName("Should generate 1 empty base document for an empty .properties file or one containing only comments")
    void emptyPropertiesOrCommentsOnlyShouldGenerateOneEmptyBaseDocument(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            # just one comment
            # another comment
            """);

        assertEquals(1, docs.size());
        assertTrue(docs.getFirst().profile().isEmpty());
        assertTrue(docs.getFirst().properties().isEmpty());
    }

    @Test
    @DisplayName("Should generate only 1 base document when the .properties file has no separator (non-regression)")
    void propertiesWithoutSeparatorShouldGenerateOnlyOneBaseDocument(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            server.port=8080
            app.name=MeuApp
            """);

        assertEquals(1, docs.size());
        assertTrue(docs.getFirst().profile().isEmpty());
        assertEquals("8080", docs.getFirst().properties().get("server.port"));
        assertEquals("MeuApp", docs.getFirst().properties().get("app.name"));
    }

    @Test
    @DisplayName("The spring.config.activate.on-profile key should be removed from the final map in .properties")
    void onProfileShouldBeRemovedFromFinalMapInProperties(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            #---
            spring.config.activate.on-profile=dev
            server.port=9090
            """);

        assertEquals(1, docs.size());
        assertFalse(docs.getFirst().properties().containsKey("spring.config.activate.on-profile"),
                "the metadata key should not remain in the business property map");
    }

    @Test
    @DisplayName("An explicitly empty YAML list should generate a sentinel key, without indices")
    void shouldEmitSentinelForExplicitlyEmptyYamlList(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
            cors:
              allowed-origins: []
            """);

        assertEquals("true", values.get("cors.allowed-origins.__empty_list__"));
        assertFalse(values.containsKey("cors.allowed-origins[0]"));
    }

    @Test
    @DisplayName("An explicitly empty YAML map/object should generate a sentinel key")
    void shouldEmitSentinelForExplicitlyEmptyYamlMap(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
            headers: {}
            """);

        assertEquals("true", values.get("headers.__empty_map__"));
        assertEquals(1, values.size());
    }

    @Test
    @DisplayName("An explicitly null scalar in YAML should emit a null sentinel key")
    void shouldEmitSentinelForExplicitNullScalar(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
        app:
          enabled: null
          description: ~
        """);

        assertEquals("true", values.get("app.enabled.__null_scalar__"));
        assertEquals("true", values.get("app.description.__null_scalar__"));
    }

    @Test
    @DisplayName("Should recognize onProfile in camelCase as profile activation")
    void shouldRecognizeOnProfileInCamelCaseAsProfileActivation(@TempDir Path tempDir) throws IOException {
        // Regression: before the fix, "onProfile" (camelCase) was not recognized
        // as spring.config.activate.on-profile, and the document silently became the base
        // instead of being treated as a profile overlay.
        List<ConfigDocument> documents = parseYaml(tempDir, "camel-case-test", """
            key: base-value
            ---
            spring:
              config:
                activate:
                  onProfile: prod
            key: prod-value
            """);

        ConfigDocument prodDocument = documents.stream()
                .filter(doc -> doc.profile().equals(Optional.of("prod")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Document with profile 'prod' was not recognized"));

        assertEquals("prod-value", prodDocument.properties().get("key"), "Should contain the 'key' key with the 'prod-value' value");
    }

    @Test
    @DisplayName("Should not leak the camelCase onProfile key as a business property")
    void shouldNotLeakCamelCaseOnProfileKeyAsBusinessProperty(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> documents = parseYaml(tempDir, "leak-test", """
            spring:
              config:
                activate:
                  onProfile: prod
            key: value
            """);

        ConfigDocument document = documents.getFirst();

        boolean hasOnProfileKey = document.properties().keySet().stream()
                .anyMatch(key -> RelaxedProperties.canonicalize(key)
                        .equals(RelaxedProperties.canonicalize("spring.config.activate.on-profile")));

        assertFalse(hasOnProfileKey, "The 'onProfile' key should not be present in the business property map");
    }

    @Test
    @DisplayName("Converts invalid YAML into YAMLException instead of crashing with a raw stack trace")
    void shouldConvertInvalidYamlToIOExceptionInsteadOfLeakingRuntimeException(@TempDir Path dir) throws IOException {
        // YAML alias referencing a non-existent anchor — snakeyaml throws
        // YAMLException (RuntimeException) when attempting to resolve it, not IOException.
        // Without the catch in loadYaml(), this would leak raw to Main.main(), breaking
        // the process with a stack trace instead of a controlled usage error.
        Files.writeString(dir.resolve("application.yml"), "key: *nonExistentAnchor\n");

        ConfigLoader loader = new ConfigLoader();

        assertThrows(IOException.class, () -> loader.loadDirectory(dir));
    }



    private Map<String, String> parse(Path tempDir, String yamlContent) throws IOException {
        Files.writeString(tempDir.resolve("application.yml"), yamlContent);
        List<ConfigFile> configFiles = new ConfigLoader().loadDirectory(tempDir);
        assertEquals(1, configFiles.size());
        return configFiles.getFirst().documents().getFirst().properties();
    }
    /**
     * Analogous to parse(), but for .properties and returning the complete
     * List<ConfigDocument> (not the flattened map of a single document) — necessary
     * because here we want to verify how many documents were produced and what each
     * one looks like, not just the final result of a single document.
    */
    private List<ConfigDocument> parseProperties(Path tempDir, String content) throws IOException {
        Path file = tempDir.resolve("application.properties");
        Files.writeString(file, content);
        List<ConfigFile> configFiles = new ConfigLoader().loadDirectory(tempDir);
        assertEquals(1, configFiles.size());
        return configFiles.getFirst().documents();
    }
    private List<ConfigDocument> parseYaml(Path tempDir, String subDirName, String yamlContent) throws IOException {
        Path subDir = tempDir.resolve(subDirName);
        Files.createDirectories(subDir);
        Files.writeString(subDir.resolve("application.yml"), yamlContent);
        List<ConfigFile> configFiles = new ConfigLoader().loadDirectory(subDir);
        assertEquals(1, configFiles.size());
        return configFiles.getFirst().documents();
    }

}