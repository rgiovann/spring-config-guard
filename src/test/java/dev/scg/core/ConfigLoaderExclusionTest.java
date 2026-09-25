package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for the directories ConfigLoader.loadDirectory() skips during its recursive walk: build
 * output next to a Maven/Gradle build file, and src/test source sets. Kept separate from
 * ConfigLoaderTest, which covers parsing rather than file discovery.
 */
class ConfigLoaderExclusionTest {

    private static final String CONFIG = "spring:\n  h2:\n    console:\n      enabled: true\n";

    private static void write(Path file, String content) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }

    private static Set<Path> scannedFiles(Path root) throws IOException {
        return new ConfigLoader().loadDirectory(root).stream()
                .map(configFile -> root.relativize(configFile.path()))
                .collect(Collectors.toSet());
    }

    @Test
    @DisplayName("Skips target/ next to a pom.xml, keeping src/main/resources")
    void skipsMavenBuildOutput(@TempDir Path root) throws IOException {
        write(root.resolve("pom.xml"), "<project/>");
        write(root.resolve("src/main/resources/application.yml"), CONFIG);
        write(root.resolve("target/classes/application.yml"), CONFIG);
        write(root.resolve("target/test-classes/application.yml"), CONFIG);

        assertEquals(Set.of(Path.of("src/main/resources/application.yml")), scannedFiles(root));
    }

    @Test
    @DisplayName("Skips build/ next to a build.gradle or build.gradle.kts")
    void skipsGradleBuildOutput(@TempDir Path root) throws IOException {
        write(root.resolve("groovy/build.gradle"), "");
        write(root.resolve("groovy/src/main/resources/application.yml"), CONFIG);
        write(root.resolve("groovy/build/resources/main/application.yml"), CONFIG);
        write(root.resolve("kotlin/build.gradle.kts"), "");
        write(root.resolve("kotlin/src/main/resources/application.yml"), CONFIG);
        write(root.resolve("kotlin/build/resources/main/application.yml"), CONFIG);

        assertEquals(Set.of(
                Path.of("groovy/src/main/resources/application.yml"),
                Path.of("kotlin/src/main/resources/application.yml")
        ), scannedFiles(root));
    }

    @Test
    @DisplayName("Keeps a target/ or build/ directory that has no build file next to it")
    void keepsTargetAndBuildWithoutBuildFile(@TempDir Path root) throws IOException {
        write(root.resolve("target/application.yml"), CONFIG);
        write(root.resolve("build/application.yml"), CONFIG);

        assertEquals(Set.of(Path.of("target/application.yml"), Path.of("build/application.yml")),
                scannedFiles(root));
    }

    @Test
    @DisplayName("Skips build output per module in a multi-module project")
    void skipsBuildOutputPerModule(@TempDir Path root) throws IOException {
        write(root.resolve("pom.xml"), "<project/>");
        write(root.resolve("module-a/pom.xml"), "<project/>");
        write(root.resolve("module-a/src/main/resources/application.yml"), CONFIG);
        write(root.resolve("module-a/target/classes/application.yml"), CONFIG);

        assertEquals(Set.of(Path.of("module-a/src/main/resources/application.yml")), scannedFiles(root));
    }

    @Test
    @DisplayName("Skips src/test/, keeping src/main/")
    void skipsTestSourceSet(@TempDir Path root) throws IOException {
        write(root.resolve("src/main/resources/application.yml"), CONFIG);
        write(root.resolve("src/test/resources/application.yml"), CONFIG);
        write(root.resolve("src/test/resources/application-it.properties"), "a=b\n");

        assertEquals(Set.of(Path.of("src/main/resources/application.yml")), scannedFiles(root));
    }

    @Test
    @DisplayName("Keeps a directory named test that isn't directly under src/")
    void keepsTestDirectoryOutsideSrc(@TempDir Path root) throws IOException {
        write(root.resolve("config/test/application.yml"), CONFIG);
        write(root.resolve("src/main/resources/test/application.yml"), CONFIG);

        assertEquals(Set.of(
                Path.of("config/test/application.yml"),
                Path.of("src/main/resources/test/application.yml")
        ), scannedFiles(root));
    }

    @Test
    @DisplayName("Still scans an excluded directory when it is passed directly as the scan root")
    void scansExcludedDirectoryPassedAsRoot(@TempDir Path root) throws IOException {
        write(root.resolve("pom.xml"), "<project/>");
        write(root.resolve("src/test/resources/application.yml"), CONFIG);
        write(root.resolve("target/classes/application.yml"), CONFIG);

        Path testResources = root.resolve("src/test/resources");
        Path targetClasses = root.resolve("target/classes");
        List<ConfigFile> fromTestResources = new ConfigLoader().loadDirectory(testResources);
        List<ConfigFile> fromTargetClasses = new ConfigLoader().loadDirectory(targetClasses);

        assertEquals(1, fromTestResources.size());
        assertEquals(1, fromTargetClasses.size());
    }

    @Test
    @DisplayName("Skips src/test/ even when the scan root is src itself")
    void skipsTestWhenRootIsSrc(@TempDir Path root) throws IOException {
        write(root.resolve("src/main/resources/application.yml"), CONFIG);
        write(root.resolve("src/test/resources/application.yml"), CONFIG);

        Path src = root.resolve("src");
        assertEquals(Set.of(Path.of("main/resources/application.yml")), scannedFiles(src));
    }
}
