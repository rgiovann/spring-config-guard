package dev.scg.cli;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests how Version reads a pom.properties resource, using fixtures under
 * src/test/resources/version-fixtures instead of the real file, which only exists inside a
 * packaged jar.
 */
class VersionTest {

    @Test
    @DisplayName("Reads the version property from a pom.properties resource")
    void readsVersionProperty() {
        assertEquals(Optional.of("9.8.7"), Version.fromResource("/version-fixtures/with-version.properties"));
    }

    @Test
    @DisplayName("Treats a blank version property as unknown")
    void treatsBlankVersionAsUnknown() {
        assertEquals(Optional.empty(), Version.fromResource("/version-fixtures/blank-version.properties"));
    }

    @Test
    @DisplayName("Treats a missing resource as unknown")
    void treatsMissingResourceAsUnknown() {
        assertEquals(Optional.empty(), Version.fromResource("/version-fixtures/does-not-exist.properties"));
    }

    @Test
    @DisplayName("Is unknown when running from target/classes, where Maven's pom.properties doesn't exist")
    void isUnknownOutsidePackagedJar() {
        assertEquals(Optional.empty(), Version.current());
    }
}
