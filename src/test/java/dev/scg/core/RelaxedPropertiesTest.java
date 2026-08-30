package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;


class RelaxedPropertiesTest {

    @Test
    @DisplayName("Canonicalize should remove hyphens and underscores and convert to lowercase")
    void canonicalizeShouldRemoveHyphensAndUnderscoresAndConvertToLowercase() {
        assertThat(RelaxedProperties.canonicalize("spring.jpa.database-platform"))
                .isEqualTo(RelaxedProperties.canonicalize("spring.jpa.databasePlatform"))
                .isEqualTo(RelaxedProperties.canonicalize("spring.JPA.database_platform"));
    }

    @Test
    @DisplayName("Canonicalize should preserve dots as structural separators")
    void canonicalizeShouldPreserveDotsAsStructuralSeparators() {
        assertThat(RelaxedProperties.canonicalize("a.b.c")).isEqualTo("a.b.c");
    }

    @Test
    @DisplayName("Get should find the value regardless of writing style")
    void getShouldFindValueRegardlessOfWritingStyle() {
        Map<String, String> properties = Map.of("spring.h2.console.settings.webAllowOthers", "true");

        assertThat(RelaxedProperties.get(properties, "spring.h2.console.settings.web-allow-others"))
                .isEqualTo("true");
    }

    @Test
    @DisplayName("Get should return null when the key does not exist")
    void getShouldReturnNullWhenKeyDoesNotExist() {
        assertThat(RelaxedProperties.get(Map.of("outra.chave", "x"), "spring.h2.console.enabled"))
                .isNull();
    }

    @Test
    @DisplayName("ValuesForKeyOrListChildren should include scalar and indexed forms")
    void valuesForKeyOrListChildrenShouldIncludeScalarAndIndexedForms() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put("management.endpoints.web.exposure.include[0]", "health");
        properties.put("management.endpoints.web.exposure.include[1]", "*");

        assertThat(RelaxedProperties.valuesForKeyOrListChildren(properties,
                "management.endpoints.web.exposure.include"))
                .containsExactlyInAnyOrder("health", "*");
    }

    @Test
    @DisplayName("FindActualKey should return the actual key, not the searched literal")
    void findActualKeyShouldReturnActualKeyNotSearchedLiteral() {
        Map<String, String> properties = Map.of("spring.config.activate.onProfile", "prod");

        Optional<String> actualKey = RelaxedProperties.findActualKey(properties,
                "spring.config.activate.on-profile");

        assertThat(actualKey).contains("spring.config.activate.onProfile");
    }

    @Test
    @DisplayName("FindActualKey should return empty when the key does not exist")
    void findActualKeyShouldReturnEmptyWhenKeyDoesNotExist() {
        assertThat(RelaxedProperties.findActualKey(Map.of(), "qualquer.chave")).isEmpty();
    }
}

