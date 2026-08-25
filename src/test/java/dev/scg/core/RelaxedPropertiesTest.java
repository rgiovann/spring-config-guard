package dev.scg.core;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class RelaxedPropertiesTest {

    @Test
    void canonicalizeDeveRemoverHifenESublinhadoEConverterParaMinusculas() {
        assertThat(RelaxedProperties.canonicalize("spring.jpa.database-platform"))
                .isEqualTo(RelaxedProperties.canonicalize("spring.jpa.databasePlatform"))
                .isEqualTo(RelaxedProperties.canonicalize("spring.JPA.database_platform"));
    }

    @Test
    void canonicalizeDevePreservarPontosComoSeparadorEstrutural() {
        assertThat(RelaxedProperties.canonicalize("a.b.c")).isEqualTo("a.b.c");
    }

    @Test
    void getDeveEncontrarValorIndependenteDoEstiloDeEscrita() {
        Map<String, String> properties = Map.of("spring.h2.console.settings.webAllowOthers", "true");

        assertThat(RelaxedProperties.get(properties, "spring.h2.console.settings.web-allow-others"))
                .isEqualTo("true");
    }

    @Test
    void getDeveRetornarNullQuandoChaveNaoExiste() {
        assertThat(RelaxedProperties.get(Map.of("outra.chave", "x"), "spring.h2.console.enabled"))
                .isNull();
    }

    @Test
    void valuesForKeyOrListChildrenDeveIncluirFormaEscalarEIndexada() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put("management.endpoints.web.exposure.include[0]", "health");
        properties.put("management.endpoints.web.exposure.include[1]", "*");

        assertThat(RelaxedProperties.valuesForKeyOrListChildren(properties,
                "management.endpoints.web.exposure.include"))
                .containsExactlyInAnyOrder("health", "*");
    }

    @Test
    void findActualKeyDeveRetornarAChaveRealNaoALiteralBuscada() {
        Map<String, String> properties = Map.of("spring.config.activate.onProfile", "prod");

        Optional<String> actualKey = RelaxedProperties.findActualKey(properties,
                "spring.config.activate.on-profile");

        assertThat(actualKey).contains("spring.config.activate.onProfile");
    }

    @Test
    void findActualKeyDeveRetornarVazioQuandoNaoExiste() {
        assertThat(RelaxedProperties.findActualKey(Map.of(), "qualquer.chave")).isEmpty();
    }
}