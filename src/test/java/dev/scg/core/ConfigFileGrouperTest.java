package dev.scg.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigFileGrouperTest {

    private final ConfigLoader loader = new ConfigLoader();
    private final ConfigFileGrouper grouper = new ConfigFileGrouper();

    @Test
    void deveAgruparApplicationYmlEApplicationProdYmlNoMesmoGrupo(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "*"
                """);
        Files.writeString(dir.resolve("application-prod.yml"), """
                spring:
                  h2:
                    console:
                      enabled: true
                """);

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));

        assertThat(groups).hasSize(1);
        assertThat(groups.get(0).mergedFile().documents()).hasSize(2);
    }

    @Test
    void deveDerivarProfileDoNomeDoArquivoIgnorandoOnProfileInterno(@TempDir Path dir) throws IOException {
        // Simula o cenário confirmado: on-profile dentro de um arquivo específico
        // é inválido no Spring real, mas nosso parser ainda consegue ler o YAML.
        // O nome do arquivo deve vencer, não o conteúdo.
        Files.writeString(dir.resolve("application.yml"), "server.port: 8080");
        Files.writeString(dir.resolve("application-staging.yml"), """
                spring:
                  config:
                    activate:
                      on-profile: outro-nome-qualquer
                custom.key: valor
                """);

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));
        ConfigFile merged = groups.get(0).mergedFile();

        boolean hasStagingLabel = merged.documents().stream()
                .anyMatch(doc -> doc.profile().equals(java.util.Optional.of("staging")));
        boolean hasOnProfileValueAsLabel = merged.documents().stream()
                .anyMatch(doc -> doc.profile().equals(java.util.Optional.of("outro-nome-qualquer")));

        assertThat(hasStagingLabel).isTrue();
        assertThat(hasOnProfileValueAsLabel).isFalse();
    }

    @Test
    void naoDeveAgruparArquivosDeDiretoriosDiferentes(@TempDir Path dir) throws IOException {
        Path moduleA = Files.createDirectories(dir.resolve("module-a"));
        Path moduleB = Files.createDirectories(dir.resolve("module-b"));

        Files.writeString(moduleA.resolve("application.yml"), "a.key: valorA");
        Files.writeString(moduleB.resolve("application.yml"), "b.key: valorB");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));

        assertThat(groups).hasSize(2); // um grupo por diretório, nunca misturados
    }

    @Test
    void deveRastrearArquivoFisicoCorretoParaCadaProfileLabel(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "base.key: valor");
        Files.writeString(dir.resolve("application-dev.yml"), "dev.key: valor");

        GroupedConfigFile group = grouper.group(loader.loadDirectory(dir)).get(0);

        assertThat(group.sourceByProfileLabel().get(ProfileMerger.BASE_PROFILE_LABEL))
                .isEqualTo(dir.resolve("application.yml"));
        assertThat(group.sourceByProfileLabel().get("dev"))
                .isEqualTo(dir.resolve("application-dev.yml"));
    }

    @Test
    void deveTratarApplicationComTracoSemSufixoComoBaseNaoComoProfileVazio(@TempDir Path dir) throws IOException {
        // Edge case defensivo, não confirmado contra Spring real: "application-.yml"
        // (traço sem nada depois) cai no branch de profile "malformado" —
        // tratado como base, não deve lançar exceção.
        Files.writeString(dir.resolve("application-.yml"), "key: valor");

        List<GroupedConfigFile> groups = grouper.group(loader.loadDirectory(dir));

        assertThat(groups).hasSize(1); // não deve lançar exceção
    }
}