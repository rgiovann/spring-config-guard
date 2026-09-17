package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigServerAssemblerTest {

    private final ConfigServerAssembler assembler = new ConfigServerAssembler();

    @Test
    @DisplayName("Should produce one base EffectiveConfig per non-application file, keyed by filename")
    void shouldProduceOneBaseEffectiveConfigPerService(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "server.port: 8080");
        Files.writeString(dir.resolve("customers-service.yml"), "spring.application.name: customers-service");
        Files.writeString(dir.resolve("api-gateway.yml"), "spring.application.name: api-gateway");

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(result).hasSize(2);
        assertThat(result).extracting(EffectiveConfig::profileLabel)
                .containsOnly(ProfileMerger.BASE_PROFILE_LABEL);
        assertThat(result).extracting(config -> config.sourceFile().getFileName().toString())
                .containsExactlyInAnyOrder("customers-service.yml", "api-gateway.yml");
    }

    @Test
    @DisplayName("Should merge Global base with Service base, Service overriding on conflict")
    void shouldMergeGlobalBaseWithServiceBaseServiceOverriding(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                management.endpoints.web.exposure.include: "*"
                server.port: 8080
                """);
        Files.writeString(dir.resolve("customers-service.yml"), "server.port: 8081");

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(result).hasSize(1);
        var properties = result.getFirst().properties();
        assertThat(properties).containsEntry("server.port", "8081"); // service wins
        assertThat(properties).containsEntry("management.endpoints.web.exposure.include", "*"); // inherited
    }

    @Test
    @DisplayName("Should work with no application.yml at all: Global base is simply empty")
    void shouldWorkWithNoGlobalFile(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("customers-service.yml"), "spring.h2.console.enabled: true");

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(result).hasSize(1);
        assertThat(result.getFirst().properties()).containsEntry("spring.h2.console.enabled", "true");
    }

    @Test
    @DisplayName("Should not recurse into subdirectories")
    void shouldNotRecurseIntoSubdirectories(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("customers-service.yml"), "server.port: 8081");
        Path nested = dir.resolve("nested");
        Files.createDirectory(nested);
        Files.writeString(nested.resolve("vets-service.yml"), "server.port: 8082");

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(result).hasSize(1);
        assertThat(result.getFirst().sourceFile().getFileName().toString()).isEqualTo("customers-service.yml");
    }

    @Test
    @DisplayName("Should pick up .properties service files, not just .yml")
    void shouldPickUpPropertiesServiceFiles(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("customers-service.properties"), "server.port=8081");

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(result).hasSize(1);
        assertThat(result.getFirst().properties()).containsEntry("server.port", "8081");
    }

    @Test
    @DisplayName("Should return an empty list for a directory with only an application.yml (no services)")
    void shouldReturnEmptyListWhenNoServiceFilesExist(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "server.port: 8080");

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(result).isEmpty();
    }
}
