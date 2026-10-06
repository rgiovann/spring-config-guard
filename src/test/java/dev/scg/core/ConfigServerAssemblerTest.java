package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

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

    @Test
    @DisplayName("Should apply a Global-only profile to a service that doesn't redefine it")
    void shouldApplyGlobalOnlyProfileToService(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                server.port: 8080
                ---
                spring.config.activate.on-profile: docker
                eureka.client.serviceUrl.defaultZone: http://discovery-server:8761/eureka/
                """);
        Files.writeString(dir.resolve("customers-service.yml"), "spring.application.name: customers-service");

        List<EffectiveConfig> result = assembler.assemble(dir);

        var docker = findByProfile(result, "docker");
        assertThat(docker.properties())
                .containsEntry("eureka.client.serviceUrl.defaultZone", "http://discovery-server:8761/eureka/")
                .containsEntry("spring.application.name", "customers-service"); // service base still applies
    }

    @Test
    @DisplayName("Should apply a Service-only profile on top of the Global and Service bases")
    void shouldApplyServiceOnlyProfileOverBothBases(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), "server.port: 8080");
        Files.writeString(dir.resolve("customers-service.yml"), """
                server.port: 8081
                ---
                spring.config.activate.on-profile: mysql
                spring.datasource.url: jdbc:mysql://localhost/petclinic
                """);

        List<EffectiveConfig> result = assembler.assemble(dir);

        var mysql = findByProfile(result, "mysql");
        assertThat(mysql.properties())
                .containsEntry("spring.datasource.url", "jdbc:mysql://localhost/petclinic")
                .containsEntry("server.port", "8081"); // service base, not global base
    }

    @Test
    @DisplayName("Should apply cascade precedence Global-base < Global-profile < Service-base < Service-profile")
    void shouldRespectFullCascadePrecedence(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                key: global-base
                ---
                spring.config.activate.on-profile: mysql
                key: global-profile
                """);
        Files.writeString(dir.resolve("customers-service.yml"), """
                key: service-base
                ---
                spring.config.activate.on-profile: mysql
                key: service-profile
                """);

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(findByProfile(result, "mysql").properties()).containsEntry("key", "service-profile");
    }

    @Test
    @DisplayName("A profile only defined by one service must not leak into another service's EffectiveConfigs")
    void shouldNotLeakServiceOnlyProfileAcrossServices(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                key: base
                ---
                spring.config.activate.on-profile: docker
                key: docker
                """);
        Files.writeString(dir.resolve("customers-service.yml"), """
                spring.application.name: customers-service
                ---
                spring.config.activate.on-profile: mysql
                spring.datasource.url: jdbc:mysql://localhost/customers
                """);
        Files.writeString(dir.resolve("vets-service.yml"), "spring.application.name: vets-service");

        List<EffectiveConfig> result = assembler.assemble(dir);

        List<EffectiveConfig> customersConfigs = byService(result, "customers-service.yml");
        List<EffectiveConfig> vetsConfigs = byService(result, "vets-service.yml");

        assertThat(customersConfigs).extracting(EffectiveConfig::profileLabel)
                .containsExactlyInAnyOrder(ProfileMerger.BASE_PROFILE_LABEL, "docker", "mysql");
        assertThat(vetsConfigs).extracting(EffectiveConfig::profileLabel)
                .containsExactlyInAnyOrder(ProfileMerger.BASE_PROFILE_LABEL, "docker"); // no "mysql" here
    }

    @Test
    @DisplayName("P15: a Global application-dev.yml applies to dev only, over every document of the service file, and keeps application.yml")
    void globalProfileFileShouldApplyToItsProfileOverTheServiceFile(@TempDir Path dir) throws IOException {
        // Before ADR-012, every application* file was "the" Global file and the last one listed won:
        // application.yml was lost and application-dev.yml became every service's base.
        Files.writeString(dir.resolve("application.yml"), """
                k1: app-base
                k2: app-base
                k3: app-base
                ---
                spring.config.activate.on-profile: dev
                k1: app-block
                k2: app-block
                """);
        Files.writeString(dir.resolve("svc.yml"), """
                k1: svc-base
                k3: svc-base
                k4: svc-base
                ---
                spring.config.activate.on-profile: dev
                k4: svc-block
                """);
        Files.writeString(dir.resolve("application-dev.yml"), """
                k3: app-dev-file
                k4: app-dev-file
                """);

        List<EffectiveConfig> result = assembler.assemble(dir);

        // The values Spring Boot 4.1.1 resolved with spring.config.name=application,svc (VALIDATION.md, P15).
        assertThat(findByProfile(result, ProfileMerger.BASE_PROFILE_LABEL).properties()).isEqualTo(Map.of(
                "k1", "svc-base", "k2", "app-base", "k3", "svc-base", "k4", "svc-base"));
        assertThat(findByProfile(result, "dev").properties()).isEqualTo(Map.of(
                "k1", "svc-base", "k2", "app-block", "k3", "app-dev-file", "k4", "app-dev-file"));
        assertThat(result).extracting(EffectiveConfig::sourceFile).containsOnly(dir.resolve("svc.yml"));
    }

    @Test
    @DisplayName("A service written in two formats keeps both files, .properties winning a key conflict")
    void serviceInTwoFormatsShouldKeepBothFiles(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("svc.yml"), "from.yml: y1\nshared: from-yml\n");
        Files.writeString(dir.resolve("svc.properties"), "from.properties=p1\nshared=from-properties\n");

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(result).hasSize(1);
        assertThat(result.getFirst().properties()).isEqualTo(Map.of(
                "from.yml", "y1", "from.properties", "p1", "shared", "from-properties"));
        assertThat(result.getFirst().sourceFile()).isEqualTo(dir.resolve("svc.properties"));
    }

    @Test
    @DisplayName("P8 in Config Server Mode: a service's on-profile default document belongs to its base")
    void defaultDocumentInServiceShouldBelongToItsBase(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("svc.yml"), """
                k: base
                ---
                spring.config.activate.on-profile: default
                k: default-block
                ---
                spring.config.activate.on-profile: docker
                k: docker-block
                """);

        List<EffectiveConfig> result = assembler.assemble(dir);

        assertThat(result).extracting(EffectiveConfig::profileLabel)
                .containsExactly(ProfileMerger.BASE_PROFILE_LABEL, "docker");
        assertThat(findByProfile(result, ProfileMerger.BASE_PROFILE_LABEL).properties()).containsEntry("k", "default-block");
        assertThat(findByProfile(result, "docker").properties()).containsEntry("k", "docker-block");
    }

    private static EffectiveConfig findByProfile(List<EffectiveConfig> configs, String profileLabel) {
        return configs.stream()
                .filter(c -> c.profileLabel().equals(profileLabel))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No EffectiveConfig found for profile '" + profileLabel + "'"));
    }

    private static List<EffectiveConfig> byService(List<EffectiveConfig> configs, String fileName) {
        return configs.stream()
                .filter(c -> c.sourceFile().getFileName().toString().equals(fileName))
                .toList();
    }
}
