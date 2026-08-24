package dev.scg;

import dev.scg.cli.ExitCodeResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainSmokeTest {

    @Test
    @DisplayName("Deve executar análise E2E identificando violações do Actuator e H2 Console")
    void shouldDetectActuatorAndH2ConsoleViolationsEndToEnd(@TempDir Path tempDir) throws Exception {
        // 1. Arrange: Criação dos arquivos YAML reais no diretório temporário
        Path appYaml = tempDir.resolve("application.yml");
        String appYamlContent = """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "*"
                """;
        Files.writeString(appYaml, appYamlContent);

        Path appProdYaml = tempDir.resolve("application-prod.yml");
        String appProdYamlContent = """
                spring:
                  config:
                    activate:
                      on-profile: prod
                  h2:
                    console:
                      enabled: true
                      settings:
                        web-allow-others: true
                """;
        Files.writeString(appProdYaml, appProdYamlContent);

        // Captura da saída do console
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;

        int exitCode;
        try {
            //System.setOut(new PrintStream(outContent));
            System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));


            // 2. Act: Executa o fluxo completo do linter via CLI
            exitCode = Main.run(new String[]{tempDir.toString()});
        } finally {
            System.setOut(originalOut);
        }

        //String output = outContent.toString();
        String output = outContent.toString(StandardCharsets.UTF_8);

        //System.out.println("OUTPUT REAL:\n" + output);

        // 3. Assert: Valida código de saída e presença das violações esperadas
        assertEquals(ExitCodeResolver.THRESHOLD_EXCEEDED, exitCode, "O código de saída deve indicar violação do threshold");

        // Regra SCG001 - Actuator
        assertTrue(output.contains("SCG001"), "Deveria conter o ID da regra SCG001");
        assertTrue(output.contains("management.endpoints.web.exposure.include contém *"), "Deveria acusar a chave de exposição do Actuator");
        // Regra SCG002 - H2 Console
        assertTrue(output.contains("SCG002"), "Deveria conter o ID da regra SCG002");
        assertTrue(output.contains("H2 console habilitado"), "Deveria acusar o H2 console habilitado");
        assertTrue(output.contains("AGRAVANTE: spring.h2.console.settings.web-allow-others=true"), "Deveria indicar o agravante RCE");

        long scg001Count = output.lines().filter(line -> line.contains("SCG001")).count();
        assertTrue(scg001Count >= 2, "SCG001 deveria aparecer tanto no base quanto no profile prod (herança confirmada)");

        // Resumo de Violações
        //assertTrue(output.contains("Resumo: 2 violação(ões) — HIGH: 2, MEDIUM: 0, LOW: 0"), "O resumo deve contabilizar exatamente 2 violações HIGH");
        // Resumo de Violações
        assertTrue(output.contains("Resumo: 3 violação(ões) — HIGH: 3, MEDIUM: 0, LOW: 0"),
                "O resumo deve contabilizar exatamente 3 violações HIGH (Actuator no base, " +
                        "Actuator herdado em prod, H2 em prod)");
    }
}