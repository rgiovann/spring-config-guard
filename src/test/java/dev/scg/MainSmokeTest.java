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
    @DisplayName("Deve executar análise E2E validando multi-documentos, herança/sobrescrita e mistura de YAML com Properties")
    void shouldRunE2EAnalysisWithComplexProfileScenarios(@TempDir Path tempDir) throws Exception {
        // 1. Arrange: YAML Base contendo multi-documento (---) com perfil dev seguro
        Path appYaml = tempDir.resolve("application.yml");
        String appYamlContent = """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "*"
                ---
                spring:
                  config:
                    activate:
                      on-profile: dev
                  h2:
                    console:
                      enabled: true
                """;
        Files.writeString(appYaml, appYamlContent);

        // 2. Arrange: YAML de Prod sobrescrevendo/corrigindo o Actuator herdado e ativando H2 arriscado
        Path appProdYaml = tempDir.resolve("application-prod.yml");
        String appProdYamlContent = """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "health,metrics"
                spring:
                  h2:
                    console:
                      enabled: true
                      settings:
                        web-allow-others: true
                """;
        Files.writeString(appProdYaml, appProdYamlContent);

        // 3. Arrange: Arquivo .properties clássico no perfil QA
        Path appQaProps = tempDir.resolve("application-qa.properties");
        String appQaPropsContent = """
                spring.h2.console.enabled=true
                """;
        Files.writeString(appQaProps, appQaPropsContent);

        // Captura da saída do console
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;

        int exitCode;
        try {
            System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));

            // Act: Executa a CLI
            exitCode = Main.run(new String[]{tempDir.toString()});
        } finally {
            System.setOut(originalOut);
        }

        String output = outContent.toString(StandardCharsets.UTF_8);

        // Assert: Validações do resultado
        assertEquals(ExitCodeResolver.THRESHOLD_EXCEEDED, exitCode, "Deve falhar devido às violações HIGH");

        // Regra SCG001 - Actuator: base, qa e dev herdam include="*" do base sem
        // redefinição própria (só prod sobrescreve para "health,metrics"). Decisão
        // deliberada (sessão de 21/08/2026): ActuatorExposureRule não isenta
        // profiles seguros, diferente de H2ConsoleExposedRule — natureza do
        // vazamento (segredos reais) e risco de credenciais compartilhadas entre
        // dev/staging justificam manter restrito sempre.
        assertTrue(output.contains("SCG001"), "Deveria acusar violação de Actuator");
        long scg001Count = output.lines().filter(line -> line.contains("SCG001")).count();
        assertEquals(3, scg001Count, "SCG001 deve aparecer em base, qa e dev (todos herdam include=* sem redefinir); prod é o único que corrige a propriedade");

        boolean devHasActuatorViolation = output.lines()
                .anyMatch(line -> line.contains("SCG001") && line.contains("[profile: dev]"));
        assertTrue(devHasActuatorViolation, "Actuator deve ser sinalizado mesmo em dev — decisão deliberada de não isentar por profile");

        boolean qaHasActuatorViolation = output.lines()
                .anyMatch(line -> line.contains("SCG001") && line.contains("[profile: qa]"));
        assertTrue(qaHasActuatorViolation, "Actuator herdado do base também deve ser sinalizado em qa");

        // Regra SCG002 - H2 Console em PROD (com agravante) e em QA (sem agravante)
        assertTrue(output.contains("SCG002"), "Deveria acusar violação de H2 Console");
        assertTrue(output.contains("[profile: prod]"), "Deveria acusar H2 em prod");
        assertTrue(output.contains("[profile: qa]"), "Deveria acusar H2 em qa");
        assertTrue(output.contains("AGRAVANTE: spring.h2.console.settings.web-allow-others=true"), "Deveria indicar o agravante RCE em prod");

        // Garante que o perfil DEV (definido via multi-documento ---) continua
        // isento de H2 (SafeProfileClassifier), mesmo não sendo mais isento de
        // Actuator — as duas regras têm políticas de profile diferentes por design.
        boolean devHasH2Violation = output.lines()
                .anyMatch(line -> line.contains("SCG002") && line.contains("[profile: dev]"));
        assertEquals(false, devHasH2Violation, "O perfil dev deve continuar isento de H2 console (regra específica do H2), mas não de Actuator");

        // Total de violações esperadas:
        // SCG001: base + qa + dev = 3
        // SCG002: prod (com agravante) + qa (sem agravante) = 2
        // Total = 5 violações HIGH
        assertTrue(output.contains("Resumo: 5 violação(ões) — HIGH: 5, MEDIUM: 0, LOW: 0"),
                "O resumo deve contabilizar exatamente 5 violações HIGH");
    }
}