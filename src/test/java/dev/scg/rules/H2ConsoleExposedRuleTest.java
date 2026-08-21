package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class H2ConsoleExposedRuleTest {

    private final H2ConsoleExposedRule rule = new H2ConsoleExposedRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    @Test
    @DisplayName("Deve gerar Finding de HIGH quando H2 console estiver habilitado no perfil base")
    void deveGerarFindingQuandoH2HabilitadoNoBase() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                ProfileMerger.BASE_PROFILE_LABEL,
                Map.of("spring.h2.console.enabled", "true")
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        Finding finding = findings.getFirst();
        assertEquals("SCG002", finding.ruleId());
        assertEquals(Severity.HIGH, finding.severity());
        assertTrue(finding.message().contains("spring.h2.console.enabled=true"));
    }

    @Test
    @DisplayName("Deve gerar Finding quando H2 console estiver habilitado em perfil de producao")
    void deveGerarFindingQuandoH2HabilitadoEmProd() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.h2.console.enabled", "TRUE")
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
    }

    @Test
    @DisplayName("Deve gerar Finding para variantes truthy do Spring Boot (yes, on, 1)")
    void deveGerarFindingParaVariantesTruthy() {
        List<String> truthyValues = List.of("yes", "YES", "on", "1");

        for (String value : truthyValues) {
            EffectiveConfig config = new EffectiveConfig(
                    FAKE_PATH,
                    "prod",
                    Map.of("spring.h2.console.enabled", value)
            );

            List<Finding> findings = rule.check(config);
            assertEquals(1, findings.size(), "Deveria ter gerado Finding para o valor truthy: " + value);
        }
    }

    @Test
    @DisplayName("NÃO deve gerar Finding quando H2 console estiver habilitado em perfil seguro (dev/test/local)")
    void naoDeveGerarFindingEmPerfilDevOuTest() {
        EffectiveConfig devConfig = new EffectiveConfig(
                FAKE_PATH,
                "dev",
                Map.of("spring.h2.console.enabled", "true")
        );

        EffectiveConfig testConfig = new EffectiveConfig(
                FAKE_PATH,
                "test",
                Map.of("spring.h2.console.enabled", "true")
        );

        assertTrue(rule.check(devConfig).isEmpty());
        assertTrue(rule.check(testConfig).isEmpty());
    }

    @Test
    @DisplayName("NÃO deve gerar Finding para perfis compostos seguros (dev-local, cloud-test, local_db)")
    void naoDeveGerarFindingParaPerfisCompostosSeguros() {
        List<String> safeCompositeProfiles = List.of("dev-local", "cloud-test", "local_db", "test.ci");

        for (String profile : safeCompositeProfiles) {
            EffectiveConfig config = new EffectiveConfig(
                    FAKE_PATH,
                    profile,
                    Map.of("spring.h2.console.enabled", "true")
            );

            assertTrue(rule.check(config).isEmpty(), "Deveria ser ignorado por ser um perfil composto seguro: " + profile);
        }
    }

    @Test
    @DisplayName("Deve gerar Finding para nomes de perfis que contêm palavras-chave como substring (delivery, devices)")
    void deveGerarFindingParaPerfisNaoSegurosComSubstringsSemelhantes() {
        List<String> unsafeProfiles = List.of("delivery", "devices", "contest");

        for (String profile : unsafeProfiles) {
            EffectiveConfig config = new EffectiveConfig(
                    FAKE_PATH,
                    profile,
                    Map.of("spring.h2.console.enabled", "true")
            );

            List<Finding> findings = rule.check(config);
            assertEquals(1, findings.size(), "Deveria ter gerado Finding para o perfil: " + profile);
        }
    }

    @Test
    @DisplayName("NÃO deve gerar Finding quando H2 console estiver desabilitado ou ausente")
    void naoDeveGerarFindingQuandoDesabilitadoOuAusente() {
        EffectiveConfig disabledConfig = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.h2.console.enabled", "false")
        );

        EffectiveConfig missingConfig = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("server.port", "8080")
        );

        assertTrue(rule.check(disabledConfig).isEmpty());
        assertTrue(rule.check(missingConfig).isEmpty());
    }

    @Test
    @DisplayName("NÃO deve lançar exceção nem gerar Finding quando valor da propriedade for nulo")
    void naoDeveLancarExcecaoQuandoPropriedadeForNula() {
        Map<String, String> properties = new HashMap<>();
        properties.put("spring.h2.console.enabled", null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        assertDoesNotThrow(() -> assertTrue(rule.check(config).isEmpty()));
    }

    @Test
    @DisplayName("Deve escalar a mensagem quando web-allow-others estiver habilitado junto com o console")
    void deveEscalarMensagemQuandoWebAllowOthersHabilitado() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.h2.console.enabled", "true",
                        "spring.h2.console.settings.web-allow-others", "true"
                )
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        Finding finding = findings.getFirst();
        assertEquals(Severity.HIGH, finding.severity()); // severidade não muda, só a mensagem
        assertTrue(finding.message().contains("AGRAVANTE"));
        assertTrue(finding.message().contains("spring.h2.console.settings.web-allow-others=true"));
    }

    @Test
    @DisplayName("NÃO deve escalar a mensagem quando web-allow-others estiver ausente")
    void naoDeveEscalarMensagemQuandoWebAllowOthersAusente() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of("spring.h2.console.enabled", "true")
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        assertFalse(findings.getFirst().message().contains("AGRAVANTE"));
    }

    @Test
    @DisplayName("NÃO deve escalar a mensagem quando web-allow-others estiver explicitamente false")
    void naoDeveEscalarMensagemQuandoWebAllowOthersFalse() {
        EffectiveConfig config = new EffectiveConfig(
                FAKE_PATH,
                "prod",
                Map.of(
                        "spring.h2.console.enabled", "true",
                        "spring.h2.console.settings.web-allow-others", "false"
                )
        );

        List<Finding> findings = rule.check(config);

        assertEquals(1, findings.size());
        assertFalse(findings.getFirst().message().contains("AGRAVANTE"));
    }

}