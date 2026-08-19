package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
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
}