package dev.scg;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs the built pipeline end-to-end against the committed config-server-showcase fixture with
 * --config-server, and pins the exact findings it's documented to produce -- same role as
 * {@link DemoProjectShowcaseTest} plays for the regular (non Config Server) fixtures.
 * <p>
 * Fixture shape mirrors a real Spring Cloud Config Server repository (confirmed against
 * spring-petclinic/spring-petclinic-microservices-config): application.yml is the Global config
 * (wildcard Actuator exposure + health show-details=ALWAYS, both inherited by every service and
 * profile), customers-service.yml adds its own mysql profile with an insecure DB transport and a
 * hardcoded credential, and vets-service.yml defines nothing of its own -- it exists purely to show
 * that a service which never mentions "docker" still gets that profile's EffectiveConfig, inherited
 * from Global, while it never gets "mysql" (customers-service's own profile, which must not leak
 * across services).
 */
class ConfigServerShowcaseTest {

    private static final String CONFIG_SERVER_DIR = "demo-project/config-server-showcase";

    @Test
    @DisplayName("config-server-showcase reports the 12 expected findings across 2 services x their profiles")
    void shouldReportExpectedFindingsAcrossServicesAndProfiles() {
        String output = run(new String[]{CONFIG_SERVER_DIR, "--config-server", "--fail-on=NONE"});

        assertTrue(output.contains("Summary: 12 violation(s)"));
        assertEquals(7, output.lines().filter(l -> l.startsWith("[HIGH]")).count());
        assertEquals(5, output.lines().filter(l -> l.startsWith("[MEDIUM]")).count());

        // Global-only findings (SCG001, SCG013) inherited by every profile of every service.
        assertTrue(hasFinding(output, "SCG001", "customers-service.yml", "[base]"));
        assertTrue(hasFinding(output, "SCG001", "customers-service.yml", "[profile: docker]"));
        assertTrue(hasFinding(output, "SCG001", "customers-service.yml", "[profile: mysql]"));
        assertTrue(hasFinding(output, "SCG001", "vets-service.yml", "[base]"));
        assertTrue(hasFinding(output, "SCG001", "vets-service.yml", "[profile: docker]"));
        assertTrue(hasFinding(output, "SCG013", "customers-service.yml", "[base]"));
        assertTrue(hasFinding(output, "SCG013", "vets-service.yml", "[profile: docker]"));

        // Service-only findings, scoped to customers-service's own "mysql" profile.
        assertTrue(hasFinding(output, "SCG012", "customers-service.yml", "[profile: mysql]"));
        assertTrue(hasFinding(output, "SCG006", "customers-service.yml", "[profile: mysql]"));

        // "mysql" must never leak into vets-service, which neither defines nor inherits it.
        assertTrue(output.lines().noneMatch(l -> l.contains("vets-service.yml") && l.contains("[profile: mysql]")));
    }

    private static boolean hasFinding(String output, String ruleId, String sourceFileName, String profileMarker) {
        return output.lines().anyMatch(l ->
                l.contains(ruleId) && l.contains(sourceFileName) && l.contains(profileMarker));
    }

    private static String run(String[] args) {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        try {
            System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));
            Main.run(args);
        } finally {
            System.setOut(originalOut);
        }
        return outContent.toString(StandardCharsets.UTF_8);
    }
}
