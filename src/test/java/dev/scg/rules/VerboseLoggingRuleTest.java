package dev.scg.rules;

import dev.scg.core.ConfigLoader;
import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Row IDs (L1, Y3, N9, ...) are the rows of VALIDATION.md, "SCG009 verbose logging scenarios",
 * measured in spring-env-benchmark/verbose-logging.
 */
class VerboseLoggingRuleTest {

    private final VerboseLoggingRule rule = new VerboseLoggingRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");

    private List<Finding> check(Map<String, String> properties) {
        return rule.check(new EffectiveConfig(FAKE_PATH, "prod", properties));
    }

    @Nested
    @DisplayName("debug and trace switches")
    class Switches {

        @ParameterizedTest
        @ValueSource(strings = {"debug", "trace"})
        @DisplayName("L0, L2, P4: silent when absent or exactly 'false'")
        void silentWhenAbsentOrFalse(String key) {
            assertThat(check(Map.of())).isEmpty();
            assertThat(check(Map.of(key, "false"))).isEmpty();
            assertThat(check(Map.of(key, "${UNSET_VAR:false}"))).isEmpty();
        }

        @ParameterizedTest
        @ValueSource(strings = {"true", "yes", "on", "1", "FALSE", "False", "off", "no", "0", "", "false ", "${UNSET_VAR:}", "${UNSET_VAR:off}"})
        @DisplayName("L1, L3-L7, P2, P3: debug is MEDIUM for any value but exactly 'false', as Spring Boot's isSet() reads it")
        void debugOnForAnyValueButFalse(String value) {
            List<Finding> findings = check(Map.of("debug", value));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
            assertThat(findings.getFirst().ruleId()).isEqualTo("SCG009");
            assertThat(findings.getFirst().message())
                    .contains("'debug=" + value + "'")
                    .contains("request query strings and request and response bodies")
                    .contains("any value except exactly 'false'");
        }

        @ParameterizedTest
        @ValueSource(strings = {"true", "off", "FALSE", ""})
        @DisplayName("L8, L9: trace is MEDIUM for any value but exactly 'false', and names the bound parameters it writes")
        void traceOnForAnyValueButFalse(String value) {
            List<Finding> findings = check(Map.of("trace", value));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
            assertThat(findings.getFirst().message()).contains("JdbcTemplate's bound parameter values");
        }

        @Test
        @DisplayName("P1: an upper-case key is the same property, quoted as written")
        void upperCaseKey() {
            List<Finding> findings = check(Map.of("DEBUG", "true"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().message()).contains("'DEBUG=true'");
        }

        @Test
        @DisplayName("a key present with a null value (a profile overriding it with null) is on: Spring Boot reads it as empty")
        void explicitNullIsOn() {
            Map<String, String> properties = new HashMap<>();
            properties.put("debug", null);

            List<Finding> findings = check(properties);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
            assertThat(findings.getFirst().message()).contains("'debug='");
        }

        @Test
        @DisplayName("Should report INFO severity when 'debug' contains an unresolved placeholder")
        void unresolvedPlaceholderIsInfo() {
            List<Finding> findings = check(Map.of("debug", "${DEBUG_ENABLED}"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
            assertThat(findings.getFirst().message()).contains("unresolved environment placeholder '${DEBUG_ENABLED}'");
        }
    }

    @Nested
    @DisplayName("Values YAML parses itself, loaded through ConfigLoader and ProfileMerger")
    class YamlValues {

        private List<Finding> checkYaml(Path dir, String yaml) throws IOException {
            Files.writeString(dir.resolve("application.yml"), yaml);
            return new ConfigLoader().loadDirectory(dir).stream()
                    .flatMap(file -> new ProfileMerger().merge(file).stream())
                    .flatMap(config -> rule.check(config).stream())
                    .toList();
        }

        @ParameterizedTest
        @ValueSource(strings = {"off", "no", "false"})
        @DisplayName("Y1, Y2: unquoted off and no are YAML booleans, loaded as 'false', so debug stays off")
        void unquotedYamlFalseIsOff(String value, @TempDir Path dir) throws IOException {
            assertThat(checkYaml(dir, "debug: " + value + "\n")).isEmpty();
        }

        @ParameterizedTest
        @ValueSource(strings = {"debug:\n", "debug: ~\n"})
        @DisplayName("Y4, Y5: a null debug in a base file stays silent: ProfileMerger drops the key, though Spring Boot turns it on (BACKLOG.md)")
        void baseFileNullIsNotSeen(String yaml, @TempDir Path dir) throws IOException {
            assertThat(checkYaml(dir, yaml)).isEmpty();
        }

        @Test
        @DisplayName("Y3: a quoted \"off\" is the string off, which turns debug on")
        void quotedOffIsOn(@TempDir Path dir) throws IOException {
            List<Finding> findings = checkYaml(dir, "debug: \"off\"\n");

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("a profile overriding debug with null turns it on, as Spring Boot reads null as empty")
        void profileNullIsOn(@TempDir Path dir) throws IOException {
            List<Finding> findings = checkYaml(dir, """
                    debug: false
                    ---
                    spring.config.activate.on-profile: prod
                    debug:
                    """);

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().profileLabel()).isEqualTo("prod");
        }
    }

    @Nested
    @DisplayName("logging.level.root")
    class RootLogger {

        @ParameterizedTest
        @CsvSource({
                "DEBUG, outbound Authorization headers",
                "debug, outbound Authorization headers",
                "TRACE, inbound and outbound Authorization headers"
        })
        @DisplayName("R1-R3: root at DEBUG or TRACE is MEDIUM and names what that level writes")
        void rootDebugOrTraceIsMedium(String level, String writes) {
            List<Finding> findings = check(Map.of("logging.level.root", level));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
            assertThat(findings.getFirst().message())
                    .contains("Root logger level set to '" + level.toUpperCase() + "'")
                    .contains(writes);
        }

        @ParameterizedTest
        @ValueSource(strings = {"INFO", "WARN", "ERROR", "OFF", "ALL", "true", "banana", "${LOG_LEVEL:INFO}"})
        @DisplayName("R4-R6: silent for other levels, and for values the app can't start with (ALL, true)")
        void silentForOtherLevels(String level) {
            assertThat(check(Map.of("logging.level.root", level))).isEmpty();
        }

        @Test
        @DisplayName("Should respect relaxed binding conventions for logging properties")
        void relaxedBinding() {
            // "logging.level.root" has no compound-word segment, so only case-folding across segments
            // is a relaxed-binding dimension for it. A key like "logging_level_root" would NOT match:
            // RelaxedProperties.canonicalize() strips '-'/'_' within a segment but doesn't turn '_' into
            // '.', which is the OS-env-var rule, out of scope since ConfigLoader only reads files.
            List<Finding> findings = check(Map.of("LOGGING.LEVEL.ROOT", "DEBUG"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("Should report INFO severity when the level relies on an unresolved placeholder")
        void unresolvedPlaceholderIsInfo() {
            List<Finding> findings = check(Map.of("logging.level.root", "${LOG_LEVEL}"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }
    }

    @Nested
    @DisplayName("Levels on other loggers")
    class OtherLoggers {

        @ParameterizedTest
        @CsvSource({
                "logging.level.web, debug, request query strings",
                "logging.level.org.springframework.web, debug, request query strings",
                "logging.level.org.springframework, debug, request query strings",
                "logging.level.org, debug, outbound HTTP headers",
                "logging.level.org.springframework, trace, JdbcTemplate's bound parameter values",
                "logging.level.sql, trace, JdbcTemplate's bound parameter values",
                "logging.level.org.springframework.jdbc.core, trace, JdbcTemplate's bound parameter values",
                "logging.level.org.hibernate.orm.jdbc.bind, trace, Hibernate's bound parameter values",
                "logging.level.org.hibernate, trace, Hibernate's bound parameter values",
                "logging.level.org.apache.hc.client5.http.wire, debug, outbound HTTP headers",
                "logging.level.org.apache.hc, debug, outbound HTTP headers"
        })
        @DisplayName("N1, N3-N13: a logger measured to write secrets, an ancestor of one, or a group containing one is MEDIUM")
        void secretLoggerIsMedium(String key, String level, String writes) {
            List<Finding> findings = check(Map.of(key, level));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
            assertThat(findings.getFirst().message()).contains(writes).contains("'" + key + "'");
        }

        @Test
        @DisplayName("N6: log-request-details added no secret to web=debug's, so only the level is reported")
        void logRequestDetailsAddsNothing() {
            List<Finding> findings = check(Map.of(
                    "spring.mvc.log-request-details", "true",
                    "logging.level.web", "debug"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("N9: an ancestor names everything its descendants write at that level")
        void ancestorNamesEveryDescendant() {
            String message = check(Map.of("logging.level.org", "trace")).getFirst().message();

            assertThat(message)
                    .contains("request query strings")
                    .contains("JdbcTemplate's bound parameter values")
                    .contains("Hibernate's bound parameter values")
                    .contains("outbound HTTP headers")
                    .contains("raw inbound requests");
        }

        @ParameterizedTest
        @CsvSource({
                "org.springframework.web.servlet.DispatcherServlet, debug, request query strings",
                "org.springframework.web.servlet.mvc.method.annotation.RequestResponseBodyMethodProcessor, debug, request and response bodies",
                "org.springframework.web.client.DefaultRestClient, debug, outbound request bodies",
                "org.springframework.web.method.HandlerMethod, trace, controller method arguments",
                "org.springframework.jdbc.core.StatementCreatorUtils, trace, JdbcTemplate's bound parameter values",
                "org.hibernate.orm.resource.registry, trace, Hibernate's bound parameter values",
                "org.apache.hc.client5.http.headers, debug, outbound HTTP headers, Authorization included",
                "org.apache.coyote.http11.Http11InputBuffer, trace, raw inbound requests"
        })
        @DisplayName("N15-N21, N23: each logger that wrote a secret, set alone to its level, is MEDIUM")
        void eachSecretLoggerIsMedium(String logger, String level, String writes) {
            List<Finding> findings = check(Map.of("logging.level." + logger, level));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
            assertThat(findings.getFirst().message()).contains(writes);
        }

        @ParameterizedTest
        @ValueSource(strings = {"org.apache.coyote.http11.Http11InputBuffer", "org.apache.tomcat.util.http.Parameters"})
        @DisplayName("N22, N24: Tomcat's loggers at debug wrote no secret, so they are INFO like any unknown logger")
        void tomcatAtDebugIsInfo(String logger) {
            List<Finding> findings = check(Map.of("logging.level." + logger, "debug"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }

        @Test
        @DisplayName("N25: a more specific logger with its own lower level decides for its descendants, so the ancestor is INFO")
        void moreSpecificLevelDecides() {
            List<Finding> findings = check(Map.of(
                    "logging.level.org", "debug",
                    "logging.level.org.springframework.web", "info",
                    "logging.level.org.apache.hc", "info"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }

        @Test
        @DisplayName("N25: a more specific logger decides only for its own descendants, not for the ancestor's others")
        void moreSpecificLevelDecidesOnlyBelowIt() {
            List<Finding> findings = check(Map.of(
                    "logging.level.org", "debug",
                    "logging.level.org.apache.hc", "info"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().message()).contains("request query strings").doesNotContain("outbound HTTP headers");
        }

        @Test
        @DisplayName("a group member's own level decides too: web at info under org.springframework at debug")
        void groupMemberLevelDecides() {
            List<Finding> findings = check(Map.of(
                    "logging.level.org.springframework", "debug",
                    "logging.level.web", "info"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }

        @Test
        @DisplayName("N26: logger names are case-sensitive, so ORG.SPRINGFRAMEWORK.WEB is an unknown logger: INFO")
        void loggerNamesAreCaseSensitive() {
            List<Finding> findings = check(Map.of("logging.level.ORG.SPRINGFRAMEWORK.WEB", "debug"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }

        @ParameterizedTest
        @CsvSource({
                "logging.level.sql, debug",
                "logging.level.org.springframework.jdbc.core, debug",
                "logging.level.org.hibernate.orm.jdbc.bind, debug",
                "logging.level.com.acme.billing, DEBUG",
                "logging.level.org.thymeleaf, trace",
                "logging.level.my-group, debug"
        })
        @DisplayName("N2: any other logger at DEBUG/TRACE is INFO: what it writes can't be known statically")
        void otherLoggerIsInfo(String key, String level) {
            List<Finding> findings = check(Map.of(key, level));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }

        @ParameterizedTest
        @ValueSource(strings = {"INFO", "WARN", "OFF", "${LEVEL:INFO}"})
        @DisplayName("N14: silent below DEBUG")
        void silentBelowDebug(String level) {
            assertThat(check(Map.of("logging.level.org.apache.hc", level))).isEmpty();
        }

        @Test
        @DisplayName("the message names the logger as written, not in its canonical form")
        void namesLoggerAsWritten() {
            assertThat(check(Map.of("logging.level.org.hibernate.SQL", "debug")).getFirst().message())
                    .contains("Logger 'org.hibernate.SQL' set to DEBUG");
        }

        @Test
        @DisplayName("an unresolved placeholder on a logger is INFO")
        void unresolvedPlaceholderIsInfo() {
            List<Finding> findings = check(Map.of("logging.level.org.springframework.web", "${WEB_LEVEL}"));

            assertThat(findings).hasSize(1);
            assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "staging", "prod"})
    @DisplayName("Should check rules regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of("debug", "true"));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should not throw and stay silent when the level values are null")
    void shouldNotThrowWhenLevelsAreNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put("logging.level.root", null);
        properties.put("logging.level.org.springframework.web", null);

        assertThat(check(properties)).isEmpty();
    }

    @Test
    @DisplayName("Should report independent findings when debug, trace, the root and another logger are all risky")
    void shouldReportIndependentFindingsForEachTrigger() {
        List<Finding> findings = check(Map.of(
                "debug", "true",
                "trace", "true",
                "logging.level.root", "DEBUG",
                "logging.level.web", "DEBUG"
        ));

        assertThat(findings).hasSize(4);
        assertThat(findings).allMatch(f -> f.severity() == Severity.MEDIUM && f.ruleId().equals("SCG009"));
    }
}
