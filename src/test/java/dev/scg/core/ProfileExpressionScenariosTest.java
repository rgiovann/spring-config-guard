package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the rows of VALIDATION.md, "Profile expressions in {@code on-profile}": each test runs the
 * pipeline (ConfigLoader, ConfigFileGrouper, ProfileMerger) over one fixture of
 * {@code spring-env-benchmark/profile-expressions/} and checks every configuration SCG builds
 * against what Spring Boot 4.1.1 resolved for the same active profiles: whether
 * {@code spring.h2.console.enabled} is on. The base is Spring's "no profile active" column.
 * Sets of several profiles are not configurations SCG builds; where a document applies only to
 * such a set, the test checks it is reported as not evaluated.
 */
class ProfileExpressionScenariosTest {

    private static final Path FIXTURES = Path.of("spring-env-benchmark/profile-expressions");
    private static final String BASE = ProfileMerger.BASE_PROFILE_LABEL;

    @Test
    @DisplayName("P1: '!a' applies with no profile active and to every profile but a")
    void p1() throws IOException {
        assertConsole("p1-not", Map.of(BASE, true, "a", false));
    }

    @Test
    @DisplayName("P2: 'a,b' applies to a and to b")
    void p2() throws IOException {
        assertConsole("p2-comma", Map.of(BASE, false, "a", true, "b", true));
    }

    @Test
    @DisplayName("P3: a YAML list [a, b] applies to a and to b, not to the base")
    void p3() throws IOException {
        assertConsole("p3-yaml-list", Map.of(BASE, true, "a", false, "b", false));
    }

    @Test
    @DisplayName("P4: 'a & b' applies only to a and b together, reported as not evaluated")
    void p4() throws IOException {
        assertConsole("p4-and", Map.of(BASE, false, "a", false, "b", false));
        assertThat(notEvaluated("p4-and")).isEqualTo(1);
    }

    @Test
    @DisplayName("P5: 'a | b' applies to a and to b")
    void p5() throws IOException {
        assertConsole("p5-or", Map.of(BASE, false, "a", true, "b", true));
    }

    @Test
    @DisplayName("P6: '(a & !b) | c' applies to a and to c, not to b")
    void p6() throws IOException {
        assertConsole("p6-parens", Map.of(BASE, false, "a", true, "b", false, "c", true));
    }

    @Test
    @DisplayName("P7: '!a, b' applies with no profile active and to b, not to a")
    void p7() throws IOException {
        assertConsole("p7-not-comma", Map.of(BASE, true, "a", false, "b", true));
    }

    @Test
    @DisplayName("P8: 'on-profile: default' belongs to the base, with no configuration named default")
    void p8() throws IOException {
        assertConsole("p8-default-block", Map.of(BASE, true));
    }

    @Test
    @DisplayName("P9: application-default.yml belongs to the base, with no configuration named default")
    void p9() throws IOException {
        assertConsole("p9-default-file", Map.of(BASE, true));
    }

    @Test
    @DisplayName("P10: a later base document overrides an earlier profile document")
    void p10() throws IOException {
        assertConsole("p10-document-order", Map.of(BASE, false, "a", false));
    }

    @Test
    @DisplayName("P11: application.properties overrides an on-profile block of application.yml")
    void p11() throws IOException {
        assertConsole("p11-file-precedence", Map.of(BASE, false, "a", false));
    }

    @Test
    @DisplayName("P12: on-profile '!b' inside application-x.yml applies to x, and nothing is left unevaluated")
    void p12() throws IOException {
        assertConsole("p12-profile-file-condition", Map.of(BASE, false, "x", true, "b", false));
        assertThat(notEvaluated("p12-profile-file-condition")).isZero();
    }

    @Test
    @DisplayName("P13: 'a & b | c' is malformed, an input error as Spring refuses to start")
    void p13() {
        assertThatThrownBy(() -> new ConfigLoader().loadDirectory(FIXTURES.resolve("p13-malformed")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Malformed profile expression [a & b | c]");
    }

    @Test
    @DisplayName("P14: spaces around list items are ignored")
    void p14() throws IOException {
        assertConsole("p14-spaces", Map.of(BASE, false, "a", true, "b", true));
    }

    private static void assertConsole(String fixture, Map<String, Boolean> expected) throws IOException {
        Map<String, Boolean> actual = merge(fixture).stream().collect(Collectors.toMap(
                EffectiveConfig::profileLabel,
                config -> "true".equalsIgnoreCase(RelaxedProperties.get(config.properties(), "spring.h2.console.enabled")),
                (first, second) -> {
                    throw new AssertionError("duplicate profile label");
                },
                TreeMap::new));
        assertThat(actual).isEqualTo(new TreeMap<>(expected));
    }

    private static List<EffectiveConfig> merge(String fixture) throws IOException {
        List<GroupedConfigFile> groups = groups(fixture);
        assertThat(groups).hasSize(1);
        return new ProfileMerger().merge(groups.getFirst());
    }

    private static int notEvaluated(String fixture) throws IOException {
        return new ProfileMerger().documentsNotEvaluated(groups(fixture).getFirst()).size();
    }

    private static List<GroupedConfigFile> groups(String fixture) throws IOException {
        return new ConfigFileGrouper().group(new ConfigLoader().loadDirectory(FIXTURES.resolve(fixture)));
    }
}
