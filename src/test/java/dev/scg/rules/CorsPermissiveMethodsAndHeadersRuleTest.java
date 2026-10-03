// FILE: CorsPermissiveMethodsAndHeadersRuleTest.java
// PACKAGE: dev.scg.rules

package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CorsPermissiveMethodsAndHeadersRuleTest {

    private final CorsPermissiveMethodsAndHeadersRule rule = new CorsPermissiveMethodsAndHeadersRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    private static final String PREFIX = "management.endpoints.web.cors";
    private static final String ORIGINS = PREFIX + ".allowed-origins";
    private static final String ALLOWED_METHODS_KEY = PREFIX + ".allowed-methods";
    private static final String EXPOSED_HEADERS_KEY = PREFIX + ".exposed-headers";
    private static final String CREDENTIALS = PREFIX + ".allow-credentials";

    /** Properties with an origin configured, so Spring Boot builds the CORS configuration. */
    private static Map<String, String> cors(String key, String value, String credentials) {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(ORIGINS, "https://trusted.example");
        properties.put(key, value);
        if (credentials != null) {
            properties.put(CREDENTIALS, credentials);
        }
        return properties;
    }

    private List<Finding> check(Map<String, String> properties) {
        return rule.check(new EffectiveConfig(FAKE_PATH, "prod", properties));
    }

    private static List<Severity> severities(List<Finding> findings) {
        return findings.stream().map(Finding::severity).toList();
    }

    @ParameterizedTest
    @ValueSource(strings = {ALLOWED_METHODS_KEY, EXPOSED_HEADERS_KEY})
    @DisplayName("M1, H3: without an origin key Spring Boot builds no CORS configuration, so the rule is silent")
    void silentWithoutOrigins(String key) {
        assertThat(check(Map.of(key, "*", CREDENTIALS, "true"))).isEmpty();
        assertThat(check(Map.of(key, "${CORS_VALUE}"))).isEmpty();
    }

    @Test
    @DisplayName("An origin pattern also enables the configuration")
    void originPatternEnablesConfiguration() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(PREFIX + ".allowed-origin-patterns[0]", "https://*.trusted.example");
        properties.put(ALLOWED_METHODS_KEY, "*");
        properties.put(CREDENTIALS, "true");

        assertThat(severities(check(properties))).containsExactly(Severity.MEDIUM);
    }

    @Test
    @DisplayName("M2: allowed-methods=* with credentials is MEDIUM")
    void methodsWildcardWithCredentialsIsMedium() {
        List<Finding> findings = check(cors(ALLOWED_METHODS_KEY, "*", "true"));

        assertThat(severities(findings)).containsExactly(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains(ALLOWED_METHODS_KEY, CREDENTIALS, "allowed-headers");
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "${CORS_CREDENTIALS}"})
    @DisplayName("M7: allowed-methods=* without credentials, or with them unresolved, is LOW")
    void methodsWildcardWithoutCredentialsIsLow(String credentials) {
        assertThat(severities(check(cors(ALLOWED_METHODS_KEY, "*", credentials)))).containsExactly(Severity.LOW);
        assertThat(severities(check(cors(ALLOWED_METHODS_KEY, "*", null)))).containsExactly(Severity.LOW);
    }

    @Test
    @DisplayName("M4: an explicit list of methods is silent")
    void explicitMethodsAreSilent() {
        assertThat(check(cors(ALLOWED_METHODS_KEY, "GET, POST, PUT, DELETE", "true"))).isEmpty();
    }

    @Test
    @DisplayName("A wildcard method in a YAML list item is found")
    void methodsWildcardInListItem() {
        Map<String, String> properties = cors(ALLOWED_METHODS_KEY + "[0]", "GET", "true");
        properties.put(ALLOWED_METHODS_KEY + "[1]", "*");

        assertThat(severities(check(properties))).containsExactly(Severity.MEDIUM);
    }

    @Test
    @DisplayName("H1: exposed-headers=* with credentials is LOW: browsers ignore the wildcard for credentialed requests")
    void exposedWildcardWithCredentialsIsLowAndIneffective() {
        List<Finding> findings = check(cors(EXPOSED_HEADERS_KEY, "*", "true"));

        assertThat(severities(findings)).containsExactly(Severity.LOW);
        assertThat(findings.getFirst().message()).contains("exposes no header here");
    }

    @Test
    @DisplayName("exposed-headers=* without credentials is LOW: it exposes headers of anonymous responses")
    void exposedWildcardWithoutCredentialsIsLow() {
        List<Finding> findings = check(cors(EXPOSED_HEADERS_KEY, "*", null));

        assertThat(severities(findings)).containsExactly(Severity.LOW);
        assertThat(findings.getFirst().message()).contains("anonymous requests");
    }

    @ParameterizedTest
    @ValueSource(strings = {"X-Auth-Token", "Authorization", "x-auth-token", " \t authorization \t "})
    @DisplayName("H4: a token header exposed with credentials is MEDIUM, in any case and spacing")
    void tokenHeaderWithCredentialsIsMedium(String header) {
        List<Finding> findings = check(cors(EXPOSED_HEADERS_KEY, header, "true"));

        assertThat(severities(findings)).containsExactly(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains(header.strip());
    }

    @Test
    @DisplayName("H5: a token header exposed without credentials is LOW")
    void tokenHeaderWithoutCredentialsIsLow() {
        assertThat(severities(check(cors(EXPOSED_HEADERS_KEY, "X-Auth-Token", null)))).containsExactly(Severity.LOW);
    }

    @Test
    @DisplayName("H6: Set-Cookie is LOW (forbidden response header, never exposed) and Cookie is INFO (a request header)")
    void forbiddenAndRequestHeaders() {
        List<Finding> findings = check(cors(EXPOSED_HEADERS_KEY, "Set-Cookie, Set-Cookie2, Cookie", "true"));

        assertThat(severities(findings)).containsExactly(Severity.LOW, Severity.LOW, Severity.INFO);
    }

    @Test
    @DisplayName("Safe operational headers are silent")
    void safeHeadersAreSilent() {
        assertThat(check(cors(EXPOSED_HEADERS_KEY, "Content-Disposition, X-Total-Count", "true"))).isEmpty();
    }

    @Test
    @DisplayName("Wildcard and token header in the same value give one finding each")
    void wildcardAndTokenHeader() {
        assertThat(severities(check(cors(EXPOSED_HEADERS_KEY, "*, Authorization", "true"))))
                .containsExactly(Severity.LOW, Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {ALLOWED_METHODS_KEY, EXPOSED_HEADERS_KEY})
    @DisplayName("An unresolved placeholder is INFO when an origin is configured")
    void unresolvedPlaceholderIsInfo(String key) {
        List<Finding> findings = check(cors(key, "${CORS_VALUE}", "true"));

        assertThat(severities(findings)).containsExactly(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("${CORS_VALUE}");
    }

    @Test
    @DisplayName("A placeholder default is resolved and reported at its own severity")
    void placeholderDefaultIsResolved() {
        assertThat(severities(check(cors(EXPOSED_HEADERS_KEY, "${CORS_EXPOSED:Authorization}", "true"))))
                .containsExactly(Severity.MEDIUM);
    }

    @Test
    @DisplayName("G1: Spring for GraphQL's keys are read with their own credentials")
    void graphqlKeysAreRead() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put("spring.graphql.cors.allowed-origins", "https://trusted.example");
        properties.put("spring.graphql.cors.allowed-methods", "*");
        properties.put("spring.graphql.cors.exposed-headers", "X-Auth-Token");
        properties.put("spring.graphql.cors.allow-credentials", "true");

        List<Finding> findings = check(properties);

        assertThat(severities(findings)).containsExactly(Severity.MEDIUM, Severity.MEDIUM);
        assertThat(findings).allSatisfy(finding -> assertThat(finding.message()).contains("spring.graphql.cors."));
    }

    @Test
    @DisplayName("Actuator's origins don't enable GraphQL's configuration")
    void prefixesAreIndependent() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(ORIGINS, "https://trusted.example");
        properties.put("spring.graphql.cors.allowed-methods", "*");

        assertThat(check(properties)).isEmpty();
    }
}
