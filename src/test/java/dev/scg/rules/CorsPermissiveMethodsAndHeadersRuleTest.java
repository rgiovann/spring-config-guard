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
    @DisplayName("E1: an origin that resolves empty builds no CORS configuration, so the rule is silent")
    void silentWhenOriginResolvesEmpty() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(ORIGINS, "${SCG_ORIGINS:}");
        properties.put(ALLOWED_METHODS_KEY, "*");
        properties.put(EXPOSED_HEADERS_KEY, "Authorization");
        properties.put(CREDENTIALS, "true");

        assertThat(check(properties)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"${SCG_ORIGINS: }", "${SCG_ORIGINS:},", " , "})
    @DisplayName("An origin value that yields no origin, blank or only commas, is silent like E1")
    void silentWhenOriginValueYieldsNoOrigin(String origin) {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(ORIGINS, origin);
        properties.put(ALLOWED_METHODS_KEY, "*");
        properties.put(CREDENTIALS, "true");

        assertThat(check(properties)).isEmpty();
    }

    @Test
    @DisplayName("An empty origin list item next to a real one still enables the checks")
    void emptyOriginListItemNextToRealOne() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(ORIGINS + "[0]", "${SCG_ORIGINS:}");
        properties.put(ORIGINS + "[1]", "https://trusted.example");
        properties.put(ALLOWED_METHODS_KEY, "*");
        properties.put(CREDENTIALS, "true");

        assertThat(severities(check(properties))).containsExactly(Severity.MEDIUM);
    }

    @Test
    @DisplayName("E1 under GraphQL: an empty GraphQL origin is silent, whatever Actuator's origins are")
    void graphQlOriginResolvingEmptyIsSilent() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(ORIGINS, "https://trusted.example");
        properties.put("spring.graphql.cors.allowed-origins", "${GRAPHQL_ORIGINS:}");
        properties.put("spring.graphql.cors.allowed-methods", "*");
        properties.put("spring.graphql.cors.allow-credentials", "true");

        assertThat(check(properties)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"${SCG_ORIGINS}", "${SCG_ORIGINS:https://trusted.example}"})
    @DisplayName("An origin that is a placeholder without a default, or with a non-empty one, enables the checks")
    void originPlaceholderEnablesChecks(String origin) {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(ORIGINS, origin);
        properties.put(ALLOWED_METHODS_KEY, "*");
        properties.put(CREDENTIALS, "true");

        assertThat(severities(check(properties))).containsExactly(Severity.MEDIUM);
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
    @DisplayName("M4: an explicit list of methods is silent, though it lets DELETE through: listing them is the fix")
    void explicitMethodsAreSilent() {
        assertThat(check(cors(ALLOWED_METHODS_KEY, "GET,DELETE", "true"))).isEmpty();
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

    @ParameterizedTest
    @ValueSource(strings = {"X-Access-Token", "x-refresh-token", "X-JWT", "X-Session-Id", "X_Client_Secret",
            "X-Api-Key", "X-APIKEY", "X-Authorization"})
    @DisplayName("T1: a header whose name suggests a token or a session is INFO, with or without credentials")
    void tokenLikeHeaderIsInfo(String header) {
        for (String credentials : new String[]{"true", null}) {
            List<Finding> findings = check(cors(EXPOSED_HEADERS_KEY, header, credentials));

            assertThat(severities(findings)).containsExactly(Severity.INFO);
            assertThat(findings.getFirst().message()).contains(header, "suggests a token or a session");
        }
    }

    @Test
    @DisplayName("Headers that keep their own finding aren't also reported as token-like")
    void knownHeadersKeepTheirOwnFinding() {
        assertThat(severities(check(cors(EXPOSED_HEADERS_KEY, "X-Auth-Token, Set-Cookie", "true"))))
                .containsExactly(Severity.MEDIUM, Severity.LOW);
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
