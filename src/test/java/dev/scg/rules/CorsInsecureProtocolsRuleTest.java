// FILE: CorsInsecureProtocolsRuleTest.java
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

class CorsInsecureProtocolsRuleTest {

    private static final String ORIGINS = "management.endpoints.web.cors.allowed-origins";
    private static final String PATTERNS = "management.endpoints.web.cors.allowed-origin-patterns";
    private static final String CREDENTIALS = "management.endpoints.web.cors.allow-credentials";

    private final CorsInsecureProtocolsRule rule = new CorsInsecureProtocolsRule();
    private static final Path FAKE_PATH = Path.of("application.yml");

    private List<Finding> check(String profile, Map<String, String> properties) {
        return rule.check(new EffectiveConfig(FAKE_PATH, profile, properties));
    }

    private List<Finding> check(Map<String, String> properties) {
        return check("prod", properties);
    }

    private static Map<String, String> withCredentials(String key, String value) {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(key, value);
        properties.put(CREDENTIALS, "true");
        return properties;
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "test", "local", "prod", "qa"})
    @DisplayName("Should generate MEDIUM finding for http:// origin with credentials in any profile (Zero-Trust)")
    void shouldGenerateFindingForHttpInAnyProfile(String profile) {
        List<Finding> findings = check(profile, withCredentials(ORIGINS, "http://app.company.com"));

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG004");
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(finding.message()).contains("http://app.company.com", CREDENTIALS);
    }

    @Test
    @DisplayName("A1: http:// origin with allow-credentials=true is MEDIUM")
    void httpOriginWithCredentialsIsMedium() {
        assertThat(check(withCredentials(ORIGINS, "http://partner.example")))
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("A2: http:// origin without allow-credentials is LOW")
    void httpOriginWithoutCredentialsIsLow() {
        List<Finding> findings = check(Map.of(ORIGINS, "http://partner.example"));

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.LOW);
        assertThat(findings.getFirst().message()).contains("http://partner.example", "anonymous requests");
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "${CORS_CREDENTIALS}"})
    @DisplayName("http:// origin with allow-credentials false or unresolved is LOW")
    void httpOriginWithCredentialsFalseOrUnresolvedIsLow(String credentials) {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(ORIGINS, "http://partner.example");
        properties.put(CREDENTIALS, credentials);

        assertThat(check(properties)).singleElement().extracting(Finding::severity).isEqualTo(Severity.LOW);
    }

    @Test
    @DisplayName("A3: an upper-case HTTP:// origin is reported, since allowed-origins is compared ignoring case")
    void upperCaseHttpOriginIsReported() {
        assertThat(check(withCredentials(ORIGINS, "HTTP://PARTNER.EXAMPLE")))
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("A4: an upper-case HTTP:// pattern is still reported, though Spring matches patterns case-sensitively")
    void upperCaseHttpPatternIsStillReported() {
        assertThat(check(withCredentials(PATTERNS, "HTTP://partner.example")))
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"*.example.com", "*://app.example.com", "http*://app.example.com"})
    @DisplayName("A5-A7: a pattern whose scheme is a wildcard or missing lets http:// origins in")
    void patternWithWildcardOrMissingSchemeIsReported(String pattern) {
        List<Finding> findings = check(withCredentials(PATTERNS, pattern));

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains(pattern);
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://*.example.com", "https://app.example.com", "*s://app.example.com"})
    @DisplayName("A pattern whose scheme can't be http stays silent")
    void patternThatCannotMatchHttpIsSilent(String pattern) {
        assertThat(check(withCredentials(PATTERNS, pattern))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost:*", "http://localhost:[*]", "http://*.localhost",
            "http://127.0.0.1:*", "http://[::1]:[*]", "http://localhost:3000/", "http://*.app.localhost"})
    @DisplayName("A8, A10, A11: loopback patterns with a port wildcard, port list or localhost subdomains stay silent")
    void loopbackPatternsAreSilent(String pattern) {
        assertThat(check(withCredentials(PATTERNS, pattern))).isEmpty();
    }

    @Test
    @DisplayName("A9b: a loopback port list in a YAML list item is one pattern, not split on its comma")
    void loopbackPortListInListItemIsSilent() {
        assertThat(check(withCredentials(PATTERNS + "[0]", "http://localhost:[8080,8082]"))).isEmpty();
    }

    @Test
    @DisplayName("A9: a loopback port list in a scalar stays silent (Spring Boot splits it, so it matches nothing)")
    void loopbackPortListInScalarIsSilent() {
        assertThat(check(withCredentials(PATTERNS, "http://localhost:[8080,8082]"))).isEmpty();
    }

    @Test
    @DisplayName("A remote port list in a YAML list item is reported as one origin")
    void remotePortListInListItemIsReportedWhole() {
        List<Finding> findings = check(withCredentials(PATTERNS + "[0]", "http://partner.example:[8080,8082]"));

        assertThat(findings).singleElement().extracting(Finding::message).asString()
                .contains("http://partner.example:[8080,8082]");
    }

    @Test
    @DisplayName("A13: http://localhost* is reported, since it matches http://localhost.evil.com")
    void localhostPrefixPatternIsReported() {
        assertThat(check(withCredentials(PATTERNS, "http://localhost*")))
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://*.127.0.0.1", "http://*localhost", "http://*.localhost.evil.com"})
    @DisplayName("A wildcard host is reported unless every match is a localhost name (*.127.0.0.1 is a DNS name)")
    void wildcardHostsOutsideLocalhostAreReported(String pattern) {
        assertThat(check(withCredentials(PATTERNS, pattern)))
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("The pattern '*' isn't a protocol choice and stays silent (SCG003 reports it with credentials)")
    void globalWildcardPatternIsSilent() {
        assertThat(check(withCredentials(PATTERNS, "*"))).isEmpty();
    }

    @Test
    @DisplayName("A '*' in allowed-origins is compared literally, so http://*.example.com there matches nothing")
    void wildcardInAllowedOriginsIsSilent() {
        assertThat(check(withCredentials(ORIGINS, "http://*.example.com"))).isEmpty();
    }

    @Test
    @DisplayName("G1: GraphQL http:// origin with credentials is MEDIUM")
    void graphqlHttpOriginWithCredentialsIsMedium() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put("spring.graphql.cors.allowed-origins", "http://partner.example");
        properties.put("spring.graphql.cors.allow-credentials", "true");

        List<Finding> findings = check(properties);

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("spring.graphql.cors.allowed-origins");
    }

    @Test
    @DisplayName("G2: GraphQL http:// pattern without credentials is LOW; Actuator's credentials don't apply to it")
    void graphqlPatternUsesItsOwnCredentials() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put("spring.graphql.cors.allowed-origin-patterns", "http://*.example.com");
        properties.put(CREDENTIALS, "true");

        assertThat(check(properties)).singleElement().extracting(Finding::severity).isEqualTo(Severity.LOW);
    }

    @Test
    @DisplayName("P1: http:// with an unresolved host placeholder is INFO")
    void unresolvedHostIsInfo() {
        List<Finding> findings = check(withCredentials(ORIGINS, "http://${PARTNER_HOST}"));

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.INFO);
        assertThat(findings.getFirst().message()).contains("http://${PARTNER_HOST}");
    }

    @Test
    @DisplayName("P2: a literal http:// origin next to an unresolved placeholder is reported at its own severity")
    void literalOriginNextToPlaceholderIsReported() {
        List<Finding> findings = check(withCredentials(ORIGINS, "${APP_ORIGIN},http://partner.example"));

        assertThat(findings).extracting(Finding::severity).containsExactly(Severity.MEDIUM, Severity.INFO);
        assertThat(findings.getFirst().message()).contains("http://partner.example").doesNotContain("APP_ORIGIN");
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://${APP_HOST}", "http://localhost:${PORT}", "${ORIGIN:https://app.example.com}"})
    @DisplayName("A placeholder whose literal part rules out plain HTTP or a remote host stays silent")
    void placeholderRuledOutByItsLiteralPartIsSilent(String value) {
        assertThat(check(withCredentials(ORIGINS, value))).isEmpty();
    }

    @Test
    @DisplayName("A placeholder default is resolved before the origins are split")
    void placeholderDefaultIsSplitAfterResolution() {
        List<Finding> findings = check(withCredentials(ORIGINS, "${ORIGINS:https://a.example.com,http://b.example.com}"));

        assertThat(findings).singleElement().extracting(Finding::message).asString()
                .contains("http://b.example.com").doesNotContain("https://a.example.com");
    }

    @Test
    @DisplayName("Should generate an INFO finding when allowed-origins relies on an unresolved environment placeholder")
    void shouldGenerateInfoFindingForUnresolvedPlaceholders() {
        List<Finding> findings = check(Map.of(ORIGINS, "${CORS_ALLOWED_ORIGINS}"));

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG004");
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder", "${CORS_ALLOWED_ORIGINS}");
    }

    @Test
    @DisplayName("Should NOT generate finding for http://localhost or http://127.0.0.1")
    void shouldNotGenerateFindingForLocalhost() {
        assertThat(check(withCredentials(ORIGINS, "http://localhost:3000, http://127.0.0.1:8080"))).isEmpty();
    }

    @Test
    @DisplayName("Should NOT generate finding for origins using secure protocol https://")
    void shouldNotGenerateFindingForHttps() {
        assertThat(check(withCredentials(ORIGINS, "https://app.company.com"))).isEmpty();
    }

    @Test
    @DisplayName("Should report only the http:// origin of a comma-separated list, once per key")
    void shouldDetectHttpInMixedList() {
        List<Finding> findings = check(withCredentials(ORIGINS, "https://secure.com, http://insecure.com"));

        assertThat(findings).singleElement().extracting(Finding::message).asString()
                .contains("http://insecure.com").doesNotContain("https://secure.com");
    }

    @Test
    @DisplayName("Should detect http:// in allowed-origin-patterns property")
    void shouldDetectHttpInAllowedOriginPatterns() {
        List<Finding> findings = check(withCredentials(PATTERNS, "http://*.company.com"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains(PATTERNS);
    }

    @Test
    @DisplayName("Should detect localhost subdomain bypass attempts (e.g., http://localhost.attacker.com)")
    void shouldDetectSubdomainLocalhostBypass() {
        List<Finding> findings = check(withCredentials(ORIGINS, "http://localhost.attacker.com"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("http://localhost.attacker.com");
    }

    @Test
    @DisplayName("Should recognize IPv6 loopback, 127.x.x.x range, and .localhost as local and NOT generate finding")
    void shouldRecognizeLoopbackVariationsAsLocal() {
        assertThat(check(withCredentials(ORIGINS, "http://127.0.1.1:8080, http://[::1]:3000, http://app.localhost"))).isEmpty();
    }

    @Test
    @DisplayName("Should generate finding for .local mDNS domains over http:// to prevent LAN MitM")
    void shouldGenerateFindingForMdnsLocalDomains() {
        List<Finding> findings = check(withCredentials(ORIGINS, "http://app.local:8080"));

        assertThat(findings).singleElement().extracting(Finding::severity).isEqualTo(Severity.MEDIUM);
        assertThat(findings.getFirst().message()).contains("http://app.local:8080");
    }

    @Test
    @DisplayName("Should NOT throw exception on malformed URI, treating it fail-closed as non-local")
    void shouldNotThrowExceptionForMalformedUri() {
        assertThat(check(withCredentials(ORIGINS, "http://an_invalid_syntax_origin.com"))).hasSize(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://127.attacker.com",
            "http://127.0.0.1.evil.org",
            "http://127.1.2.256",
            "http://127.0.0.1.com",
            "http://0127.0.0.1",
            "http://127.0.0.01"
    })
    @DisplayName("Should generate MEDIUM Finding for malicious domains disguised as 127.x.x.x loopback")
    void shouldDetectBypassAttemptsDisguisedAsLoopback(String origin) {
        assertThat(check(withCredentials(ORIGINS, origin)))
                .singleElement()
                .extracting(Finding::severity)
                .isEqualTo(Severity.MEDIUM);
    }
}
