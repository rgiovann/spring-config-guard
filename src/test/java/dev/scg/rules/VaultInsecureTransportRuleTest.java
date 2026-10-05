package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers SCG016's opt-in-to-insecure trigger (absence is safe -- default 'https'), the
 * uri-overrides-scheme precedence (including uri falling back to scheme when blank), the
 * case-sensitive scheme, the spring.cloud.vault.enabled switch, all three placeholder states for
 * both properties, and Zero-Trust across profiles. Row IDs (S1, U4, E1, ...) are the rows of
 * VALIDATION.md, "SCG016 Vault transport scenarios", measured in spring-env-benchmark/vault-transport.
 */
class VaultInsecureTransportRuleTest {

    private final VaultInsecureTransportRule rule = new VaultInsecureTransportRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");
    private static final String SCHEME_KEY = "spring.cloud.vault.scheme";
    private static final String URI_KEY = "spring.cloud.vault.uri";

    @Test
    @DisplayName("D0: silent when neither scheme nor uri is configured: the client used TLS")
    void shouldStaySilentWhenNeitherPropertyConfigured() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.cloud.vault.host", "vault.internal"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("S3: silent when scheme is explicitly https")
    void shouldStaySilentWhenSchemeIsHttps() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(SCHEME_KEY, "https"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("S1: HIGH when scheme is explicitly http: the token went in the clear")
    void shouldReportHighWhenSchemeIsHttp() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(SCHEME_KEY, "http"));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.ruleId()).isEqualTo("SCG016");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("'spring.cloud.vault.scheme=http'");
    }

    @Test
    @DisplayName("S2: silent for scheme=HTTP: Spring Cloud Vault compares it case-sensitively and the app didn't start")
    void shouldStaySilentForUpperCaseScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(SCHEME_KEY, "HTTP"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("S4: silent when scheme is blank: the app didn't start")
    void shouldStaySilentWhenSchemeIsBlank() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(SCHEME_KEY, "   "));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("U1: HIGH when uri starts with http://: the token went in the clear")
    void shouldReportHighWhenUriIsHttp() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "http://vault.internal:8200"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.message()).contains("'spring.cloud.vault.uri=http://vault.internal:8200'");
    }

    @Test
    @DisplayName("U5: silent for uri=HTTP://...: Spring Cloud Vault compares the scheme case-sensitively and the app didn't start")
    void shouldStaySilentForUpperCaseUriScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "HTTP://vault.internal:8200"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "FALSE", "off", "no", "0", "${VAULT_ENABLED:false}"})
    @DisplayName("E1-E5: silent when spring.cloud.vault.enabled is a false literal (false, FALSE, off, no, 0), or a placeholder whose default is one: the client made no connection")
    void shouldStaySilentWhenVaultIsDisabled(String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                SCHEME_KEY, "http",
                "spring.cloud.vault.enabled", value
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("enabled=false is checked first: it silences an unresolved uri too, and works with a relaxed spelling")
    void disabledWinsOverUnresolvedUri() {
        EffectiveConfig unresolvedUri = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "${VAULT_URI}",
                "spring.cloud.vault.enabled", "false"
        ));
        EffectiveConfig relaxedSpelling = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                SCHEME_KEY, "http",
                "SPRING.CLOUD.VAULT.ENABLED", "false"
        ));

        assertThat(rule.check(unresolvedUri)).isEmpty();
        assertThat(rule.check(relaxedSpelling)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "${VAULT_ENABLED}"})
    @DisplayName("still HIGH when enabled is true or unknown (a placeholder without a default)")
    void shouldReportWhenVaultIsNotProvablyDisabled(String value) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                SCHEME_KEY, "http",
                "spring.cloud.vault.enabled", value
        ));

        assertThat(rule.check(config)).singleElement().extracting(Finding::severity).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("U2: silent when uri starts with https://, with no scheme present")
    void shouldStaySilentWhenUriIsHttpsAlone() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "https://vault.internal:8200"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("U3: silent when uri starts with https://, even if scheme=http is also present: uri wins")
    void shouldStaySilentWhenUriIsHttpsRegardlessOfScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "https://vault.internal:8200",
                SCHEME_KEY, "http"
        ));

        // uri takes precedence over scheme in Spring Cloud Vault's real binding.
        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("U4: HIGH from uri even when scheme=https is also present: uri wins")
    void shouldReportHighFromUriRegardlessOfScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "http://vault.internal:8200",
                SCHEME_KEY, "https"
        ));

        // uri takes precedence over scheme -- an insecure uri isn't rescued by a secure scheme.
        List<Finding> findings = rule.check(config);
        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("uri=http://");
    }

    @Test
    @DisplayName("Should stay silent for a non-http/https uri scheme (not our concern -- startup failure)")
    void shouldStaySilentForUnrecognizedUriScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "vault.internal:8200"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("U6: falls back to scheme when uri is blank")
    void shouldFallBackToSchemeWhenUriIsBlank() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "   ",
                SCHEME_KEY, "http"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("scheme=http");
    }

    @Test
    @DisplayName("Should report INFO when uri relies on an unresolved placeholder")
    void shouldReportInfoOnUnresolvedUriPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "${VAULT_URI}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        Finding finding = findings.getFirst();
        assertThat(finding.severity()).isEqualTo(Severity.INFO);
        assertThat(finding.message()).contains("unresolved environment placeholder '${VAULT_URI}'");
    }

    @Test
    @DisplayName("Should not fall back to scheme when uri placeholder is unresolved (uncertainty stays uncertainty)")
    void shouldNotFallBackToSchemeOnUnresolvedUriPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "${VAULT_URI}",
                SCHEME_KEY, "http"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("Should report INFO when scheme relies on an unresolved placeholder and uri is absent")
    void shouldReportInfoOnUnresolvedSchemePlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                SCHEME_KEY, "${VAULT_SCHEME}"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("Should report HIGH when uri placeholder resolves to an insecure default")
    void shouldReportHighOnResolvedInsecureUriPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "${VAULT_URI:http://vault.internal:8200}"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should stay silent when uri placeholder resolves to a secure default")
    void shouldStaySilentOnResolvedSecureUriPlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "${VAULT_URI:https://vault.internal:8200}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should fall back to scheme when uri placeholder resolves to an empty default")
    void shouldFallBackToSchemeOnEmptyUriPlaceholderDefault() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "${VAULT_URI:}",
                SCHEME_KEY, "http"
        ));

        List<Finding> findings = rule.check(config);

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().message()).contains("scheme=http");
    }

    @Test
    @DisplayName("Should report HIGH when scheme placeholder resolves to an insecure default")
    void shouldReportHighOnResolvedInsecureSchemePlaceholder() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                SCHEME_KEY, "${VAULT_SCHEME:http}"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should stay silent when scheme placeholder resolves to an empty default")
    void shouldStaySilentOnEmptySchemePlaceholderDefault() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                SCHEME_KEY, "${VAULT_SCHEME:}"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should not throw and stay silent when scheme value is null and uri is absent")
    void shouldNotThrowWhenSchemeValueIsNull() {
        Map<String, String> properties = new HashMap<>();
        properties.put(SCHEME_KEY, null);

        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", properties);

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should respect relaxed binding case-folding across segments for scheme")
    void shouldSupportRelaxedBindingForScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "SPRING.CLOUD.VAULT.SCHEME", "http"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should respect relaxed binding case-folding across segments for uri")
    void shouldSupportRelaxedBindingForUri() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "SPRING.CLOUD.VAULT.URI", "http://vault.internal:8200"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "test", "local", "prod", "staging"})
    @DisplayName("Should report regardless of active profile (Zero-Trust)")
    void shouldReportRegardlessOfProfile(String profile) {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, profile, Map.of(SCHEME_KEY, "http"));

        assertThat(rule.check(config)).hasSize(1);
    }
}
