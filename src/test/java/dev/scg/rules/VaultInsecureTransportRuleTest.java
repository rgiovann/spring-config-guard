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
 * uri-overrides-scheme precedence (including uri falling back to scheme when blank), all three
 * placeholder states for both properties, and Zero-Trust across profiles.
 */
class VaultInsecureTransportRuleTest {

    private final VaultInsecureTransportRule rule = new VaultInsecureTransportRule();
    private static final Path FAKE_PATH = Path.of("src/main/resources/application.yml");
    private static final String SCHEME_KEY = "spring.cloud.vault.scheme";
    private static final String URI_KEY = "spring.cloud.vault.uri";

    @Test
    @DisplayName("Should stay silent when neither scheme nor uri is configured (default is https)")
    void shouldStaySilentWhenNeitherPropertyConfigured() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                "spring.cloud.vault.host", "vault.internal"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when scheme is explicitly https")
    void shouldStaySilentWhenSchemeIsHttps() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(SCHEME_KEY, "https"));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH when scheme is explicitly http")
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
    @DisplayName("Should detect scheme=http case-insensitively")
    void shouldDetectSchemeCaseInsensitively() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(SCHEME_KEY, "HTTP"));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should stay silent when scheme resolves to blank (same as absent -- default https applies)")
    void shouldStaySilentWhenSchemeIsBlank() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(SCHEME_KEY, "   "));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH when uri starts with http://")
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
    @DisplayName("Should detect uri http:// case-insensitively")
    void shouldDetectUriSchemeCaseInsensitively() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "HTTP://vault.internal:8200"
        ));

        assertThat(rule.check(config)).hasSize(1);
    }

    @Test
    @DisplayName("Should stay silent when uri starts with https:// on its own, with no scheme present")
    void shouldStaySilentWhenUriIsHttpsAlone() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "https://vault.internal:8200"
        ));

        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should stay silent when uri starts with https://, even if scheme=http is also present")
    void shouldStaySilentWhenUriIsHttpsRegardlessOfScheme() {
        EffectiveConfig config = new EffectiveConfig(FAKE_PATH, "prod", Map.of(
                URI_KEY, "https://vault.internal:8200",
                SCHEME_KEY, "http"
        ));

        // uri takes precedence over scheme in Spring Cloud Vault's real binding.
        assertThat(rule.check(config)).isEmpty();
    }

    @Test
    @DisplayName("Should report HIGH from uri even when scheme=https is also present")
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
    @DisplayName("Should fall back to evaluating scheme when uri is blank")
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
