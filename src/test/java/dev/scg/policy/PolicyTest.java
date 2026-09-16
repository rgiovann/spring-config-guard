package dev.scg.policy;

import dev.scg.core.Finding;
import dev.scg.core.ProfileMerger;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyTest {

    private static final Set<String> KNOWN_RULE_IDS = Set.of("SCG001", "SCG002", "SCG006");

    private static Finding findingOf(String ruleId, String profileLabel) {
        return new Finding(ruleId, Severity.HIGH, "msg", "application.yml", profileLabel);
    }

    @Test
    @DisplayName("Policy.none() lets every finding pass through unchanged")
    void noneLetsEveryFindingPassThrough() {
        List<Finding> findings = List.of(findingOf("SCG002", "dev"), findingOf("SCG006", "prod"));

        assertThat(Policy.none().apply(findings)).containsExactlyElementsOf(findings);
    }

    @Test
    @DisplayName("Suppresses only the configured rule+profile pair, not other rules in the same profile")
    void suppressesOnlyConfiguredRuleAndProfile(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, """
                SCG002:
                  - dev
                """);
        Policy policy = Policy.load(policyFile, KNOWN_RULE_IDS);

        Finding suppressed = findingOf("SCG002", "dev");
        Finding sameRuleOtherProfile = findingOf("SCG002", "prod");
        Finding otherRuleSameProfile = findingOf("SCG006", "dev");

        List<Finding> result = policy.apply(List.of(suppressed, sameRuleOtherProfile, otherRuleSameProfile));

        assertThat(result).containsExactly(sameRuleOtherProfile, otherRuleSameProfile);
    }

    @Test
    @DisplayName("Resolves the 'base' alias to ProfileMerger.BASE_PROFILE_LABEL")
    void resolvesBaseAliasToSentinel(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, """
                SCG001:
                  - base
                """);
        Policy policy = Policy.load(policyFile, KNOWN_RULE_IDS);

        Finding baseFinding = findingOf("SCG001", ProfileMerger.BASE_PROFILE_LABEL);

        assertThat(policy.apply(List.of(baseFinding))).isEmpty();
    }

    @Test
    @DisplayName("Resolves the 'base' alias case-insensitively and trims stray whitespace")
    void resolvesBaseAliasCaseInsensitivelyAndTrimmed(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, """
                SCG001:
                  - " Base "
                """);
        Policy policy = Policy.load(policyFile, KNOWN_RULE_IDS);

        Finding baseFinding = findingOf("SCG001", ProfileMerger.BASE_PROFILE_LABEL);

        assertThat(policy.apply(List.of(baseFinding))).isEmpty();
    }

    @Test
    @DisplayName("Does NOT case-fold real profile names -- only the 'base' alias is case-insensitive")
    void doesNotCaseFoldRealProfileNames(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, """
                SCG001:
                  - DEV
                """);
        Policy policy = Policy.load(policyFile, KNOWN_RULE_IDS);

        Finding lowercaseDev = findingOf("SCG001", "dev");

        assertThat(policy.apply(List.of(lowercaseDev))).containsExactly(lowercaseDev);
    }

    @Test
    @DisplayName("'*' suppresses the rule across every profile")
    void wildcardSuppressesEveryProfile(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, """
                SCG006:
                  - "*"
                """);
        Policy policy = Policy.load(policyFile, KNOWN_RULE_IDS);

        List<Finding> findings = List.of(
                findingOf("SCG006", "dev"),
                findingOf("SCG006", "prod"),
                findingOf("SCG006", ProfileMerger.BASE_PROFILE_LABEL)
        );

        assertThat(policy.apply(findings)).isEmpty();
    }

    @Test
    @DisplayName("Fails fast when the policy file references an unknown rule ID")
    void failsFastOnUnknownRuleId(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, """
                SCG999:
                  - dev
                """);

        assertThatThrownBy(() -> Policy.load(policyFile, KNOWN_RULE_IDS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SCG999");
    }

    @Test
    @DisplayName("Fails fast when the policy file is empty")
    void failsFastOnEmptyFile(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, "");

        assertThatThrownBy(() -> Policy.load(policyFile, KNOWN_RULE_IDS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty or malformed");
    }

    @Test
    @DisplayName("Fails fast when a rule maps to something other than a list of profiles")
    void failsFastOnWrongValueShape(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, """
                SCG002: dev
                """);

        assertThatThrownBy(() -> Policy.load(policyFile, KNOWN_RULE_IDS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SCG002");
    }

    @Test
    @DisplayName("Fails fast when the policy file is not valid YAML")
    void failsFastOnInvalidYaml(@TempDir Path tempDir) throws IOException {
        Path policyFile = writePolicy(tempDir, "SCG002: [dev");

        assertThatThrownBy(() -> Policy.load(policyFile, KNOWN_RULE_IDS))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Propagates IOException when the policy file does not exist")
    void propagatesIOExceptionWhenFileMissing(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("does-not-exist.yml");

        assertThatThrownBy(() -> Policy.load(missing, KNOWN_RULE_IDS))
                .isInstanceOf(IOException.class);
    }

    private static Path writePolicy(Path tempDir, String content) throws IOException {
        Path file = tempDir.resolve("scg-policy.yml");
        Files.writeString(file, content);
        return file;
    }
}
