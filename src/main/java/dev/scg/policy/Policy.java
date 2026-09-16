package dev.scg.policy;

import dev.scg.core.Finding;
import dev.scg.core.ProfileMerger;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Binary suppression of {@link Finding}s by rule ID + profile, applied between
 * {@code RuleEngine.run()} and {@code Reporter}/{@code ExitCodeResolver} — neither of those needs
 * to know this exists. Rules stay profile-agnostic (Zero-Trust); this is where a consuming team's
 * own risk acceptance ("we accept SCG002 in dev") lives instead, per rule and per profile so one
 * suppressed rule doesn't blanket-disable every other rule in that same profile.
 * <p>
 * The YAML source is user-authored input, not a project-shipped resource, so {@link #load} treats
 * it as a real boundary: an unknown rule ID, a malformed shape, or an empty file all fail fast
 * with a specific message rather than a raw {@link ClassCastException} or a silent no-op — a typo
 * in a rule ID would otherwise suppress nothing while looking like it suppressed something.
 * <p>
 * {@code "base"} is accepted as the profile alias for {@link ProfileMerger#BASE_PROFILE_LABEL},
 * matching the same human-facing label {@link Finding#toString()} already uses, so nobody needs to
 * know the internal sentinel value to write a policy. {@code "*"} suppresses a rule in every
 * profile without enumerating each one.
 */
public final class Policy {

    private static final String PROFILE_WILDCARD = "*";
    private static final String BASE_PROFILE_ALIAS = "base";

    private final Map<String, Set<String>> suppressedProfilesByRule;

    private Policy(Map<String, Set<String>> suppressedProfilesByRule) {
        this.suppressedProfilesByRule = suppressedProfilesByRule;
    }

    /** No-op policy: every finding passes through unchanged. */
    public static Policy none() {
        return new Policy(Map.of());
    }

    /**
     * @param knownRuleIds registered rule IDs (from {@code RuleRegistry.discoverRules()}), used to
     *                      fail fast on a typo'd rule ID instead of silently suppressing nothing.
     */
    public static Policy load(Path yamlPath, Set<String> knownRuleIds) throws IOException {
        Objects.requireNonNull(yamlPath, "yamlPath must not be null");
        Objects.requireNonNull(knownRuleIds, "knownRuleIds must not be null");

        Object loaded;
        try (InputStream is = Files.newInputStream(yamlPath)) {
            loaded = new Yaml().load(is);
        } catch (YAMLException e) {
            throw new IllegalArgumentException(
                    "Policy file '" + yamlPath + "' is not valid YAML: " + e.getMessage(), e);
        }

        if (!(loaded instanceof Map<?, ?> rawMap) || rawMap.isEmpty()) {
            throw new IllegalArgumentException(
                    "Policy file '" + yamlPath + "' is empty or malformed: expected a map of " +
                            "rule ID to a list of profiles.");
        }

        Map<String, Set<String>> parsed = new HashMap<>();
        for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
            String ruleId = String.valueOf(entry.getKey());
            if (!knownRuleIds.contains(ruleId)) {
                throw new IllegalArgumentException(
                        "Policy file '" + yamlPath + "' references unknown rule ID '" + ruleId +
                                "'. Known rule IDs: " +
                                knownRuleIds.stream().sorted().collect(Collectors.joining(", ")));
            }

            if (!(entry.getValue() instanceof List<?> rawProfiles) || rawProfiles.isEmpty()) {
                throw new IllegalArgumentException(
                        "Policy file '" + yamlPath + "': rule '" + ruleId +
                                "' must map to a non-empty list of profiles.");
            }

            Set<String> profiles = rawProfiles.stream()
                    .map(String::valueOf)
                    .map(Policy::resolveProfileAlias)
                    .collect(Collectors.toUnmodifiableSet());
            parsed.put(ruleId, profiles);
        }

        return new Policy(Map.copyOf(parsed));
    }

    /**
     * Trims every value (defends against stray YAML whitespace) and case-folds only the "base"
     * comparison -- "base" is a tool-invented alias, not real Spring data, so being lenient about
     * how a user writes it is safe. A real profile name is deliberately NOT case-folded here: it
     * must match {@link Finding#profileLabel()} exactly, the same way Spring itself treats profile
     * names as case-sensitive strings (unlike property keys, which get relaxed binding).
     */
    private static String resolveProfileAlias(String profile) {
        String trimmed = profile.strip();
        return BASE_PROFILE_ALIAS.equalsIgnoreCase(trimmed) ? ProfileMerger.BASE_PROFILE_LABEL : trimmed;
    }

    /** Returns a new list with every suppressed finding removed; input order is preserved. */
    public List<Finding> apply(List<Finding> findings) {
        return findings.stream()
                .filter(finding -> !isSuppressed(finding))
                .toList();
    }

    private boolean isSuppressed(Finding finding) {
        Set<String> profiles = suppressedProfilesByRule.get(finding.ruleId());
        if (profiles == null) {
            return false;
        }
        return profiles.contains(PROFILE_WILDCARD) || profiles.contains(finding.profileLabel());
    }
}
