package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * SCG001 — detects management.endpoints.web.exposure.include=* when sensitive endpoints
 * are not explicitly restricted.
 * Sensitive endpoints according to the Spring Boot documentation: env, heapdump, threaddump, shutdown,
 * configprops, beans.
*  DELIBERATE DECISION (session on 2026-08-21): this rule does NOT exempt safe profiles (dev/test/local),
 *  unlike H2ConsoleExposedRule. This is not a gap to be fixed — it was explicitly evaluated and the
 *  decision was made to keep it this way. Reasons: (1) the nature of the exposure is different —
 *  the H2 console exposes a database access tool, while Actuator (env, configprops, heapdump)
 *  exposes actual secrets in memory (API tokens, passwords, environment variables);
 *  (2) dev/local environments commonly share real or semi-real credentials from staging/external services,
 *  so an exposed /env endpoint in a dev environment connected to the corporate network is already a direct
 *  attack vector; (3) the correct Spring Boot practice is for the base configuration to declare only safe
 *  endpoints (health, info) — include=* in the base configuration is already an anti-pattern, regardless
 *  of the profile.
 * Starting with Spring Boot 3.4, endpoint access control migrated from management.endpoint.<id>.enabled
 * (boolean, deprecated) to management.endpoint.<id>.access (none | read-only | unrestricted).
 * Confirmed in the Spring Boot 3.4 Configuration Changelog (official wiki of the
 * spring-projects/spring-boot repository) that most endpoints have access=unrestricted by default —
 * BUT shutdown (default=none since 3.4) and heapdump (default=none since 3.5) are exceptions.
 * Also empirically confirmed against a real Spring Boot 4.1 application: heapdump only appears on
 * the discovery page after explicitly setting access=unrestricted, even with exposure.include=*.
 */
public final class ActuatorExposureRule implements Rule {

    private static final String EXPOSURE_KEY = "management.endpoints.web.exposure.include";

    private static final Set<String> SENSITIVE_ENDPOINTS = Set.of(
            "env", "heapdump", "threaddump", "shutdown", "configprops", "beans"
    );

    //Confirmed: management.endpoint.shutdown.access and management.endpoint.heapdump.access
    // have a default value of "none" (restricted), unlike the other sensitive endpoints
    // (default "unrestricted").
    //Without this distinction, the rule generates false positives for these two endpoints when
    // no explicit configuration exists (BL-11).
    private static final Set<String> RESTRICTED_BY_DEFAULT = Set.of("shutdown", "heapdump");

    private static final String RESTRICTED_ACCESS_VALUE = "none";

    @Override
    public String id() {
        return "SCG001";
    }

    @Override
    public String description() {
        return "Actuator exposed via exposure.include=* without restricting sensitive endpoints";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        boolean hasWildcardExposure = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), EXPOSURE_KEY)
                .stream()
                .anyMatch(this::mayContainWildcard);

        if (!hasWildcardExposure) {
            return findings;
        }

        List<String> stillEnabled = new ArrayList<>();
        for (String endpoint : SENSITIVE_ENDPOINTS) {
            if (!isRestricted(config, endpoint)) {
                stillEnabled.add(endpoint);
            }
        }

        if (!stillEnabled.isEmpty()) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    "%s contains * and exposes all endpoints via HTTP, and the following remain unrestricted: %s. "
                            .formatted(EXPOSURE_KEY, String.join(", ", stillEnabled))
                            + "Consider setting management.endpoint.<name>.access=none for each one, or replacing '*' with an explicit list.",
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }

        return findings;
    }

    private boolean mayContainWildcard(String value) {
        if (value == null) {
            return false; // Explicit null (BL-09): intentional override, not a risk
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        // Dynamic placeholder without a default: we do not know the actual value,
        // so we assume it MAY be "*" — security-oriented approach.
        return resolved.map(s -> s.contains("*")).orElse(true);

    }

    /**
     * An endpoint is considered restricted (not exposed in practice) when:
     * (1) management.endpoint.<id>.access = "none" (current mechanism, 3.4+), OR
     * (2) management.endpoint.<id>.enabled = "false" (legacy mechanism), OR
     * (3) neither key is defined, and the endpoint is one of those that
     * Spring Boot itself restricts by default (shutdown, heapdump).
     * access takes precedence over enabled when both are present — it is
     * the newer mechanism of the two. This specific precedence order
     * (what happens if both keys coexist with conflicting values) has not
     * been confirmed against a real-world scenario; it is the most reasonable
     * interpretation of the documented migration, not a tested fact — document
     * it if this ever becomes relevant in practice.
     */
    private boolean isRestricted(EffectiveConfig config, String endpoint) {
        String rawAccessValue = RelaxedProperties.get(config.properties(), "management.endpoint." + endpoint + ".access");
        if (rawAccessValue != null) {
            Optional<String> accessValue = EnvironmentPlaceholder.resolve(rawAccessValue);
            return accessValue.filter(s -> RESTRICTED_ACCESS_VALUE.equalsIgnoreCase(s.trim())).isPresent();
            // access is present but is a dynamic placeholder without a default:
            // we do not continue the fallback chain (which could mask the
            // risk via RESTRICTED_BY_DEFAULT) — we assume unrestricted.
        }

        String rawEnabledValue = RelaxedProperties.get(config.properties(), "management.endpoint." + endpoint + ".enabled");
        if (rawEnabledValue != null) {
            Optional<String> enabledValue = EnvironmentPlaceholder.resolve(rawEnabledValue);
            // same approach: dynamic placeholder without a default -> assume unrestricted
            return enabledValue.filter(s -> "false".equalsIgnoreCase(s.trim())).isPresent();
        }

        return RESTRICTED_BY_DEFAULT.contains(endpoint);
    }
}