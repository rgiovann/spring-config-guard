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
 *  the H2 console exposes a database access tool, while Actuator (env, configprops, heapdump) can
 *  expose actual secrets in memory (API tokens, passwords, environment variables) once show-values
 *  is also elevated (see the show-values check below) — and even at show-values' safe default, mere
 *  reachability still discloses property names and config structure, itself useful reconnaissance;
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
 * <p>
 * Also detects {@code management.endpoint.env.show-values} / {@code management.endpoint.configprops.show-values}
 * set to {@code always} or {@code when-authorized} on a reachable, unrestricted env/configprops
 * endpoint (HIGH) — independent of the wildcard-exposure check above, since {@code exposure.include}
 * can list these endpoints explicitly without a wildcard. Confirmed against the actual Spring Boot
 * {@code Sanitizer} source: {@code show-values} is a master switch — at the safe default
 * ({@code never}), every value is masked regardless of key name; once elevated, only keys matching
 * known-sensitive patterns (password, secret, token, ...) stay masked, so this property is what
 * actually decides whether raw values are exposed, not endpoint reachability by itself.
 * {@code when-authorized} is treated as equally risky as {@code always}, not a lesser opt-out: its
 * actual safety depends on a runtime {@code SecurityContext} this tool has no visibility into, so
 * the mere opt-out from the safe {@code never} default is the signal, same posture as the rest of
 * this project's Zero-Trust checks.
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

    private static final Set<String> SHOW_VALUES_ENDPOINTS = Set.of("env", "configprops");
    // Matches Spring Boot's own lenient enum binding rather than enumerating separator variants
    // by hand: LenientObjectToEnumConverterFactory.getCanonicalName() (org.springframework.boot.convert)
    // reduces both the source string and the enum constant name to letters/digits only, lowercased,
    // before comparing -- so "when-authorized", "when_authorized", and "whenAuthorized" all bind to
    // the same constant. A Set of separator variants compared via toUpperCase() (this project's
    // original approach here, and still VerboseErrorResponseRule's RISKY_ENUM_VALUES) misses
    // "whenAuthorized": it canonicalizes to "whenauthorized", which has no separator left to match a
    // set entry written with one. See HealthDetailsExposureRule (SCG013) for the same fix applied
    // from the start.
    private static final Set<String> RISKY_CANONICAL_SHOW_VALUES = Set.of("always", "whenauthorized");

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

        if (hasWildcardExposure) {
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
                                + "Endpoint structure and property names are disclosed regardless of show-values; "
                                + "raw values stay masked unless show-values is also elevated (see SCG001's separate "
                                + "show-values finding, if any). "
                                + "Consider setting management.endpoint.<name>.access=none for each one, or replacing '*' with an explicit list.",
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }

        // Independent of hasWildcardExposure above: exposure.include can list env/configprops
        // explicitly without a wildcard, and that path must still be evaluated for show-values.
        List<String> leakingValues = new ArrayList<>();
        for (String endpoint : SHOW_VALUES_ENDPOINTS) {
            if (isEndpointReachable(config, endpoint) && !isRestricted(config, endpoint)
                    && hasRiskyShowValues(config, endpoint, findings)) {
                leakingValues.add(endpoint);
            }
        }

        if (!leakingValues.isEmpty()) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    "management.endpoint.<id>.show-values exposes raw property values for: %s (reachable via %s). "
                            .formatted(String.join(", ", leakingValues), EXPOSURE_KEY)
                            + "Set show-values=never (the safe default) unless authenticated access to raw values is a deliberate, justified requirement.",
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
     * True when {@code endpointId} is reachable via {@code exposure.include}: a wildcard
     * (delegates to {@link #mayContainWildcard(String)}) or the id present as an explicit,
     * exact token — covers both the YAML list form (each item already isolated by
     * {@code valuesForKeyOrListChildren}) and the comma-separated scalar form used by
     * {@code .properties} files and flow-style YAML. Exact token match after split+trim,
     * not a substring check, so a hypothetical endpoint id sharing a prefix with another
     * token can't false-positive (same class of bug {@code hasKeyWithPrefix} was written
     * to avoid for key matching).
     */
    private boolean isEndpointReachable(EffectiveConfig config, String endpointId) {
        return RelaxedProperties.valuesForKeyOrListChildren(config.properties(), EXPOSURE_KEY).stream()
                .anyMatch(rawValue -> mayContainWildcard(rawValue) || explicitlyIncludes(rawValue, endpointId));
    }

    private boolean explicitlyIncludes(String rawValue, String endpointId) {
        if (rawValue == null) {
            return false; // explicit null (BL-09): intentional override, not a risk
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);
        // Same 2-state posture as mayContainWildcard() for this same property: an unresolved
        // placeholder without a default is treated as "may include this endpoint" rather than
        // silently assumed safe -- consistent with how the sibling wildcard check already
        // treats exposure.include's own uncertainty. Deliberately NOT the 3-state INFO model
        // used by hasRiskyShowValues() below: this is the same key mayContainWildcard() already
        // reads with 2-state semantics, so splitting the two paths would make exposure.include's
        // uncertainty behave differently depending on which check happens to evaluate it.
        if (resolved.isEmpty()) {
            return true;
        }

        for (String token : resolved.get().split(",")) {
            if (endpointId.equalsIgnoreCase(token.strip())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Unlike {@link #isRestricted(EffectiveConfig, String)}, this follows the project's newer
     * 3-state placeholder model (INFO for unresolved) rather than the older 2-state
     * assume-worst-case one. {@code show-values} is a property this rule has never evaluated
     * before, so there is no existing 2-state precedent on this specific key to stay consistent
     * with — and CLAUDE.md's Findings section defines INFO as exactly this case ("static
     * analysis cannot determine the actual risk"). isRestricted() and mayContainWildcard() are
     * untouched and keep their existing 2-state behavior on their own keys; this is a deliberate,
     * documented exception, not an oversight.
     */
    private boolean hasRiskyShowValues(EffectiveConfig config, String endpointId, List<Finding> findings) {
        String key = "management.endpoint." + endpointId + ".show-values";
        String raw = RelaxedProperties.get(config.properties(), key);
        if (raw == null || raw.isBlank()) {
            return false;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(key, raw, config));
            return false;
        }

        return RISKY_CANONICAL_SHOW_VALUES.contains(canonicalize(resolved.get().strip()));
    }

    /**
     * Same reduction as Spring Boot's {@code LenientObjectToEnumConverterFactory.getCanonicalName()}:
     * keep only letters/digits, lowercase -- so separator style (hyphen/underscore/none) and casing
     * stop mattering, matching how the real {@code Binder} would resolve this enum value at runtime.
     */
    private static String canonicalize(String value) {
        StringBuilder canonical = new StringBuilder(value.length());
        value.chars()
                .filter(Character::isLetterOrDigit)
                .map(Character::toLowerCase)
                .forEach(c -> canonical.append((char) c));
        return canonical.toString();
    }

    private Finding unresolvedPlaceholderFinding(String key, String rawValue, EffectiveConfig config) {
        return new Finding(
                id(),
                Severity.INFO,
                ("Actuator property '%s' relies on an unresolved environment placeholder '%s'. " +
                        "Static analysis cannot verify whether raw property values are exposed at runtime.")
                        .formatted(key, rawValue),
                config.sourceFile().toString(),
                config.profileLabel()
        );
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