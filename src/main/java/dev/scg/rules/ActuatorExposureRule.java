package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * SCG001 — detects sensitive Actuator endpoints reachable via
 * {@code management.endpoints.web.exposure.include} and not explicitly restricted, whether via a
 * wildcard ({@code *}) or an explicit list entry. Tracks {@code env}, {@code heapdump},
 * {@code threaddump}, {@code shutdown}, {@code configprops}, {@code beans}, {@code loggers}
 * (Actuator core), and {@code restart} (Spring Cloud Context; see {@code RESTRICTED_BY_DEFAULT}).
 * <p>
 * Does NOT track {@code refresh} or {@code sessions}: both are conditionally auto-configured on an
 * optional bean/dependency this static-analysis tool can't see (Spring Cloud Context;
 * {@code FindByIndexNameSessionRepository} for {@code sessions} specifically), so flagging them
 * would risk advising restriction on an endpoint that doesn't exist in most real apps. Does NOT
 * track {@code jolokia}: Spring Boot 3 dropped its auto-configuration entirely.
 * <p>
 * Also flags {@code management.endpoint.env/configprops.show-values=always|when-authorized} on a
 * reachable, unrestricted endpoint (HIGH) — {@code show-values} is the actual switch for raw-value
 * exposure, not reachability by itself; {@code when-authorized} is treated as equally risky since
 * its real safety depends on a runtime {@code SecurityContext} this tool can't see.
 * <p>
 * No profile exemption (Zero-Trust), unlike {@link H2ConsoleExposedRule}: {@code include=*} is
 * already an anti-pattern in base config regardless of profile, and dev/local environments often
 * carry real credentials anyway.
 */
public final class ActuatorExposureRule implements Rule {

    private static final String EXPOSURE_KEY = "management.endpoints.web.exposure.include";

    private static final Set<String> SENSITIVE_ENDPOINTS = Set.of(
            "env", "heapdump", "threaddump", "shutdown", "configprops", "beans", "loggers", "restart"
    );

    //Confirmed: management.endpoint.shutdown.access and management.endpoint.heapdump.access
    // have a default value of "none" (restricted), unlike the other sensitive endpoints
    // (default "unrestricted").
    //Without this distinction, the rule generates false positives for these two endpoints when
    // no explicit configuration exists (BL-11).
    // "restart" joins them for the same reason, confirmed against its own source rather than
    // assumed from the Boot 3.4/3.5 changelog above (which only covers Actuator-core defaults):
    // RestartEndpoint (Spring Cloud Context, org.springframework.cloud.context.restart) is
    // annotated @Endpoint(id="restart", enableByDefault=false) -- disabled unless explicitly
    // opted into, same shape as shutdown/heapdump. Without this, exposure.include=* would flag
    // "restart" as unrestricted on every plain Spring Boot app, including ones with no
    // spring-cloud-context on the classpath at all, where the property is a pure no-op.
    private static final Set<String> RESTRICTED_BY_DEFAULT = Set.of("shutdown", "heapdump", "restart");

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

        // Deliberately NOT gated on hasWildcardExposure: exposure.include can list sensitive
        // endpoints explicitly without a wildcard (e.g. "threaddump,beans"), and isEndpointReachable()
        // already covers both forms -- gating here would leave that explicit-list path unchecked,
        // even though endpoints unrestricted by default (threaddump/beans/env/configprops) are just
        // as reachable that way as under a wildcard.
        List<String> stillEnabled = new ArrayList<>();
        for (String endpoint : SENSITIVE_ENDPOINTS) {
            if (isEndpointReachable(config, endpoint) && !isRestricted(config, endpoint)) {
                stillEnabled.add(endpoint);
            }
        }

        if (!stillEnabled.isEmpty()) {
            findings.add(new Finding(
                    id(),
                    Severity.HIGH,
                    buildSensitiveEndpointsMessage(hasWildcardExposure, stillEnabled),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }

        // Independent of the stillEnabled finding above: exposure.include can list env/configprops
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

    private String buildSensitiveEndpointsMessage(boolean hasWildcardExposure, List<String> stillEnabled) {
        String exposureDescription = hasWildcardExposure
                ? "%s contains '*' and exposes all endpoints via HTTP".formatted(EXPOSURE_KEY)
                : "%s explicitly lists sensitive endpoints".formatted(EXPOSURE_KEY);

        return exposureDescription + ", and the following remain unrestricted: %s. "
                .formatted(String.join(", ", stillEnabled))
                + "Endpoint structure and property names are disclosed regardless of show-values; "
                + "raw values stay masked unless show-values is also elevated (see SCG001's separate "
                + "show-values finding, if any). "
                + "Consider setting management.endpoint.<name>.access=none for each one"
                + (hasWildcardExposure ? ", or replacing '*' with an explicit list." : ".");
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