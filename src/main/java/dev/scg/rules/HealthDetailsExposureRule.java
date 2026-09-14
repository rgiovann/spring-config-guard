package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * SCG013 — detects {@code management.endpoint.health.show-details} set to {@code always} or
 * {@code when-authorized}.
 * <p>
 * Unlike the sensitive endpoints covered by {@link ActuatorExposureRule} (SCG001), {@code health}
 * is exposed by default in Spring Boot — {@code management.endpoints.web.exposure.include} itself
 * defaults to {@code health} — so no wildcard or explicit inclusion is needed for this property to
 * matter. {@code show-details} defaults to {@code never} (safe); once elevated, the health response
 * body includes each {@code HealthIndicator}'s detail map: disk space thresholds and free space,
 * datasource/queue up-down status, and any custom indicator's own detail keys, which commonly leak
 * internal hostnames, driver/version strings, or topology of downstream dependencies to an
 * unauthenticated caller.
 * <p>
 * {@code when-authorized} is treated as equally risky as {@code always}, same reasoning already
 * applied to {@code show-values} in {@link ActuatorExposureRule}: its actual safety depends on a
 * runtime {@code SecurityContext} this tool has no visibility into, so the opt-out from the safe
 * {@code never} default is itself the signal.
 * <p>
 * Severity is {@link Severity#MEDIUM}, not {@link Severity#HIGH}: standard health indicators
 * disclose operational status and infrastructure metadata, not credentials or secret values —
 * unlike SCG001's HIGH, which is driven by endpoints that can expose actual secrets in memory
 * (heapdump) or full application internals (env, beans). This matches the calibration already used
 * for other info-disclosure-without-compromise findings (e.g. {@code CorsInsecureProtocolsRule},
 * {@code SwaggerOpenApiExposedRule}).
 * <p>
 * DELIBERATE SCOPE DECISION: this rule does not check whether the {@code health} endpoint is itself
 * restricted (e.g. {@code management.endpoint.health.access=none}, {@code .enabled=false}, or
 * excluded via {@code management.endpoints.web.exposure.exclude}). Setting {@code show-details} to
 * a risky value while also disabling the only endpoint it affects is a self-contradictory
 * configuration that is not a realistic authoring pattern, so the added complexity of replicating
 * {@link ActuatorExposureRule}'s restriction logic here was judged not worth it. Revisit if this
 * proves to be a real false-positive source in practice.
 * <p>
 * No profile exemption (Zero-Trust), consistent with {@link ActuatorExposureRule}. Plain
 * {@link Rule}, not {@link ConfigurableRule}: {@code never}/{@code when-authorized}/{@code always}
 * are fixed values of Spring Boot's own {@code Show} enum, not something a consumer of this tool
 * would ever need to override.
 * <p>
 * Value matching mirrors Spring Boot's own lenient enum binding rather than enumerating
 * separator variants by hand: {@code LenientObjectToEnumConverterFactory.getCanonicalName()}
 * (spring-boot-project/spring-boot, {@code org.springframework.boot.convert} package) reduces
 * both the source string and the enum constant name to letters/digits only, lowercased, before
 * comparing — so {@code when-authorized}, {@code when_authorized}, {@code whenAuthorized}, and
 * {@code WHEN-AUTHORIZED} all bind to the same constant. A fixed {@code Set} of separator
 * variants compared via {@code toUpperCase()} would miss {@code whenAuthorized} (canonicalizes
 * to {@code whenauthorized}, no separator survives to match a set entry written with one) —
 * {@link #canonicalize(String)} replicates the real algorithm instead.
 */
public final class HealthDetailsExposureRule implements Rule {

    private static final String RULE_NAME = "SCG013";

    private static final String SHOW_DETAILS_KEY = "management.endpoint.health.show-details";

    private static final Set<String> RISKY_CANONICAL_VALUES = Set.of("always", "whenauthorized");

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Actuator health endpoint discloses component details via management.endpoint.health.show-details";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        String raw = RelaxedProperties.get(config.properties(), SHOW_DETAILS_KEY);
        if (raw == null || raw.isBlank()) {
            return findings;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(new Finding(
                    id(),
                    Severity.INFO,
                    ("Actuator property '%s' relies on an unresolved environment placeholder '%s'. " +
                            "Static analysis cannot verify whether health component details are exposed at runtime.")
                            .formatted(SHOW_DETAILS_KEY, raw),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
            return findings;
        }

        String value = resolved.get().strip();
        if (!RISKY_CANONICAL_VALUES.contains(canonicalize(value))) {
            return findings;
        }

        findings.add(new Finding(
                id(),
                Severity.MEDIUM,
                ("'%s=%s' exposes health indicator details (disk space, datasource/queue status, custom " +
                        "indicators) to any caller reaching /actuator/health, which is exposed by default in " +
                        "Spring Boot. Set this to 'never' unless authenticated access to component details is " +
                        "a deliberate, justified requirement.")
                        .formatted(SHOW_DETAILS_KEY, raw),
                config.sourceFile().toString(),
                config.profileLabel()
        ));

        return findings;
    }

    /**
     * Same reduction as Spring Boot's {@code LenientObjectToEnumConverterFactory.getCanonicalName()}:
     * keep only letters/digits, lowercase — so separator style (hyphen/underscore/none) and casing
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
}
