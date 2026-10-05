package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * SCG013 — detects the health endpoint, or one of its groups, showing component details or
 * component names: {@code management.endpoint.health.show-details} and {@code show-components},
 * and the same two keys under {@code management.endpoint.health.group.<name>}.
 * <p>
 * Unlike the sensitive endpoints covered by {@link ActuatorExposureRule} (SCG001), {@code health}
 * is exposed by default in Spring Boot — {@code management.endpoints.web.exposure.include} itself
 * defaults to {@code health} — so no wildcard or explicit inclusion is needed for these properties to
 * matter. What each setting returns was measured in running Spring Boot 4.1.1 apps with Actuator and
 * a datasource, without and with Spring Security (VALIDATION.md, "SCG013 health details scenarios"):
 * <ul>
 *     <li>{@code show-details=always} returned every component's details to an anonymous caller:
 *     the database vendor, diskSpace's absolute path and free space, the SSL chains. That is
 *     {@link Severity#MEDIUM}: operational and infrastructure metadata, not credentials, unlike
 *     SCG001's HIGH endpoints (heapdump, env).</li>
 *     <li>{@code when-authorized} returned nothing extra to an anonymous caller, with or without
 *     Spring Security; only an authenticated user got the details, and {@code roles} narrowed that
 *     to the users with one of those roles. Whether that is a risk depends on who can authenticate,
 *     which static analysis can't see, so it is {@link Severity#INFO}.</li>
 *     <li>{@code show-components} defaults to {@code show-details}. Set on its own, it returned the
 *     components' names and status without details: {@link Severity#INFO}, a much smaller
 *     disclosure. Set to {@code never}, it hid the details too, whatever {@code show-details} says.
 *     So the level reported is the lower of the two.</li>
 *     <li>A health group ({@code management.endpoint.health.group.<name>}) has its own
 *     {@code show-details} and {@code show-components}, served at {@code /actuator/health/<name>}
 *     and at its {@code additional-path}, which can be on the main server port (e.g.
 *     {@code server:/healthz}); a key a group doesn't set, or sets to an empty value, falls back
 *     to the endpoint's. A group is reported when it sets one of the two keys itself, so the
 *     endpoint's own setting isn't reported once per group.</li>
 *     <li>A value Spring Boot can't bind ({@code true}) stopped the app from starting, so it is
 *     treated like {@code never}.</li>
 * </ul>
 * <p>
 * DELIBERATE SCOPE DECISION: this rule does not check whether the {@code health} endpoint is itself
 * restricted (e.g. {@code management.endpoint.health.access=none}, or excluded via
 * {@code management.endpoints.web.exposure.exclude}). Measured, both return 404 and the finding is
 * then a false positive; but setting {@code show-details} while disabling the only endpoint it
 * affects is a self-contradictory configuration, not a realistic authoring pattern, so replicating
 * {@link ActuatorExposureRule}'s restriction logic here was judged not worth it. Revisit if this
 * proves to be a real false-positive source in practice.
 * <p>
 * No profile exemption (Zero-Trust), consistent with {@link ActuatorExposureRule}. Plain
 * {@link Rule}, not {@link ConfigurableRule}: {@code never}/{@code when-authorized}/{@code always}
 * are fixed values of Spring Boot's own {@code Show} enum.
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

    private static final String HEALTH_PREFIX = "management.endpoint.health";
    private static final String GROUP_PREFIX = HEALTH_PREFIX + ".group.";
    private static final String HEALTH_PATH = "/actuator/health";

    /** Spring Boot's {@code Show} values, least to most permissive. */
    private enum Show {
        NEVER, WHEN_AUTHORIZED, ALWAYS;

        static Show lower(Show a, Show b) {
            return a.ordinal() <= b.ordinal() ? a : b;
        }
    }

    /**
     * One key's value: its level, or empty when it is an unresolved placeholder. {@code raw} is null
     * when the key isn't set; an empty value counts as not set, as Spring Boot binds it to nothing
     * (a group with an empty {@code show-details} took the endpoint's). {@code inherited} marks a
     * group's value taken from the endpoint, whose own finding already covers it.
     */
    private record Setting(String key, String raw, Optional<Show> show, boolean inherited) {

        boolean isSet() {
            return raw != null;
        }

        Setting inheritedBy() {
            return new Setting(key, raw, show, true);
        }
    }

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Actuator health endpoint or health group discloses component details via show-details/show-components";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();
        Map<String, String> properties = config.properties();

        Setting details = setting(properties, HEALTH_PREFIX + ".show-details");
        Setting components = setting(properties, HEALTH_PREFIX + ".show-components");
        String roles = roles(properties, HEALTH_PREFIX + ".roles");
        checkScope(config, "The health endpoint (" + HEALTH_PATH + ")", details, components, roles, findings);

        for (String group : groupNames(properties)) {
            String prefix = GROUP_PREFIX + group;
            Setting groupDetails = setting(properties, prefix + ".show-details");
            Setting groupComponents = setting(properties, prefix + ".show-components");
            if (!groupDetails.isSet() && !groupComponents.isSet()) {
                continue;
            }
            String additionalPath = RelaxedProperties.get(properties, prefix + ".additional-path");
            String where = "Health group '%s' (%s/%s%s)".formatted(group, HEALTH_PATH, group,
                    additionalPath == null || additionalPath.isBlank() ? "" : ", and " + additionalPath);
            String groupRoles = roles(properties, prefix + ".roles");
            checkScope(config, where,
                    groupDetails.isSet() ? groupDetails : details.inheritedBy(),
                    groupComponents.isSet() ? groupComponents : components.inheritedBy(),
                    groupRoles == null ? roles : groupRoles,
                    findings);
        }
        return findings;
    }

    private void checkScope(EffectiveConfig config, String where, Setting details, Setting components,
                            String roles, List<Finding> findings) {
        // show-components=never hid the details whatever show-details says (C2): nothing to report,
        // even when show-details is a placeholder that can't be resolved.
        if (components.isSet() && components.show().equals(Optional.of(Show.NEVER))) {
            return;
        }
        boolean unresolved = false;
        for (Setting setting : List.of(details, components)) {
            if (setting.isSet() && setting.show().isEmpty()) {
                unresolved = true;
                if (setting.inherited()) {
                    continue; // the endpoint's own finding already reports it
                }
                findings.add(finding(Severity.INFO,
                        ("%s: '%s' relies on an unresolved environment placeholder '%s'. Static analysis cannot " +
                                "verify whether health component details are exposed at runtime.")
                                .formatted(where, setting.key(), setting.raw()),
                        config));
            }
        }
        if (unresolved) {
            return;
        }

        Show detailsLevel = details.show().orElse(Show.NEVER);
        Show componentsLevel = components.isSet() ? components.show().orElse(Show.NEVER) : detailsLevel;
        Show shown = Show.lower(detailsLevel, componentsLevel);
        String setBy = describe(details, components);

        if (shown == Show.ALWAYS) {
            findings.add(finding(Severity.MEDIUM,
                    ("%s returns health component details (database vendor, disk path and free space, SSL chains, " +
                            "custom indicators) to any caller, via %s. Set show-details to 'never' unless they are " +
                            "a deliberate requirement.").formatted(where, setBy),
                    config));
        } else if (shown == Show.WHEN_AUTHORIZED) {
            findings.add(finding(Severity.INFO,
                    ("%s returns health component details to authenticated users%s, via %s; anonymous callers get " +
                            "the status only. Check who can authenticate.")
                            .formatted(where, rolesNote(roles), setBy),
                    config));
        } else if (componentsLevel != Show.NEVER) {
            findings.add(finding(Severity.INFO,
                    ("%s returns the names and status of its components, without details, to %s, via %s.")
                            .formatted(where, componentsLevel == Show.ALWAYS
                                    ? "any caller"
                                    : "authenticated users" + rolesNote(roles), setBy),
                    config));
        }
    }

    private static String describe(Setting details, Setting components) {
        List<String> parts = new ArrayList<>();
        for (Setting setting : List.of(details, components)) {
            if (setting.isSet()) {
                parts.add("'%s=%s'".formatted(setting.key(), setting.raw()));
            }
        }
        return String.join(" and ", parts);
    }

    private static String rolesNote(String roles) {
        return roles == null || roles.isBlank() ? "" : " with one of the roles '" + roles + "'";
    }

    private static Setting setting(Map<String, String> properties, String key) {
        String raw = RelaxedProperties.get(properties, key);
        if (raw == null || raw.isBlank()) {
            return new Setting(key, null, Optional.of(Show.NEVER), false);
        }
        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            return new Setting(key, raw, Optional.empty(), false);
        }
        if (resolved.get().isBlank()) {
            return new Setting(key, null, Optional.of(Show.NEVER), false);
        }
        Show show = switch (canonicalize(resolved.get())) {
            case "always" -> Show.ALWAYS;
            case "whenauthorized" -> Show.WHEN_AUTHORIZED;
            default -> Show.NEVER; // never, or a value Spring Boot can't bind: the app doesn't start
        };
        return new Setting(key, raw, Optional.of(show), false);
    }

    /** The roles, written as a comma-separated value or a list; null when none is set. */
    private static String roles(Map<String, String> properties, String key) {
        List<String> roles = RelaxedProperties.valuesForKeyOrListChildren(properties, key).stream()
                .filter(role -> role != null && !role.isBlank())
                .toList();
        return roles.isEmpty() ? null : String.join(",", roles);
    }

    /**
     * The names of the groups that set {@code show-details} or {@code show-components}, as written
     * and in a stable order. A name is everything between {@code group.} and the key's last segment,
     * so a name with a dot ({@code group[a.b]}, which ConfigLoader writes as {@code group.a.b}) stays
     * whole.
     */
    private static Set<String> groupNames(Map<String, String> properties) {
        String canonicalPrefix = RelaxedProperties.canonicalize(GROUP_PREFIX);
        Set<String> names = new TreeSet<>();
        for (String key : properties.keySet()) {
            String canonical = RelaxedProperties.canonicalize(key);
            if (!canonical.startsWith(canonicalPrefix)
                    || !(canonical.endsWith(".showdetails") || canonical.endsWith(".showcomponents"))) {
                continue;
            }
            int nameStart = ordinalIndexOf(key, '.', 4) + 1;
            int nameEnd = key.lastIndexOf('.');
            if (nameStart > 0 && nameEnd > nameStart) {
                names.add(key.substring(nameStart, nameEnd));
            }
        }
        return names;
    }

    private static int ordinalIndexOf(String text, char c, int ordinal) {
        int index = -1;
        for (int i = 0; i < ordinal; i++) {
            index = text.indexOf(c, index + 1);
            if (index < 0) {
                return -1;
            }
        }
        return index;
    }

    private Finding finding(Severity severity, String message, EffectiveConfig config) {
        return new Finding(id(), severity, message, config.sourceFile().toString(), config.profileLabel());
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
