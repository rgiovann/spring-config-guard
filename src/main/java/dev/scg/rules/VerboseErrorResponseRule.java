package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * SCG010 — detects Spring Boot's HTTP error response verbosity switches left enabled:
 * {@code server.error.include-stacktrace}, {@code server.error.include-exception},
 * {@code server.error.include-message}, or {@code server.error.include-binding-errors}.
 * <p>
 * Spring Boot's {@code BasicErrorController} constructs default JSON error payloads for
 * unhandled HTTP errors. Exposing stack traces, exception class names, internal messages,
 * or detailed binding errors directly to HTTP clients leads to Information Disclosure
 * (CWE-209). In particular, values like {@code ON_PARAM} allow any anonymous user to trigger
 * full stack trace leaks on demand by appending {@code ?trace=true} to the request URL.
 * <p>
 * These four properties are NOT type-uniform, and the risky-value check must not treat them
 * as if they were. Confirmed against the real {@code ErrorProperties} class (Spring Boot API
 * docs, current and 2.3.0.RELEASE): {@code include-exception} is a plain {@code boolean}
 * ({@code isIncludeException()}/{@code setIncludeException(boolean)}), while
 * {@code include-stacktrace}, {@code include-message}, and {@code include-binding-errors} all
 * share the same {@code ErrorProperties.IncludeAttribute} enum ({@code never}/{@code always}/
 * {@code on-param}) — a boolean-truthy value such as {@code true} is not a valid value for the
 * enum-typed properties and would fail Spring Boot's own binding at startup, not silently
 * behave like {@code always}. Confirmed against the official Spring Boot 2.3 Release Notes
 * (spring-projects/spring-boot wiki) that {@code include-message} and
 * {@code include-binding-errors} were changed to default {@code never} specifically for
 * security — "The error message and any binding errors are no longer included in the default
 * error page by default. This reduces the risk of leaking information to a client." All four
 * properties default to a safe state and must be explicitly set to become risky.
 * <p>
 * Follows the same 3-state environment placeholder resolution language as {@link VerboseLoggingRule}:
 * <ul>
 *     <li>Unresolved placeholder → {@link Severity#INFO} warning.</li>
 *     <li>Resolved to a risky value → {@link Severity#HIGH} or {@link Severity#MEDIUM}.</li>
 *     <li>Resolved to a safe value ({@code never}/{@code false}) or absent → Silent.</li>
 * </ul>
 * {@code include-binding-errors} is {@code MEDIUM}, not a lesser {@code LOW}: unlike this
 * project's actual {@code LOW} precedent (CORS exposing {@code Set-Cookie}, which browsers
 * block from script access regardless of the config), an enabled binding-errors leak really
 * does disclose DTO field names and validation rules to the caller — smaller blast radius than
 * a full stack trace, but not an ineffective misconfiguration, so it belongs in the same tier
 * as {@code include-exception}/{@code include-message} rather than in {@code LOW}.
 * <p>
 * No profile exemption (Zero-Trust), consistent with {@link VerboseLoggingRule}. Plain {@link Rule},
 * not {@link ConfigurableRule}, as these key names are fixed Spring Boot facts.
 */
public final class VerboseErrorResponseRule implements Rule {

    private static final String RULE_NAME = "SCG010";

    private static final String INCLUDE_STACKTRACE_KEY = "server.error.include-stacktrace";
    private static final String INCLUDE_EXCEPTION_KEY = "server.error.include-exception";
    private static final String INCLUDE_MESSAGE_KEY = "server.error.include-message";
    private static final String INCLUDE_BINDING_ERRORS_KEY = "server.error.include-binding-errors";

    // Matches Spring Boot's own lenient enum binding rather than enumerating separator variants
    // by hand: LenientObjectToEnumConverterFactory.getCanonicalName() (org.springframework.boot.convert)
    // reduces both the source string and the enum constant name to letters/digits only, lowercased,
    // before comparing -- so "on-param", "on_param", and "onParam" all bind to the same constant.
    // A Set of separator variants compared via toUpperCase() (this rule's original approach)
    // misses "onParam": it canonicalizes to "onparam", which has no separator left to match a set
    // entry written with one. Same fix already applied to ActuatorExposureRule (SCG001) and
    // HealthDetailsExposureRule (SCG013).
    private static final Set<String> RISKY_CANONICAL_ENUM_VALUES = Set.of("always", "onparam");

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Verbose HTTP error responses enabled via server.error.include-* properties";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        checkEnumProperty(config, INCLUDE_STACKTRACE_KEY, Severity.HIGH,
                "Full stack traces are returned in HTTP error responses via '%s=%s' (or triggerable via query parameters). " +
                        "This exposes internal class names, line numbers, third-party library versions, and nested exception details to unauthenticated callers. " +
                        "Set this to 'never' in production environments.",
                findings);

        checkBooleanProperty(config, INCLUDE_EXCEPTION_KEY, Severity.MEDIUM,
                "Java exception class names are exposed in HTTP error responses via '%s=%s'. " +
                        "This leaks internal architectural details and framework choices to callers. " +
                        "Disable this by setting the property to false.",
                findings);

        checkEnumProperty(config, INCLUDE_MESSAGE_KEY, Severity.MEDIUM,
                "Internal exception messages are exposed in HTTP error responses via '%s=%s'. " +
                        "Unwrapped exception messages often contain SQL queries, failed validation details, or internal state. " +
                        "Set this to 'never' and handle user-facing error messages explicitly.",
                findings);

        checkEnumProperty(config, INCLUDE_BINDING_ERRORS_KEY, Severity.MEDIUM,
                "Detailed field validation binding errors are exposed in HTTP error responses via '%s=%s'. " +
                        "This exposes internal DTO field names and validation rules to the caller. " +
                        "Set this to 'never' unless the API is explicitly designed to surface field-level errors.",
                findings);

        return findings;
    }

    /**
     * For {@code include-stacktrace}/{@code include-message}/{@code include-binding-errors} —
     * all three bind to {@code ErrorProperties.IncludeAttribute}, so only {@code always}/
     * {@code on-param} are valid risky values. A boolean-truthy string like {@code true} is not
     * a value this property accepts; treating it as risky here would misreport a broken,
     * non-binding configuration as a confirmed information-disclosure finding.
     */
    private void checkEnumProperty(EffectiveConfig config, String key, Severity severity,
                                   String messageTemplate, List<Finding> findings) {
        checkProperty(config, key, severity, messageTemplate,
                value -> RISKY_CANONICAL_ENUM_VALUES.contains(canonicalize(value)),
                findings);
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

    /**
     * For {@code include-exception} only — the one property among the four that is a genuine
     * {@code boolean}, not the {@code IncludeAttribute} enum.
     */
    private void checkBooleanProperty(EffectiveConfig config, String key, Severity severity,
                                      String messageTemplate, List<Finding> findings) {
        checkProperty(config, key, severity, messageTemplate, RelaxedBoolean::isTruthy, findings);
    }

    private void checkProperty(EffectiveConfig config, String key, Severity severity,
                               String messageTemplate, Predicate<String> isRisky,
                               List<Finding> findings) {
        String raw = RelaxedProperties.get(config.properties(), key);
        if (raw == null || raw.isBlank()) {
            return;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(key, raw, config));
            return;
        }

        String value = resolved.get().strip();
        if (!isRisky.test(value)) {
            return;
        }

        findings.add(new Finding(
                id(),
                severity,
                messageTemplate.formatted(key, raw),
                config.sourceFile().toString(),
                config.profileLabel()
        ));
    }

    private Finding unresolvedPlaceholderFinding(String key, String rawValue, EffectiveConfig config) {
        return new Finding(
                id(),
                Severity.INFO,
                ("HTTP error response property '%s' relies on an unresolved environment placeholder '%s'. " +
                        "Static analysis cannot verify the runtime value; ensure verbose error responses are not " +
                        "enabled in production.")
                        .formatted(key, rawValue),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }
}