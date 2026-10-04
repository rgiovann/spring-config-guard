package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * SCG010 — detects Spring Boot's HTTP error response verbosity switches left enabled:
 * {@code include-stacktrace}, {@code include-exception}, {@code include-message}, or
 * {@code include-binding-errors}, under either the {@code server.error.*} prefix or the
 * {@code spring.web.error.*} prefix. Spring Boot 4.0 renamed the first to the second, and each
 * prefix is read by one side of that line only: Spring Boot 4.1.1's configuration metadata marks
 * every {@code server.error.*} key deprecated at level {@code error} (no longer bound) since
 * 4.0.0, and in running apps Spring Boot 4.1.1 ignored all four {@code server.error.*} keys while
 * Spring Boot 3.5.16 ignored all four {@code spring.web.error.*} ones (VALIDATION.md, "SCG010
 * error response scenarios"). Static analysis doesn't know which version a project targets, so
 * both prefixes are checked at the same severity, and every message says which versions read
 * which prefix: on the other version the key is inert, and removing it is the fix. Lowering both
 * to {@code INFO} instead would hide the key that does take effect. The keys come from
 * {@link ConfigurableRule} metadata ({@code rules-metadata/SCG010.yml}) rather than code, since a
 * Spring Boot major version already proved these names aren't fixed.
 * <p>
 * Spring Boot builds the error response of an unhandled exception from these switches, in Spring
 * MVC's {@code BasicErrorController} and WebFlux's error handler alike (both measured). Exposing
 * stack traces, exception class names, internal messages, or detailed binding errors to HTTP
 * clients is Information Disclosure (CWE-209). {@code on-param} is no safer than {@code always}:
 * any caller gets the attribute by adding its query parameter ({@code trace}, {@code message},
 * {@code errors}) with any value other than {@code false} in any case, even an empty one.
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
 * properties default to a safe state and must be explicitly set to become risky; measured in
 * running apps, the defaults return none of the four attributes, so an absent key is silent.
 * A value Spring Boot can't bind ({@code true} or an unquoted YAML {@code on} for an enum,
 * {@code always} or an empty value for {@code include-exception}) stops the application from
 * starting, so it can never leak anything and is silent too.
 * <p>
 * Follows the same 3-state environment placeholder resolution language as {@link VerboseLoggingRule}:
 * <ul>
 *     <li>Unresolved placeholder → {@link Severity#INFO} warning.</li>
 *     <li>Resolved to a risky value → {@link Severity#MEDIUM}.</li>
 *     <li>Resolved to a safe value ({@code never}/{@code false}) or absent → Silent.</li>
 * </ul>
 * All four are {@code MEDIUM}: each is information disclosure without compromise, which is
 * {@code MEDIUM} in this project's severity scale. {@code include-stacktrace} is not
 * {@code HIGH}: a stack trace carries the exception's message and its cause chain, so it
 * discloses more of the same kind of data {@code include-message} does, not a different kind of
 * risk. {@code include-binding-errors} is not {@code LOW} either: unlike this project's
 * {@code LOW} precedent (CORS exposing {@code Set-Cookie}, which browsers block from script
 * access regardless of the config), an enabled binding-errors leak really does disclose DTO
 * field names and validation rules to the caller.
 * <p>
 * No profile exemption (Zero-Trust), consistent with {@link VerboseLoggingRule}.
 *
 * @see ConfigurableRule
 */
public final class VerboseErrorResponseRule implements ConfigurableRule {

    private static final String RULE_NAME = "SCG010";

    // Matches Spring Boot's own lenient enum binding rather than enumerating separator variants
    // by hand: LenientObjectToEnumConverterFactory.getCanonicalName() (org.springframework.boot.convert)
    // reduces both the source string and the enum constant name to letters/digits only, lowercased,
    // before comparing -- so "on-param", "on_param", and "onParam" all bind to the same constant.
    // A Set of separator variants compared via toUpperCase() (this rule's original approach)
    // misses "onParam": it canonicalizes to "onparam", which has no separator left to match a set
    // entry written with one. Same fix already applied to ActuatorExposureRule (SCG001) and
    // HealthDetailsExposureRule (SCG013).
    private static final Set<String> RISKY_CANONICAL_ENUM_VALUES = Set.of("always", "onparam");

    private static final String VERSION_NOTE =
            " Spring Boot reads server.error.* before 4.0 and spring.web.error.* from 4.0 on; " +
                    "if your version doesn't read this key, remove it.";

    private List<String> includeStacktraceKeys;
    private List<String> includeExceptionKeys;
    private List<String> includeMessageKeys;
    private List<String> includeBindingErrorsKeys;

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Verbose HTTP error responses enabled via server.error.include-* or spring.web.error.include-* properties";
    }

    @Override
    public void configure(Map<String, List<String>> metadata) {
        Objects.requireNonNull(metadata, RULE_NAME + " metadata map cannot be null");

        includeStacktraceKeys = requireKeys(metadata, "include-stacktrace-keys");
        includeExceptionKeys = requireKeys(metadata, "include-exception-keys");
        includeMessageKeys = requireKeys(metadata, "include-message-keys");
        includeBindingErrorsKeys = requireKeys(metadata, "include-binding-errors-keys");
    }

    private List<String> requireKeys(Map<String, List<String>> metadata, String metadataKey) {
        List<String> keys = metadata.get(metadataKey);
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: '" + metadataKey + "' is missing or empty.");
        }
        return List.copyOf(keys);
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        ensureConfigured();

        List<Finding> findings = new ArrayList<>();

        checkEnumProperty(config, includeStacktraceKeys, Severity.MEDIUM,
                "Stack traces are returned in HTTP error responses via '%s=%s' (with on-param, to any caller that adds a 'trace' query parameter). " +
                        "A stack trace carries the exception's message and its cause chain, internal class names, line numbers, and third-party library versions. " +
                        "Set this to 'never'.",
                findings);

        checkBooleanProperty(config, includeExceptionKeys, Severity.MEDIUM,
                "Java exception class names are exposed in HTTP error responses via '%s=%s'. " +
                        "This leaks internal architectural details and framework choices to callers. " +
                        "Disable this by setting the property to false.",
                findings);

        checkEnumProperty(config, includeMessageKeys, Severity.MEDIUM,
                "Internal exception messages are exposed in HTTP error responses via '%s=%s'. " +
                        "Unwrapped exception messages often contain SQL queries, failed validation details, or internal state" +
                        " (with on-param, any caller gets them by adding a 'message' query parameter). " +
                        "Set this to 'never' and handle user-facing error messages explicitly.",
                findings);

        checkEnumProperty(config, includeBindingErrorsKeys, Severity.MEDIUM,
                "Detailed field validation binding errors are exposed in HTTP error responses via '%s=%s'. " +
                        "This exposes internal DTO field names and validation rules to the caller" +
                        " (with on-param, to any caller that adds an 'errors' query parameter). " +
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
    private void checkEnumProperty(EffectiveConfig config, List<String> keys, Severity severity,
                                   String messageTemplate, List<Finding> findings) {
        checkProperty(config, keys, severity, messageTemplate,
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
     * {@code boolean}, not the {@code IncludeAttribute} enum. The value reaching the predicate is
     * already resolved ({@link #checkSingleKey}), so it is matched as a literal.
     */
    private void checkBooleanProperty(EffectiveConfig config, List<String> keys, Severity severity,
                                      String messageTemplate, List<Finding> findings) {
        checkProperty(config, keys, severity, messageTemplate, RelaxedBoolean::isTrueLiteral, findings);
    }

    /**
     * Checks every key alias for one logical property independently (e.g. both the
     * {@code server.error.*} and {@code spring.web.error.*} spellings) -- a project could only
     * realistically have one of the two prefixes bound at runtime, but static analysis doesn't
     * know which Spring Boot major version a given project targets, so both are evaluated the
     * same way relaxed binding already handles casing variants of a single key.
     */
    private void checkProperty(EffectiveConfig config, List<String> keys, Severity severity,
                               String messageTemplate, Predicate<String> isRisky,
                               List<Finding> findings) {
        for (String key : keys) {
            checkSingleKey(config, key, severity, messageTemplate, isRisky, findings);
        }
    }

    private void checkSingleKey(EffectiveConfig config, String key, Severity severity,
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
                messageTemplate.formatted(key, raw) + VERSION_NOTE,
                config.sourceFile().toString(),
                config.profileLabel()
        ));
    }

    private Finding unresolvedPlaceholderFinding(String key, String rawValue, EffectiveConfig config) {
        return new Finding(
                id(),
                Severity.INFO,
                ("HTTP error response property '%s' relies on an unresolved environment placeholder '%s'. " +
                        "Static analysis cannot verify the runtime value; ensure it resolves to a safe value " +
                        "('never', or false for include-exception).")
                        .formatted(key, rawValue) + VERSION_NOTE,
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }

    private void ensureConfigured() {
        if (includeStacktraceKeys == null || includeExceptionKeys == null
                || includeMessageKeys == null || includeBindingErrorsKeys == null) {
            throw new IllegalStateException("Rule " + RULE_NAME + " must be configured before execution.");
        }
    }
}
