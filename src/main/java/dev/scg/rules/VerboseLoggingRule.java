package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * SCG009 — detects Spring Boot's own verbose-logging switches left enabled:
 * {@code debug=true}, {@code trace=true}, or {@code logging.level.root=DEBUG|TRACE}.
 * <p>
 * All three default to a safe, non-verbose state and must be explicitly set to become
 * risky — same opt-in shape as {@link H2ConsoleExposedRule}. {@code debug}/{@code trace}
 * elevate a core set of framework loggers (web, security, SQL) to a highly detailed
 * level; {@code logging.level.root} at DEBUG/TRACE goes further and applies to every
 * logger in the application, including third-party libraries. Either can leak request/
 * response bodies, SQL statements with bound parameters, or session/security internals
 * into application logs.
 * <p>
 * Deliberately scoped to these three keys only — not per-package
 * {@code logging.level.<package>} overrides, which are common and usually benign, and
 * not {@code server.error.*} response verbosity, which is a different Spring Boot
 * subsystem (HTTP error responses, reachable by any anonymous request) with a different
 * exploitation vector than log-file verbosity (requires access to the logs). That is
 * covered separately by the error-response rule (SCG010) rather than merged here.
 * <p>
 * No profile exemption (Zero-Trust), consistent with {@link H2ConsoleExposedRule} and
 * {@link ActuatorExposureRule}: a profile labeled "dev" can still run against shared or
 * staging infrastructure, so verbose logging enabled there is still a real risk, not a
 * suppressed one.
 * <p>
 * Plain {@link Rule}, not {@link ConfigurableRule}: these three property names are fixed
 * Spring Boot facts, not an open-ended or org-specific list.
 */
public final class VerboseLoggingRule implements Rule {

    private static final String RULE_NAME = "SCG009";

    private static final String DEBUG_KEY = "debug";
    private static final String TRACE_KEY = "trace";
    private static final String LOG_LEVEL_ROOT_KEY = "logging.level.root";

    private static final Set<String> RISKY_LOG_LEVELS = Set.of("DEBUG", "TRACE");

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Verbose logging enabled via debug/trace or a DEBUG/TRACE root logger level";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        checkBooleanFlag(config, DEBUG_KEY, findings);
        checkBooleanFlag(config, TRACE_KEY, findings);
        checkLogLevelRoot(config, findings);

        return findings;
    }

    private void checkBooleanFlag(EffectiveConfig config, String key, List<Finding> findings) {
        String raw = RelaxedProperties.get(config.properties(), key);
        if (raw == null || raw.isBlank()) {
            return;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(key, raw, config));
            return;
        }

        // RelaxedBoolean.isTruthy() re-resolves internally, but the value is already
        // placeholder-free at this point, so the call is a no-op wrapper around the
        // TRUTHY_VALUES check (true/yes/on/1) — reused here instead of duplicating that set.
        if (!RelaxedBoolean.isTruthy(resolved.get())) {
            return;
        }

        findings.add(new Finding(
                id(),
                Severity.MEDIUM,
                ("Verbose mode enabled via '%s=%s'. This elevates core framework loggers " +
                        "(web, security, SQL) to a highly detailed level, which can leak request/response " +
                        "bodies, SQL statements with bound parameters, or session/security internals into " +
                        "application logs. Keep this unset (or false) outside local troubleshooting.")
                        .formatted(key, raw),
                config.sourceFile().toString(),
                config.profileLabel()
        ));
    }

    private void checkLogLevelRoot(EffectiveConfig config, List<Finding> findings) {
        String raw = RelaxedProperties.get(config.properties(), LOG_LEVEL_ROOT_KEY);
        if (raw == null || raw.isBlank()) {
            return;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(LOG_LEVEL_ROOT_KEY, raw, config));
            return;
        }

        String level = resolved.get().strip().toUpperCase(Locale.ROOT);
        if (!RISKY_LOG_LEVELS.contains(level)) {
            return;
        }

        findings.add(new Finding(
                id(),
                Severity.MEDIUM,
                ("Root logger level set to '%s' via '%s'. This applies to every logger in the " +
                        "application, including third-party libraries, which can leak request/response " +
                        "bodies, SQL statements with bound parameters, or session/security internals into " +
                        "application logs. Restrict verbose levels to specific, deliberately chosen loggers " +
                        "instead of the root logger.")
                        .formatted(level, LOG_LEVEL_ROOT_KEY),
                config.sourceFile().toString(),
                config.profileLabel()
        ));
    }

    private Finding unresolvedPlaceholderFinding(String key, String rawValue, EffectiveConfig config) {
        return new Finding(
                id(),
                Severity.INFO,
                ("Verbose logging property '%s' relies on an unresolved environment placeholder '%s'. " +
                        "Static analysis cannot verify the runtime value; ensure verbose logging is not " +
                        "enabled in production.")
                        .formatted(key, rawValue),
                config.sourceFile().toString(),
                config.profileLabel()
        );
    }
}
