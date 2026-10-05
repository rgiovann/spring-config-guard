package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * SCG009 — detects logging that writes secrets from requests and queries to the application log:
 * Spring Boot's {@code debug} and {@code trace} switches, a {@code DEBUG}/{@code TRACE} root
 * logger, and a {@code DEBUG}/{@code TRACE} level on a logger known to write secrets at that level.
 * <p>
 * What each setting writes was measured in a running Spring Boot 4.1.1 app (Spring MVC,
 * JdbcTemplate and JPA, RestClient on Apache HttpClient 5) that receives one request with a secret
 * in its query string, Authorization header and body, binds secrets as SQL parameters, and sends
 * an outbound request with its own Authorization header and body (VALIDATION.md, "SCG009 verbose
 * logging scenarios"). All three settings default to a safe state, and nothing reached the log
 * with the defaults.
 * <ul>
 *     <li>{@code debug} sets Spring Boot's {@code web} and {@code sql} logger groups and
 *     {@code org.springframework.boot} to {@code DEBUG}; the log then held request query strings
 *     and request and response bodies. {@code trace} sets {@code org.springframework}, Tomcat,
 *     Catalina, Jetty and Hibernate's schema tool to {@code TRACE}, which added JdbcTemplate's bound
 *     parameter values. Spring Boot's {@code LoggingApplicationListener} reads both as raw strings
 *     and turns them on for any value except exactly {@code false}: {@code FALSE}, {@code off},
 *     {@code no}, {@code 0}, an empty value, a trailing space after {@code false} and a quoted YAML
 *     {@code "off"} all turned debug logging on. Unquoted YAML {@code off} and {@code no} are YAML
 *     booleans, loaded as {@code false}, and stay off. An explicit null is read as an empty value,
 *     so a key present with a null value (a profile overriding it with null) is on too.</li>
 *     <li>{@code logging.level.root=DEBUG} added outbound Authorization headers to that;
 *     {@code TRACE} added inbound Authorization headers and every bound parameter.</li>
 *     <li>For any other logger, the level applies to the logger and to its descendants without
 *     a level of their own: {@code logging.level.org=debug} wrote what {@code DispatcherServlet}
 *     and Apache HttpClient's loggers write at {@code DEBUG}, and nothing once
 *     {@code org.springframework.web} and {@code org.apache.hc} were set to {@code info}.
 *     {@link #SECRET_LOGGERS} lists the loggers that wrote a secret and the level at which they did.
 *     A logger that is one of them or an ancestor of one, or Spring Boot's {@code web} or
 *     {@code sql} group containing one, is {@link Severity#MEDIUM} when its level reaches that one's
 *     and no more specific logger in between has a level of its own. Any other logger at
 *     {@code DEBUG}/{@code TRACE} is {@link Severity#INFO}: what an application's own or a
 *     third-party logger writes at that level can't be known statically, so it may be a secret
 *     ({@code logging.level.sql=debug} wrote SQL without its parameters). Logger names are
 *     compared as written, since Spring Boot binds them case-sensitively.</li>
 * </ul>
 * Groups defined in the configuration ({@code logging.group.<name>}) are not expanded: a level on
 * such a group is {@code INFO} like any other unknown logger name, and a configuration that
 * redefines {@code web} or {@code sql} is still read with Spring Boot's members.
 * <p>
 * {@link Severity#MEDIUM}, not {@code HIGH}: the secrets reach whoever can read the application
 * log, an already privileged position, unlike a secret written in the repository (SCG006) or
 * exposed over the network. Unresolved placeholders are {@link Severity#INFO}. HTTP error
 * responses, which reach the caller, are SCG010's.
 * <p>
 * No profile exemption (Zero-Trust), consistent with {@link H2ConsoleExposedRule} and
 * {@link ActuatorExposureRule}: a profile labeled "dev" can still run against shared or
 * staging infrastructure, so verbose logging enabled there is still a real risk, not a
 * suppressed one.
 * <p>
 * Plain {@link Rule}, not {@link ConfigurableRule}: the switches are fixed Spring Boot facts, and
 * {@link #SECRET_LOGGERS} holds only what was measured, so it changes with a new measurement and
 * its test, not with a project's preferences.
 */
public final class VerboseLoggingRule implements Rule {

    private static final String RULE_NAME = "SCG009";

    private static final String DEBUG_KEY = "debug";
    private static final String TRACE_KEY = "trace";
    private static final String LOG_LEVEL_PREFIX = "logging.level.";
    private static final String ROOT_LOGGER = "root";

    /** A logger measured to write secrets to the log at {@code minLevel} or a more verbose level. */
    private record SecretLogger(String name, String minLevel, String writes) {
    }

    /**
     * The loggers that wrote a secret, each set alone to {@code minLevel} (VALIDATION.md, "SCG009
     * verbose logging scenarios", N15-N21 and N23).
     */
    private static final List<SecretLogger> SECRET_LOGGERS = List.of(
            new SecretLogger("org.springframework.web.servlet.DispatcherServlet", "DEBUG", "request query strings"),
            new SecretLogger("org.springframework.web.servlet.mvc.method.annotation.RequestResponseBodyMethodProcessor",
                    "DEBUG", "request and response bodies"),
            new SecretLogger("org.springframework.web.client.DefaultRestClient", "DEBUG", "outbound request bodies"),
            new SecretLogger("org.springframework.web.method.HandlerMethod", "TRACE",
                    "controller method arguments, query parameters and bodies included"),
            new SecretLogger("org.springframework.jdbc.core.StatementCreatorUtils", "TRACE",
                    "JdbcTemplate's bound parameter values"),
            new SecretLogger("org.hibernate.orm.jdbc.bind", "TRACE", "Hibernate's bound parameter values"),
            new SecretLogger("org.hibernate.orm.resource.registry", "TRACE", "Hibernate's bound parameter values"),
            new SecretLogger("org.apache.hc.client5.http.headers", "DEBUG", "outbound HTTP headers, Authorization included"),
            new SecretLogger("org.apache.hc.client5.http.wire", "DEBUG",
                    "outbound HTTP headers, Authorization included, and bodies"),
            new SecretLogger("org.apache.coyote.http11.Http11InputBuffer", "TRACE",
                    "raw inbound requests, Authorization headers and bodies included"));

    /** Spring Boot's predefined logger groups, from {@code LoggingApplicationListener}. */
    private static final Map<String, List<String>> SPRING_BOOT_GROUPS = Map.of(
            "web", List.of("org.springframework.core.codec", "org.springframework.http", "org.springframework.web",
                    "org.springframework.boot.actuate.endpoint.web",
                    "org.springframework.boot.web.servlet.ServletContextInitializerBeans"),
            "sql", List.of("org.springframework.jdbc.core", "org.hibernate.SQL", "org.jooq.tools.LoggerListener"));

    private static final String SWITCH_NOTE =
            " Spring Boot turns it on for any value except exactly 'false' (not 'FALSE', 'off', 'no' or empty); " +
                    "remove the key or set it to 'false'.";

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Verbose logging enabled via debug/trace or a DEBUG/TRACE level on the root logger or another logger";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        checkSwitch(config, DEBUG_KEY,
                "Debug logging enabled via '%s=%s': Spring Boot sets its web and sql logger groups and " +
                        "org.springframework.boot to DEBUG, which writes request query strings and request and " +
                        "response bodies to the application log.",
                findings);
        checkSwitch(config, TRACE_KEY,
                "Trace logging enabled via '%s=%s': Spring Boot sets org.springframework, Tomcat, Catalina, " +
                        "Jetty and Hibernate's schema tool to TRACE, which writes request query strings, request and response " +
                        "bodies, and JdbcTemplate's bound parameter values to the application log.",
                findings);
        checkLoggerLevels(config, findings);

        return findings;
    }

    /**
     * Mirrors {@code LoggingApplicationListener.isSet()}: on unless the value is exactly
     * {@code false}, compared without trimming or ignoring case. A key present with a null value
     * (explicit null in a profile) is read by Spring Boot as an empty value, so it is on.
     */
    private void checkSwitch(EffectiveConfig config, String key, String messageTemplate, List<Finding> findings) {
        Optional<String> actualKey = RelaxedProperties.findActualKey(config.properties(), key);
        if (actualKey.isEmpty()) {
            return;
        }
        String raw = config.properties().get(actualKey.get());
        String shown = raw == null ? "" : raw;

        Optional<String> resolved = raw == null ? Optional.of("") : EnvironmentPlaceholder.resolve(raw);
        if (resolved.isEmpty()) {
            findings.add(unresolvedPlaceholderFinding(key, raw, config));
            return;
        }
        if (resolved.get().equals("false")) {
            return;
        }

        findings.add(finding(Severity.MEDIUM, messageTemplate.formatted(actualKey.get(), shown) + SWITCH_NOTE, config));
    }

    /**
     * Logger names are compared as written: Spring Boot binds them case-sensitively, and
     * {@code logging.level.ORG.SPRINGFRAMEWORK.WEB=debug} wrote nothing (N26). Only the
     * {@code logging.level} prefix is matched with relaxed binding.
     */
    private void checkLoggerLevels(EffectiveConfig config, List<Finding> findings) {
        Map<String, String> keysByLogger = new TreeMap<>();
        for (String key : config.properties().keySet()) {
            if (RelaxedProperties.canonicalize(key).startsWith(LOG_LEVEL_PREFIX)) {
                keysByLogger.put(key.split("\\.", 3)[2], key);
            }
        }
        Map<String, Optional<String>> levels = new TreeMap<>();
        keysByLogger.forEach((logger, key) -> levels.put(logger, level(config.properties().get(key))));

        for (Map.Entry<String, String> entry : keysByLogger.entrySet()) {
            String logger = entry.getKey();
            String key = entry.getValue();
            String raw = config.properties().get(key);
            Optional<String> level = levels.get(logger);
            if (level.isEmpty()) {
                if (raw != null && !raw.isBlank()) {
                    findings.add(unresolvedPlaceholderFinding(key, raw, config));
                }
                continue;
            }
            if (!level.get().equals("DEBUG") && !level.get().equals("TRACE")) {
                continue;
            }

            if (logger.equalsIgnoreCase(ROOT_LOGGER)) {
                findings.add(finding(Severity.MEDIUM, rootMessage(key, level.get()), config));
                continue;
            }
            Set<String> writes = secretsWrittenBy(logger, level.get(), configuredLoggers(levels.keySet()));
            if (writes.isEmpty()) {
                findings.add(finding(Severity.INFO,
                        ("Logger '%s' set to %s via '%s'. SCG can't tell what this logger writes at that level; " +
                                "check that it doesn't log credentials, tokens or personal data.")
                                .formatted(logger, level.get(), key),
                        config));
            } else {
                findings.add(finding(Severity.MEDIUM,
                        ("Logger '%s' set to %s via '%s', which writes %s to the application log. " +
                                "Raise it to INFO, or set DEBUG/TRACE only on loggers that don't log secrets.")
                                .formatted(logger, level.get(), key, String.join("; ", writes)),
                        config));
            }
        }
    }

    /** The configured logger names, with the members of Spring Boot's groups among them. */
    private static Set<String> configuredLoggers(Set<String> names) {
        Set<String> loggers = new LinkedHashSet<>(names);
        names.forEach(name -> loggers.addAll(SPRING_BOOT_GROUPS.getOrDefault(name, List.of())));
        return loggers;
    }

    /**
     * The level a value sets, upper-cased; empty when it is blank (no level) or an unresolved
     * placeholder, which {@link #checkLoggerLevels} tells apart by the raw value.
     */
    private static Optional<String> level(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.of("");
        }
        return EnvironmentPlaceholder.resolve(raw.strip()).map(value -> value.strip().toUpperCase(Locale.ROOT));
    }

    private static String rootMessage(String key, String level) {
        String writes = level.equals("TRACE")
                ? "request query strings, inbound and outbound Authorization headers, request and response bodies, " +
                "and bound SQL parameter values"
                : "request query strings, outbound Authorization headers, and request and response bodies";
        return ("Root logger level set to '%s' via '%s'. It applies to every logger without its own level, " +
                "third-party libraries included, and writes %s to the application log. Set DEBUG/TRACE only on " +
                "specific loggers that don't log secrets.").formatted(level, key, writes);
    }

    /**
     * What {@code logger} (or each member, for Spring Boot's {@code web} or {@code sql} group) writes
     * at {@code level}: every {@link #SECRET_LOGGERS} entry it is or is an ancestor of, whose minimum
     * level {@code level} reaches, and whose level it actually decides. A more specific configured
     * logger between them decides instead (N25: {@code org=debug} with {@code org.springframework.web}
     * and {@code org.apache.hc} at {@code info} wrote nothing), and reports on its own.
     */
    private static Set<String> secretsWrittenBy(String logger, String level, Set<String> configuredLoggers) {
        List<String> members = SPRING_BOOT_GROUPS.getOrDefault(logger, List.of(logger));
        Set<String> writes = new LinkedHashSet<>();
        for (SecretLogger secretLogger : SECRET_LOGGERS) {
            boolean levelReaches = level.equals("TRACE") || secretLogger.minLevel().equals(level);
            boolean decides = members.stream().anyMatch(member -> isAncestorOrSelf(member, secretLogger.name())
                    && configuredLoggers.stream().noneMatch(other -> !other.equals(member) && !other.equals(logger)
                    && isAncestorOrSelf(member, other) && isAncestorOrSelf(other, secretLogger.name())));
            if (levelReaches && decides) {
                writes.add(secretLogger.writes());
            }
        }
        return writes;
    }

    private static boolean isAncestorOrSelf(String ancestor, String logger) {
        return logger.equals(ancestor) || logger.startsWith(ancestor + ".");
    }

    private Finding unresolvedPlaceholderFinding(String key, String rawValue, EffectiveConfig config) {
        return finding(Severity.INFO,
                ("Verbose logging property '%s' relies on an unresolved environment placeholder '%s'. " +
                        "Static analysis cannot verify the runtime value; check that it doesn't resolve to a " +
                        "verbose setting.").formatted(key, rawValue),
                config);
    }

    private Finding finding(Severity severity, String message, EffectiveConfig config) {
        return new Finding(id(), severity, message, config.sourceFile().toString(), config.profileLabel());
    }
}
