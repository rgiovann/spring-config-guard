package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;
import java.util.stream.Stream;

/**
 * SCG005 — detects a CORS configuration that lets permitted origins use every HTTP method, or read
 * response headers that carry a session or an authentication token.
 * <p>
 * Covers the two CORS configurations Spring Boot binds from properties, as SCG003 and SCG004 do:
 * Actuator's {@code management.endpoints.web.cors.*} and Spring for GraphQL's
 * {@code spring.graphql.cors.*}. Spring Boot 4.1.1 builds either configuration only when
 * {@code allowed-origins} or {@code allowed-origin-patterns} is set
 * ({@code toCorsConfiguration()} returns null otherwise), so without an origin key these keys
 * have no effect and the rule is silent. Checked against a running Spring Boot 4.1.1 app and
 * Chromium (VALIDATION.md, "SCG005 methods and headers scenarios"):
 * <ul>
 *     <li>{@code allowed-methods=*} lets a permitted origin's script send any method, DELETE
 *     included; a JSON POST (an Actuator write operation such as {@code /actuator/loggers}) also
 *     needs {@code allowed-headers} to allow {@code Content-Type}. The default is GET and HEAD.</li>
 *     <li>{@code Authorization} or {@code X-Auth-Token} (Spring Session's header) in
 *     {@code exposed-headers} lets that script read the token and use it outside the browser.</li>
 *     <li>{@code exposed-headers=*}: browsers honor the wildcard only for requests without
 *     credentials; with credentials it is a header literally named {@code *}, and Chromium exposed
 *     nothing.</li>
 *     <li>{@code Set-Cookie} and {@code Set-Cookie2} are forbidden response headers that browsers
 *     never expose (LOW, ineffective); {@code Cookie} is a request header (INFO).</li>
 * </ul>
 * The permitted origins are trusted by configuration, so these findings matter when one of them is
 * compromised, or allowed too broadly (SCG003, SCG004). Severity follows {@code allow-credentials},
 * as in SCG004: MEDIUM when it is true, since the script then acts with the user's session; LOW
 * otherwise (false, absent, or an unresolved placeholder), since it only reaches anonymous
 * responses. {@code exposed-headers=*} is LOW either way: ineffective with credentials, anonymous
 * responses without. A placeholder without a default is INFO.
 */
public final class CorsPermissiveMethodsAndHeadersRule implements Rule {

    /** The CORS prefixes Spring Boot binds from properties, in report order. */
    private static final List<String> CORS_PREFIXES = List.of("management.endpoints.web.cors", "spring.graphql.cors");

    /** Response headers that carry a session or an authentication token. */
    private static final Set<String> TOKEN_HEADERS = Set.of("authorization", "x-auth-token");

    /** Forbidden response headers: browsers never expose them, whatever CORS says. */
    private static final Set<String> FORBIDDEN_RESPONSE_HEADERS = Set.of("set-cookie", "set-cookie2");

    /** Request headers, meaningless in exposed-headers. */
    private static final Set<String> REQUEST_HEADERS = Set.of("cookie");

    @Override
    public String id() {
        return "SCG005";
    }

    @Override
    public String description() {
        return "Permissive CORS configuration exposing all HTTP methods or sensitive/wildcard response headers " +
                "(Actuator and Spring for GraphQL)";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();
        for (String prefix : CORS_PREFIXES) {
            if (!hasOrigins(config, prefix)) {
                continue;
            }
            String credentialsKey = prefix + ".allow-credentials";
            String credentials = RelaxedProperties.get(config.properties(), credentialsKey);
            boolean credentialsEnabled = credentials != null && EnvironmentPlaceholder.resolve(credentials.strip())
                    .map(RelaxedBoolean::isTrueLiteral)
                    .orElse(false);
            checkAllowedMethods(config, prefix + ".allowed-methods", credentialsKey, credentialsEnabled, findings);
            checkExposedHeaders(config, prefix + ".exposed-headers", credentialsKey, credentialsEnabled, findings);
        }
        return findings;
    }

    /** Whether Spring Boot builds this prefix's CORS configuration: an origin key holds a value. */
    private static boolean hasOrigins(EffectiveConfig config, String prefix) {
        return Stream.of(prefix + ".allowed-origins", prefix + ".allowed-origin-patterns")
                .flatMap(key -> RelaxedProperties.valuesForKeyOrListChildren(config.properties(), key).stream())
                .anyMatch(value -> value != null && !value.isBlank());
    }

    private void checkAllowedMethods(EffectiveConfig config, String key, String credentialsKey,
                                     boolean credentialsEnabled, List<Finding> findings) {
        for (String rawValue : RelaxedProperties.valuesForKeyOrListChildren(config.properties(), key)) {
            if (rawValue == null) {
                continue;
            }
            Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);
            if (resolved.isEmpty()) {
                findings.add(unresolvedPlaceholder(config, key, rawValue));
            } else if (tokens(resolved.get()).contains("*")) {
                findings.add(credentialsEnabled
                        ? finding(config, Severity.MEDIUM,
                                ("CORS key '%s' allows every HTTP method ('*') while '%s' is true: a script on a " +
                                        "permitted origin can send DELETE, PUT or POST requests with the user's session " +
                                        "(a JSON POST also needs 'allowed-headers' to allow Content-Type). List only the " +
                                        "methods the clients need (e.g. GET).")
                                        .formatted(key, credentialsKey))
                        : finding(config, Severity.LOW,
                                ("CORS key '%s' allows every HTTP method ('*'). '%s' is not true here, so a script on a " +
                                        "permitted origin only sends them as anonymous requests; if credentials are " +
                                        "allowed at runtime, it sends them with the user's session. List only the methods " +
                                        "the clients need (e.g. GET).")
                                        .formatted(key, credentialsKey)));
            }
        }
    }

    private void checkExposedHeaders(EffectiveConfig config, String key, String credentialsKey,
                                     boolean credentialsEnabled, List<Finding> findings) {
        for (String rawValue : RelaxedProperties.valuesForKeyOrListChildren(config.properties(), key)) {
            if (rawValue == null) {
                continue;
            }
            Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);
            if (resolved.isEmpty()) {
                findings.add(unresolvedPlaceholder(config, key, rawValue));
                continue;
            }
            for (String header : tokens(resolved.get())) {
                String name = header.toLowerCase(Locale.ROOT);
                if ("*".equals(name)) {
                    findings.add(finding(config, Severity.LOW, credentialsEnabled
                            ? ("CORS key '%s' contains '*' while '%s' is true. Browsers honor the wildcard only for " +
                                    "requests without credentials, so it exposes no header here; list the headers clients " +
                                    "need to read (e.g. Content-Disposition).").formatted(key, credentialsKey)
                            : ("CORS key '%s' contains '*', which lets scripts on permitted origins read every header " +
                                    "of responses to anonymous requests. List only the headers clients need to read " +
                                    "(e.g. Content-Disposition).").formatted(key)));
                } else if (TOKEN_HEADERS.contains(name)) {
                    findings.add(credentialsEnabled
                            ? finding(config, Severity.MEDIUM,
                                    ("CORS key '%s' exposes '%s' while '%s' is true: a script on a permitted origin can " +
                                            "read the user's session or authentication token and use it outside the " +
                                            "browser. Don't expose token headers cross-origin.")
                                            .formatted(key, header, credentialsKey))
                            : finding(config, Severity.LOW,
                                    ("CORS key '%s' exposes '%s'. '%s' is not true here, so a script on a permitted " +
                                            "origin only reads it on anonymous responses; if credentials are allowed at " +
                                            "runtime, it reads the user's token. Don't expose token headers cross-origin.")
                                            .formatted(key, header, credentialsKey)));
                } else if (FORBIDDEN_RESPONSE_HEADERS.contains(name)) {
                    findings.add(finding(config, Severity.LOW,
                            ("Header '%s' in key '%s' is ineffective: browsers treat Set-Cookie and Set-Cookie2 as " +
                                    "forbidden response headers and never expose them to scripts, whatever CORS allows.")
                                    .formatted(header, key)));
                } else if (REQUEST_HEADERS.contains(name)) {
                    findings.add(finding(config, Severity.INFO,
                            ("Header '%s' in key '%s' is a request header, not a response header; exposing it has " +
                                    "no effect.")
                                    .formatted(header, key)));
                }
            }
        }
    }

    private static List<String> tokens(String value) {
        return Arrays.stream(value.split(","))
                .map(String::strip)
                .filter(token -> !token.isEmpty())
                .toList();
    }

    private Finding unresolvedPlaceholder(EffectiveConfig config, String key, String rawValue) {
        return finding(config, Severity.INFO,
                ("CORS key '%s' relies on an unresolved environment placeholder '%s'. Static analysis cannot " +
                        "determine the runtime CORS policy; verify this value in your deployment settings.")
                        .formatted(key, rawValue));
    }

    private Finding finding(EffectiveConfig config, Severity severity, String message) {
        return new Finding(id(), severity, message, config.sourceFile().toString(), config.profileLabel());
    }
}
