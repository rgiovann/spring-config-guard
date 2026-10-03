package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * SCG004 — detects a CORS configuration that allows an origin served over plain HTTP from a host
 * other than the local machine. Anyone on the network path between a user and that origin (public
 * Wi-Fi, a compromised router) can inject script into its pages, and the browser lets that script
 * call this application cross-origin and read the responses.
 * <p>
 * Covers the two CORS configurations Spring Boot binds from properties, as SCG003 does:
 * Actuator's {@code management.endpoints.web.cors.*} and Spring for GraphQL's
 * {@code spring.graphql.cors.*} (Spring Boot 4.1.1's configuration metadata). Each origin is read
 * as Spring's {@code CorsConfiguration} reads it, checked against running Spring Boot 4.1.1 apps
 * (VALIDATION.md, "SCG004 insecure origin scenarios"):
 * <ul>
 *     <li>{@code allowed-origins} is compared literally (ignoring case), so only an
 *     {@code http://} origin without {@code *} can match;</li>
 *     <li>in {@code allowed-origin-patterns}, a {@code *} may stand for the scheme, so a pattern
 *     without one ({@code *.example.com}) or with a wildcard scheme ({@code *://app.example.com},
 *     {@code http*://app.example.com}) also lets {@code http://} origins in;</li>
 *     <li>a loopback host is not reported, with any port, port wildcard or port list
 *     ({@code http://localhost:*}, {@code http://127.0.0.1:[8080,8081]}), nor are subdomains of
 *     {@code localhost} ({@code http://*.localhost}): no network attacker sits between a browser
 *     and its own machine. {@code http://localhost*} is reported: it matches
 *     {@code http://localhost.evil.com}.</li>
 * </ul>
 * The pattern {@code *} lets every origin in, plain HTTP included; it isn't a choice of
 * protocol, and SCG003 reports it when credentials are allowed.
 * <p>
 * Severity follows {@code allow-credentials}: MEDIUM when it is true, since the injected script
 * then reads responses to requests carrying the user's cookies or credentials; LOW otherwise
 * (false, absent, or an unresolved placeholder), since without credentials the script only reads
 * responses to anonymous requests, sent from the user's network position. An origin that relies on
 * a placeholder without a default is INFO, unless its literal part already rules out plain HTTP
 * ({@code https://${HOST}}) or a remote host ({@code http://localhost:${PORT}}).
 */
public final class CorsInsecureProtocolsRule implements Rule {

    /** The CORS prefixes Spring Boot binds from properties, in report order. */
    private static final List<String> CORS_PREFIXES = List.of("management.endpoints.web.cors", "spring.graphql.cors");

    /** Stands in for a placeholder without a default; can't occur in a property value. */
    private static final String UNRESOLVED = "\u0000";

    @Override
    public String id() {
        return "SCG004";
    }

    @Override
    public String description() {
        return "Use of an insecure protocol (http://) in non-loopback CORS origins (Actuator and Spring for GraphQL)";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();
        for (String prefix : CORS_PREFIXES) {
            String credentialsKey = prefix + ".allow-credentials";
            String credentials = RelaxedProperties.get(config.properties(), credentialsKey);
            boolean credentialsEnabled = credentials != null && EnvironmentPlaceholder.resolve(credentials.strip())
                    .map(RelaxedBoolean::isTrueLiteral)
                    .orElse(false);
            checkKey(config, prefix + ".allowed-origins", false, credentialsKey, credentialsEnabled, findings);
            checkKey(config, prefix + ".allowed-origin-patterns", true, credentialsKey, credentialsEnabled, findings);
        }
        return findings;
    }

    private void checkKey(EffectiveConfig config, String originKey, boolean patterns,
                          String credentialsKey, boolean credentialsEnabled, List<Finding> findings) {
        List<String> insecure = new ArrayList<>();
        List<String> unresolved = new ArrayList<>();
        for (String rawValue : RelaxedProperties.valuesForKeyOrListChildren(config.properties(), originKey)) {
            if (rawValue == null) {
                continue;
            }
            for (String origin : CorsOrigins.split(EnvironmentPlaceholder.substitute(rawValue, UNRESOLVED))) {
                if (origin.contains(UNRESOLVED)) {
                    if (admitsRemoteHttp(origin.replace(UNRESOLVED, "*")) && !unresolved.contains(rawValue)) {
                        unresolved.add(rawValue);
                    }
                } else if (patterns ? !"*".equals(origin) && admitsRemoteHttp(origin) : isRemoteHttpOrigin(origin)) {
                    insecure.add(origin);
                }
            }
        }

        if (!insecure.isEmpty()) {
            String origins = String.join(", ", insecure);
            findings.add(credentialsEnabled
                    ? finding(config, Severity.MEDIUM,
                            ("CORS key '%s' allows origins served over plain HTTP from a remote host: %s, and '%s' is " +
                                    "true. An attacker on the network path of a user visiting such an origin can inject " +
                                    "script into its pages and read responses to requests carrying the user's credentials. " +
                                    "Use https:// origins; plain HTTP is only safe for loopback addresses.")
                                    .formatted(originKey, origins, credentialsKey))
                    : finding(config, Severity.LOW,
                            ("CORS key '%s' allows origins served over plain HTTP from a remote host: %s. '%s' is not " +
                                    "true here, so script injected into such an origin's pages by an attacker on the " +
                                    "network path only reads responses to anonymous requests, sent from the user's " +
                                    "network; if credentials are allowed at runtime, it reads the user's data too. " +
                                    "Use https:// origins; plain HTTP is only safe for loopback addresses.")
                                    .formatted(originKey, origins, credentialsKey)));
        }
        if (!unresolved.isEmpty()) {
            findings.add(finding(config, Severity.INFO,
                    ("CORS key '%s' relies on an unresolved environment placeholder: %s. Static analysis can't tell " +
                            "whether the runtime origin uses plain HTTP (http://) from a remote host; ensure " +
                            "production origins use https://.")
                            .formatted(originKey, String.join(", ", unresolved))));
        }
    }

    /** An {@code allowed-origins} value: compared literally, so a {@code *} in it matches nothing. */
    private static boolean isRemoteHttpOrigin(String origin) {
        return !origin.contains("*")
                && origin.toLowerCase(Locale.ROOT).startsWith("http://")
                && !CorsOrigins.isLoopbackHost(CorsOrigins.host(origin));
    }

    /** An {@code allowed-origin-patterns} value: whether it can match an http:// origin on a remote host. */
    private static boolean admitsRemoteHttp(String pattern) {
        int schemeEnd = pattern.indexOf("://");
        if (schemeEnd < 0) {
            // Every origin has a scheme, so this pattern only matches one if a '*' stands for it.
            int firstWildcard = pattern.indexOf('*');
            return firstWildcard >= 0
                    && "http://".startsWith(pattern.substring(0, firstWildcard).toLowerCase(Locale.ROOT));
        }
        return matchesAsSpringPattern(pattern.substring(0, schemeEnd).toLowerCase(Locale.ROOT), "http")
                && !CorsOrigins.isLoopbackHost(CorsOrigins.host(pattern));
    }

    /** Whether {@code text} matches {@code pattern} with {@code *} as any sequence, as Spring compiles it. */
    private static boolean matchesAsSpringPattern(String pattern, String text) {
        return Pattern.compile("\\Q" + pattern.replace("*", "\\E.*\\Q") + "\\E").matcher(text).matches();
    }

    private Finding finding(EffectiveConfig config, Severity severity, String message) {
        return new Finding(id(), severity, message, config.sourceFile().toString(), config.profileLabel());
    }
}
