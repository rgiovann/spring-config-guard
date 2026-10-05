package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;

/**
 * SCG003 — detects a wildcard or {@code null} CORS origin combined with allow-credentials=true,
 * which lets a page on another origin make credentialed requests and read the responses.
 * <p>
 * Covers the two CORS configurations Spring Boot binds from properties, which share the same
 * keys and semantics: Actuator's {@code management.endpoints.web.cors.*} and Spring for
 * GraphQL's {@code spring.graphql.cors.*} (both in Spring Boot 4.1.1's configuration metadata).
 * Spring MVC's own CORS for application controllers has no property binding: it's configured in
 * code ({@code WebMvcConfigurer}, {@code @CrossOrigin}), which SCG can't see.
 * <p>
 * The two origin keys are matched as Spring matches them, checked against a running Spring Boot
 * 4.1.1 app for both prefixes (VALIDATION.md, "SCG003 CORS scenarios"):
 * <ul>
 *     <li>{@code allowed-origin-patterns}: {@code *} and {@code https://*} let any origin in with
 *     credentials (HIGH), and so does a pattern an attacker can register a match for, since Spring
 *     only anchors its end ({@code https://*.com}, {@code https://*example.com},
 *     {@code https://app.*}); a domain pattern ({@code https://*.example.com}) lets in every
 *     matching subdomain (MEDIUM). A wildcard only in the scheme or the port
 *     ({@code *://app.example.com}, {@code http://localhost:*}, {@code http://localhost:[*]}) lets a
 *     single host in, and one whose matches are all on the local machine
 *     ({@code http://*.localhost}) is no attacker's origin: both are silent here (SCG004 reports
 *     a plain-HTTP remote host).</li>
 *     <li>{@code allowed-origins}: values are compared literally, so {@code https://*.example.com}
 *     matches no real origin (Spring answers 403) and stays silent. The special value {@code *}
 *     with credentials is rejected by Spring itself: the Actuator endpoint mapping fails at
 *     startup, and GraphQL answers every CORS request with 500. It is reported as LOW
 *     (present but ineffective), since it isn't exploitable but the configuration is broken.</li>
 *     <li>{@code null}, in either key (case-insensitive in {@code allowed-origins}), matches the
 *     {@code Origin: null} that browsers send from a sandboxed iframe, which any web page can embed:
 *     a running app answered such an iframe's credentialed request (HIGH). Unquoted in YAML,
 *     {@code null} is no value at all, and Spring disables CORS.</li>
 * </ul>
 * A placeholder without a default, in an origin key or in {@code allow-credentials}, can't be
 * evaluated statically: INFO, never HIGH (CLAUDE.md, "Findings").
 */
public final class CorsWildcardWithCredentialsRule implements Rule {

    /** The CORS prefixes Spring Boot binds from properties, in report order. */
    private static final List<String> CORS_PREFIXES = List.of("management.endpoints.web.cors", "spring.graphql.cors");

    private enum Credentials { ENABLED, UNRESOLVED, DISABLED }

    @Override
    public String id() {
        return "SCG003";
    }

    @Override
    public String description() {
        return "CORS wildcard or 'null' origin combined with allow-credentials=true (Actuator and Spring for GraphQL)";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();
        for (String prefix : CORS_PREFIXES) {
            checkPrefix(config, prefix, findings);
        }
        return findings;
    }

    private void checkPrefix(EffectiveConfig config, String prefix, List<Finding> findings) {
        String credentialsKey = prefix + ".allow-credentials";
        Credentials credentials = credentials(RelaxedProperties.get(config.properties(), credentialsKey));
        if (credentials == Credentials.DISABLED) {
            return;
        }

        String patternsKey = prefix + ".allowed-origin-patterns";
        WildcardScope patternScope = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), patternsKey).stream()
                .map(this::classifyWildcard)
                .max(WildcardScope::compareTo)
                .orElse(WildcardScope.NONE);

        if (patternScope == WildcardScope.UNRESOLVED
                || (credentials == Credentials.UNRESOLVED && patternScope != WildcardScope.NONE)) {
            findings.add(finding(config, Severity.INFO,
                    ("CORS key '%s' or '%s' relies on an unresolved environment placeholder. If credentials are " +
                            "enabled and the origin patterns include a wildcard at runtime, any matching origin can make " +
                            "credentialed requests; static analysis can't tell. Use explicit origins.")
                            .formatted(patternsKey, credentialsKey)));
        } else if (patternScope == WildcardScope.GLOBAL) {
            findings.add(finding(config, Severity.HIGH,
                    ("Insecure CORS combination detected in key '%s': a global wildcard pattern allows credentialed " +
                            "requests from any host (*, https://*, etc.). This combination exposes the application " +
                            "to severe Cross-Site Request Forgery (CSRF) and session data leakage. " +
                            "Replace global wildcards with explicit origins or restricted domain patterns.")
                            .formatted(patternsKey)));
        } else if (patternScope == WildcardScope.NON_GLOBAL) {
            findings.add(finding(config, Severity.MEDIUM,
                    ("CORS origin pattern in key '%s' contains a domain-scoped wildcard while credential " +
                            "sending (allow-credentials) is enabled. This grants credentialed access to every " +
                            "matching subdomain. Review subdomain ownership and takeover risks, or use explicit origins.")
                            .formatted(patternsKey)));
        }

        String originsKey = prefix + ".allowed-origins";
        boolean literalWildcardOrigin = resolvedOrigins(config, originsKey).contains("*");
        if (credentials == Credentials.ENABLED && literalWildcardOrigin) {
            findings.add(finding(config, Severity.LOW,
                    ("CORS key '%s' contains '*' while '%s' is true. Spring rejects this combination: the Actuator " +
                            "endpoint mapping fails at startup, and GraphQL answers every CORS request with an error, so " +
                            "it isn't exploitable, but the configuration is broken. List explicit origins, or use " +
                            "'allowed-origin-patterns' with explicit domains.")
                            .formatted(originsKey, credentialsKey)));
        }

        // 'null' is compared ignoring case in allowed-origins and case-sensitively as a pattern.
        boolean nullInOrigins = resolvedOrigins(config, originsKey).stream().anyMatch("null"::equalsIgnoreCase);
        boolean nullInPatterns = resolvedOrigins(config, patternsKey).contains("null");
        if (credentials != Credentials.DISABLED && (nullInOrigins || nullInPatterns)) {
            String nullKey = nullInOrigins ? originsKey : patternsKey;
            findings.add(credentials == Credentials.ENABLED
                    ? finding(config, Severity.HIGH,
                            ("CORS key '%s' allows the origin 'null' while '%s' is true. Browsers send 'Origin: null' " +
                                    "from sandboxed iframes, so any web page can make credentialed requests and read the " +
                                    "responses. Remove 'null' and list explicit https:// origins.")
                                    .formatted(nullKey, credentialsKey))
                    : finding(config, Severity.INFO,
                            ("CORS key '%s' allows the origin 'null', and '%s' relies on an unresolved environment " +
                                    "placeholder. If credentials are enabled at runtime, any web page can make credentialed " +
                                    "requests from a sandboxed iframe and read the responses; static analysis can't tell. " +
                                    "Remove 'null' and list explicit https:// origins.")
                                    .formatted(nullKey, credentialsKey)));
        }
    }

    /** The origins of a key with placeholders resolved, split as Spring splits them; unresolved values are skipped. */
    private static List<String> resolvedOrigins(EffectiveConfig config, String key) {
        return RelaxedProperties.valuesForKeyOrListChildren(config.properties(), key).stream()
                .filter(Objects::nonNull)
                .map(EnvironmentPlaceholder::resolve)
                .flatMap(Optional::stream)
                .flatMap(value -> CorsOrigins.split(value).stream())
                .toList();
    }

    private static Credentials credentials(String raw) {
        if (raw == null || raw.isBlank()) {
            return Credentials.DISABLED;
        }
        Optional<String> resolved = EnvironmentPlaceholder.resolve(raw.strip());
        if (resolved.isEmpty()) {
            return Credentials.UNRESOLVED;
        }
        return RelaxedBoolean.isTrueLiteral(resolved.get()) ? Credentials.ENABLED : Credentials.DISABLED;
    }

    private Finding finding(EffectiveConfig config, Severity severity, String message) {
        return new Finding(id(), severity, message, config.sourceFile().toString(), config.profileLabel());
    }

    private WildcardScope classifyWildcard(String value) {
        if (value == null) {
            return WildcardScope.NONE;
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        if (resolved.isEmpty()) {
            return WildcardScope.UNRESOLVED;
        }

        WildcardScope result = WildcardScope.NONE;
        for (String rawOrigin : CorsOrigins.split(resolved.get())) {
            String origin = rawOrigin.toLowerCase(Locale.ROOT);
            WildcardScope scope = evaluateOriginScope(origin);

            if (scope == WildcardScope.GLOBAL) {
                return WildcardScope.GLOBAL;
            }
            if (scope == WildcardScope.NON_GLOBAL) {
                result = WildcardScope.NON_GLOBAL;
            }
        }
        return result;
    }

    private WildcardScope evaluateOriginScope(String origin) {
        if (!origin.contains("*")) {
            return WildcardScope.NONE;
        }

        // 1. Pure literal '*'
        if ("*".equals(origin)) {
            return WildcardScope.GLOBAL;
        }

        // The host, without the scheme and the port, a port wildcard or a port list. A wildcard
        // only in the scheme or the port (*://app.example.com, https://app.example.com:*) lets
        // a single host in; one whose matches are all on the local machine (http://*.localhost)
        // is no attacker's origin.
        String host = CorsOrigins.host(origin);
        if (!host.contains("*") || CorsOrigins.isLoopbackHost(host)) {
            return WildcardScope.NONE;
        }

        // 2. No literal host present (e.g. https://*, http://*, *://*) -> GLOBAL
        if ("*".equals(host)) {
            return WildcardScope.GLOBAL;
        }

        // 3. Spring anchors the end of the pattern, so what follows the last '*' is the only part
        // an origin must keep. Unless that suffix fixes a domain of at least two labels after its
        // first dot, an attacker can register a matching origin -> GLOBAL: https://*.com
        // (evil.com), https://*example.com (evilexample.com), https://app.* (app.evil.com).
        // https://*.example.com and https://*-staging.example.com stay under example.com.
        // A public suffix of two labels or more (https://*.co.uk, or a hosting platform's domain
        // such as https://*.vercel.app) can't be told from a company's domain without the public
        // suffix list, so it stays NON_GLOBAL.
        String suffix = host.substring(host.lastIndexOf('*') + 1);
        int firstDot = suffix.indexOf('.');
        if (firstDot == -1 || suffix.indexOf('.', firstDot + 1) == -1) {
            return WildcardScope.GLOBAL;
        }

        // 4. A wildcard scoped to a domain -> NON_GLOBAL (MEDIUM)
        return WildcardScope.NON_GLOBAL;
    }

    /** Ordered by precedence: an unresolved value can't be ruled out, so it outranks the others. */
    private enum WildcardScope {
        NONE,
        NON_GLOBAL,
        GLOBAL,
        UNRESOLVED
    }
}