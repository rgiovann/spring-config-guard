package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Security rule (SCG012) that detects explicit disabling or degradation of TLS/SSL
 * transport encryption in database and broker connection URIs.
 *
 * <p>Inspects connection strings via three mechanisms, kept separate since they're different
 * vulnerability classes or evidence shapes, not one flat "risky value" bucket. The two query
 * parameter mechanisms apply to <b>every property</b> whose value is a database connection string
 * ({@code jdbc:}, {@code r2dbc:}, {@code mongodb:}, {@code mongodb+srv:}): those prefixes only
 * name databases, so the value's shape is enough, and a key list went stale as Spring Boot renamed
 * properties ({@code spring.mongodb.uri}, {@code spring.flyway.url}, the pool-specific JDBC URLs).
 * The scheme mechanism stays limited to {@code uri-based} keys: {@code http://} in an arbitrary
 * property is not a database or broker connection (BACKLOG.md, "Discarded": a generic
 * {@code http://} scanner).
 * <ul>
 *     <li>{@code risky-query-params}: TLS/SSL disabled or downgradable to cleartext
 *     (e.g., {@code sslmode=disable}, {@code useSSL=false}) — CWE-319.</li>
 *     <li>{@code no-verify-query-params}: TLS is used, but certificate/hostname validation
 *     is explicitly disabled (e.g., {@code verifyServerCertificate=false}, PostgreSQL's
 *     {@code sslmode=require}, MySQL's {@code sslMode=REQUIRED}, MariaDB's {@code sslMode=trust})
 *     — the wire is encrypted, but a forged/self-signed certificate lets an attacker MITM anyway —
 *     CWE-295.</li>
 *     <li>{@code risky-schemes}: same CWE-319 outcome as {@code risky-query-params}, but the
 *     signal is the URI's own scheme ({@code http://}, {@code amqp://}, {@code tcp://},
 *     {@code ldap://}), not a query parameter — added because Elasticsearch/RabbitMQ/ActiveMQ/
 *     LDAP don't express TLS via query string the way JDBC drivers do; listing them under
 *     {@code uri-based} alone (as Elasticsearch/RabbitMQ/ActiveMQ originally were) left them as
 *     dead entries that could never actually match either query-param mechanism.</li>
 * </ul>
 * TLS disabled (query parameter or scheme) is {@link Severity#HIGH}: anyone on the network path
 * reads the traffic passively. Certificate validation disabled is {@link Severity#MEDIUM}: the
 * traffic is encrypted, and reading it takes an active man in the middle presenting a forged
 * certificate. Both are written in the file, so both are certain evidence; the difference is the
 * attack they allow.
 * <p>
 * When every host of the value is a loopback address ({@code jdbc:mysql://localhost:3306/app}),
 * either finding is {@link Severity#INFO}: the traffic doesn't leave the host unless something
 * local relays it ({@link ConnectionHosts}).
 * <p>
 * {@code sslmode=prefer} is deliberately NOT in {@code risky-query-params}: it's the
 * PostgreSQL JDBC driver's own default when the property is absent entirely (confirmed in
 * the official pgjdbc documentation), so flagging it would penalize writing the default
 * explicitly rather than detecting an actual downgrade — same lesson already learned from
 * {@code server.forward-headers-strategy=NONE} in {@link InsecureServerTransportRule}.
 *
 * @see ConfigurableRule
 * @see EnvironmentPlaceholder
 */
public final class InsecureDatabaseTransportRule implements ConfigurableRule {

    private static final String RULE_NAME = "SCG012";

    private Set<String> uriBasedKeys;
    private Map<String, Set<String>> riskyQueryParams;
    private Map<String, Set<String>> noVerifyQueryParams;
    private Set<String> riskySchemes;

    /** Prefixes that only ever start a database connection string. */
    private static final List<String> DATABASE_URL_PREFIXES = List.of("jdbc:", "r2dbc:", "mongodb:", "mongodb+srv:");

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Disabled or insecure TLS transport in database/broker connection URIs";
    }

    @Override
    public void configure(Map<String, List<String>> metadata) {
        Objects.requireNonNull(metadata, RULE_NAME + " metadata map cannot be null");

        List<String> rawUriKeys = metadata.get("uri-based");
        if (rawUriKeys == null || rawUriKeys.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'uri-based' is missing or empty.");
        }

        List<String> rawRiskyParams = metadata.get("risky-query-params");
        if (rawRiskyParams == null || rawRiskyParams.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'risky-query-params' is missing or empty.");
        }

        List<String> rawNoVerifyParams = metadata.get("no-verify-query-params");
        if (rawNoVerifyParams == null || rawNoVerifyParams.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'no-verify-query-params' is missing or empty.");
        }

        List<String> rawRiskySchemes = metadata.get("risky-schemes");
        if (rawRiskySchemes == null || rawRiskySchemes.isEmpty()) {
            throw new IllegalArgumentException(RULE_NAME + " initialization failed: 'risky-schemes' is missing or empty.");
        }

        this.uriBasedKeys = rawUriKeys.stream()
                .map(RelaxedProperties::canonicalize)
                .collect(Collectors.toUnmodifiableSet());

        this.riskyQueryParams = parseQueryParamMap(rawRiskyParams);
        this.noVerifyQueryParams = parseQueryParamMap(rawNoVerifyParams);

        this.riskySchemes = rawRiskySchemes.stream()
                .map(s -> s.strip().toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    // Parses the "param=value" format, keeping a single flat level in the YAML
    private Map<String, Set<String>> parseQueryParamMap(List<String> rawPairs) {
        Map<String, Set<String>> parsedParams = new HashMap<>();
        for (String pair : rawPairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                String paramName = kv[0].strip().toLowerCase(Locale.ROOT);
                String paramValue = kv[1].strip().toLowerCase(Locale.ROOT);

                parsedParams.computeIfAbsent(paramName, k -> new HashSet<>()).add(paramValue);
            }
        }

        Map<String, Set<String>> immutableParams = new HashMap<>();
        parsedParams.forEach((k, v) -> immutableParams.put(k, Set.copyOf(v)));
        return Map.copyOf(immutableParams);
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        ensureConfigured();

        List<Finding> findings = new ArrayList<>();

        for (Map.Entry<String, String> entry : config.properties().entrySet()) {
            String rawValue = entry.getValue();
            if (rawValue == null || rawValue.isBlank()) {
                continue;
            }

            // canonicalRoot strips a trailing "[0]"/"[1]"/... so a key written as one item of a
            // YAML list (e.g. spring.elasticsearch.uris[0]) still matches the plain target key
            // -- same fix as EmbeddedConnectionCredentialsRule (SCG007), applied here from the
            // start instead of inheriting the gap.
            String canonicalKey = RelaxedProperties.canonicalRoot(RelaxedProperties.canonicalize(entry.getKey()));
            boolean isUriKey = uriBasedKeys.contains(canonicalKey);
            String trimmedValue = rawValue.strip();
            if (!isUriKey && !isDatabaseUrl(EnvironmentPlaceholder.substitute(trimmedValue, ""))) {
                continue;
            }

            // 1. Resolve environment placeholders
            Optional<String> resolvedValue = EnvironmentPlaceholder.resolve(trimmedValue);

            // Unresolved dynamic placeholder -> INFO, for the known connection keys only
            if (resolvedValue.isEmpty() && !isUriKey) {
                continue;
            }
            if (resolvedValue.isEmpty()) {
                findings.add(new Finding(
                        id(),
                        Severity.INFO,
                        ("Connection property '%s' relies on an unresolved environment placeholder '%s'. " +
                                "Static analysis cannot verify whether TLS transport security is enforced at runtime.")
                                .formatted(entry.getKey(), rawValue),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
                continue;
            }

            String valueToInspect = resolvedValue.get();
            if (valueToInspect.isBlank()) {
                continue;
            }

            // 2. Inspect the scheme first, then query parameters for explicit TLS opt-outs, then
            // for disabled certificate validation -- three different mechanisms, checked in
            // sequence rather than merged into one lookup so each keeps its own message. Scheme
            // goes first since it needs no "?"/";" boundary to exist at all -- a bare
            // "http://host:port" with no query string would never reach the other two checks.
            boolean isFromPlaceholderDefault = trimmedValue.contains("${");
            boolean loopback = ConnectionHosts.allLoopback(trimmedValue);

            Optional<String> insecureScheme = isUriKey ? findSchemeMatch(valueToInspect) : Optional.empty();
            if (insecureScheme.isPresent()) {
                findings.add(onLoopback(loopback, new Finding(
                        id(),
                        Severity.HIGH,
                        buildInsecureSchemeMessage(entry.getKey(), rawValue, insecureScheme.get(), isFromPlaceholderDefault),
                        config.sourceFile().toString(),
                        config.profileLabel()
                )));
                continue;
            }

            Optional<String> disabledTls = findMatch(valueToInspect, riskyQueryParams);
            if (disabledTls.isPresent()) {
                findings.add(onLoopback(loopback, new Finding(
                        id(),
                        Severity.HIGH,
                        buildDisabledTlsMessage(entry.getKey(), rawValue, disabledTls.get(), isFromPlaceholderDefault),
                        config.sourceFile().toString(),
                        config.profileLabel()
                )));
                continue;
            }

            Optional<String> noVerify = findMatch(valueToInspect, noVerifyQueryParams);
            if (noVerify.isPresent()) {
                findings.add(onLoopback(loopback, new Finding(
                        id(),
                        Severity.MEDIUM,
                        buildNoVerifyMessage(entry.getKey(), rawValue, noVerify.get(), isFromPlaceholderDefault),
                        config.sourceFile().toString(),
                        config.profileLabel()
                )));
            }
        }

        return findings;
    }

    private static Finding onLoopback(boolean loopback, Finding finding) {
        return loopback ? ConnectionHosts.onLoopback(finding) : finding;
    }

    /**
     * Unlike {@link #findMatch(String, Map)}, this needs no "?"/";" query boundary -- Elasticsearch,
     * RabbitMQ, ActiveMQ, and LDAP express transport security via the URI's own scheme
     * ({@code http://} vs {@code https://}, {@code tcp://} vs {@code ssl://}, ...), not a query
     * parameter, so a value like {@code http://es-node:9200} with no query string at all must
     * still match here.
     */
    private Optional<String> findSchemeMatch(String uriString) {
        // Every node of a comma-separated list (spring.elasticsearch.uris=https://a,http://b)
        for (String node : uriString.split(",")) {
            String lowerCased = node.strip().toLowerCase(Locale.ROOT);
            Optional<String> match = riskySchemes.stream()
                    .filter(lowerCased::startsWith)
                    .findFirst();
            if (match.isPresent()) {
                return match;
            }
        }
        return Optional.empty();
    }

    private static boolean isDatabaseUrl(String value) {
        String lowerCased = value.toLowerCase(Locale.ROOT);
        return DATABASE_URL_PREFIXES.stream().anyMatch(lowerCased::startsWith);
    }

    private Optional<String> findMatch(String uriString, Map<String, Set<String>> paramMap) {
        int queryStart = uriString.indexOf('?');
        String queryString;

        if (queryStart != -1) {

            // Standard URL/JDBC format: jdbc:mysql://host:port/db?param=val
            queryString = uriString.substring(queryStart + 1);
        } else {
            // SQL Server/Oracle format without '?': jdbc:sqlserver://host:1433;param=val
            int firstSemicolon = uriString.indexOf(';');
            if (firstSemicolon == -1 || firstSemicolon == uriString.length() - 1) {
                return Optional.empty();
            }
            queryString = uriString.substring(firstSemicolon + 1);
        }

        String[] pairs = queryString.split("[&;]");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length != 2) {
                continue;
            }

            String key = kv[0].strip().toLowerCase(Locale.ROOT);
            String val = kv[1].strip().toLowerCase(Locale.ROOT);

            Set<String> riskyValues = paramMap.get(key);
            if (riskyValues != null && riskyValues.contains(val)) {
                return Optional.of(key + "=" + val);
            }
        }

        return Optional.empty();
    }

    private String buildInsecureSchemeMessage(String key, String rawValue, String matchedScheme, boolean isFromPlaceholderDefault) {
        String base = ("Insecure scheme '%s' detected in connection property '%s'. " +
                "This service does not express transport security via a query parameter -- the scheme itself " +
                "is the signal -- and traffic to it is transmitted in cleartext (CWE-319).")
                .formatted(matchedScheme, key);

        return withPlaceholderNote(base, rawValue, isFromPlaceholderDefault);
    }

    private String buildDisabledTlsMessage(String key, String rawValue, String matchedParam, boolean isFromPlaceholderDefault) {
        String base = ("Insecure TLS configuration detected in connection property '%s' via parameter '%s'. " +
                "Disabling TLS or allowing unencrypted fallback exposes all database traffic, queries, " +
                "and transport credentials to network interception (CWE-319).")
                .formatted(key, matchedParam);

        return withPlaceholderNote(base, rawValue, isFromPlaceholderDefault);
    }

    private String buildNoVerifyMessage(String key, String rawValue, String matchedParam, boolean isFromPlaceholderDefault) {
        String base = ("Certificate validation is disabled in connection property '%s' via parameter '%s'. " +
                "The connection is encrypted, but accepting any certificate (forged or self-signed) allows an " +
                "attacker to man-in-the-middle the connection despite TLS being active (CWE-295).")
                .formatted(key, matchedParam);

        return withPlaceholderNote(base, rawValue, isFromPlaceholderDefault);
    }

    private String withPlaceholderNote(String base, String rawValue, boolean isFromPlaceholderDefault) {
        if (!isFromPlaceholderDefault) {
            return base;
        }
        return base + " The value originates from a static placeholder default ('%s').".formatted(rawValue);
    }

    private void ensureConfigured() {
        if (uriBasedKeys == null || riskyQueryParams == null || noVerifyQueryParams == null || riskySchemes == null) {
            throw new IllegalStateException("Rule " + RULE_NAME + " must be configured before execution.");
        }
    }
}
