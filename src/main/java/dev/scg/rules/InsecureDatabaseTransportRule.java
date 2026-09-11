package dev.scg.rules;

import dev.scg.core.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Security rule (SCG012) that detects explicit disabling or degradation of TLS/SSL
 * transport encryption in database and broker connection URIs.
 *
 * <p>Inspects {@code uri-based} connection properties (JDBC, R2DBC, MongoDB, Redis, etc.)
 * for query parameters that weaken transport security, split into two mechanisms since
 * they're different vulnerability classes, not one flat "risky value" bucket:
 * <ul>
 *     <li>{@code risky-query-params}: TLS/SSL disabled or downgradable to cleartext
 *     (e.g., {@code sslmode=disable}, {@code useSSL=false}) — CWE-319.</li>
 *     <li>{@code no-verify-query-params}: TLS is used, but certificate/hostname validation
 *     is explicitly disabled (e.g., {@code verifyServerCertificate=false}) — the wire is
 *     encrypted, but a forged/self-signed certificate lets an attacker MITM anyway — CWE-295.</li>
 * </ul>
 * Both are reported at {@link Severity#HIGH}: the practical outcome (an attacker in the
 * network path reads all traffic) is the same either way — only the mechanism differs — so
 * this rule does not treat CWE-295 as a lesser finding than CWE-319.
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

        this.uriBasedKeys = rawUriKeys.stream()
                .map(RelaxedProperties::canonicalize)
                .collect(Collectors.toUnmodifiableSet());

        this.riskyQueryParams = parseQueryParamMap(rawRiskyParams);
        this.noVerifyQueryParams = parseQueryParamMap(rawNoVerifyParams);
    }

    // Parse do formato "param=valor" mantendo 1 único nível no YAML
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
            if (!uriBasedKeys.contains(canonicalKey)) {
                continue;
            }

            String trimmedValue = rawValue.strip();

            // 1. Resolve environment placeholders
            Optional<String> resolvedValue = EnvironmentPlaceholder.resolve(trimmedValue);

            // Unresolved dynamic placeholder -> INFO
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

            // 2. Inspect query parameters for explicit TLS opt-outs, then for disabled
            // certificate validation -- two different mechanisms/CWEs, checked in sequence
            // rather than merged into one lookup so each keeps its own message.
            boolean isFromPlaceholderDefault = trimmedValue.contains("${");

            Optional<String> disabledTls = findMatch(valueToInspect, riskyQueryParams);
            if (disabledTls.isPresent()) {
                findings.add(new Finding(
                        id(),
                        Severity.HIGH,
                        buildDisabledTlsMessage(entry.getKey(), rawValue, disabledTls.get(), isFromPlaceholderDefault),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
                continue;
            }

            Optional<String> noVerify = findMatch(valueToInspect, noVerifyQueryParams);
            if (noVerify.isPresent()) {
                findings.add(new Finding(
                        id(),
                        Severity.HIGH,
                        buildNoVerifyMessage(entry.getKey(), rawValue, noVerify.get(), isFromPlaceholderDefault),
                        config.sourceFile().toString(),
                        config.profileLabel()
                ));
            }
        }

        return findings;
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

    private String buildDisabledTlsMessage(String key, String rawValue, String matchedParam, boolean isFromPlaceholderDefault) {
        String base = ("Insecure TLS configuration detected in connection property '%s' via parameter '%s'. " +
                "Disabling TLS or allowing unencrypted fallback exposes all database traffic, queries, " +
                "and transport credentials to network interception (CWE-319).")
                .formatted(key, matchedParam);

        return withPlaceholderNote(base, rawValue, isFromPlaceholderDefault);
    }

    private String buildNoVerifyMessage(String key, String rawValue, String matchedParam, boolean isFromPlaceholderDefault) {
        String base = ("Certificate validation is explicitly disabled in connection property '%s' via parameter '%s'. " +
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
        if (uriBasedKeys == null || riskyQueryParams == null || noVerifyQueryParams == null) {
            throw new IllegalStateException("Rule " + RULE_NAME + " must be configured before execution.");
        }
    }
}
