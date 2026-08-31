package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.net.URI;
import java.util.Locale;

public final class CorsInsecureProtocolsRule implements Rule {

    private static final Set<String> ORIGIN_KEYS = Set.of(
            "management.endpoints.web.cors.allowed-origins",
            "management.endpoints.web.cors.allowed-origin-patterns"
    );

    @Override
    public String id() {
        return "SCG004";
    }

    @Override
    public String description() {
        return "Use of an insecure protocol (http://) in non-loopback CORS origins";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {

        List<Finding> findings = new ArrayList<>();

        for (String originKey : ORIGIN_KEYS) {
            List<String> rawValues = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), originKey);

            for (String rawValue : rawValues) {
                List<String> insecureOrigins = findInsecureOrigins(rawValue);

                if (!insecureOrigins.isEmpty()) {
                    findings.add(new Finding(
                            id(),
                            Severity.MEDIUM,
                            ("Insecure CORS origin detected in key '%s': %s. " +
                                    "Using 'http://' in non-development environments exposes the application to Man-in-the-Middle (MitM) attacks. " +
                                    "Use HTTPS for remote origins or restrict HTTP origins strictly to loopback addresses..")
                                    .formatted(originKey, String.join(", ", insecureOrigins)),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                }
            }
        }

        return findings;
    }

    private List<String> findInsecureOrigins(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }

        Optional<String> resolved = EnvironmentPlaceholder.resolve(value);
        if (resolved.isEmpty()) {
            return List.of(); // Sem default estático, não é possível determinar a URL em tempo de compilação
        }

        String[] tokens = resolved.get().split(",");
        List<String> insecure = new ArrayList<>();

        for (String token : tokens) {
            String origin = token.strip().toLowerCase(Locale.ROOT);
            if (origin.startsWith("http://") && !isLocalhost(origin)) {
                insecure.add(token.strip());
            }
        }

        return insecure;
    }

    private boolean isLocalhost(String origin) {
        if (origin == null || origin.isBlank()) {
            return false;
        }

        try {
            URI uri = URI.create(origin.strip());
            String host = uri.getHost();

            if (host == null) {
                // URIs without an explicit host (e.g., "http:", "relative/path") are not considered valid local origins
                return false;
            }

            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }

            host = host.toLowerCase(Locale.ROOT);

            // 1. Loopback IPv4 exact or range 127.0.0.0/8 (RFC 1122)
            if (host.startsWith("127.")) {
                return true;
            }

            // 2. Loopback IPv6 (::1, [::1], 0:0:0:0:0:0:0:1)
            if (host.equals("::1") || host.equals("[::1]") || host.equals("0:0:0:0:0:0:0:1")) {
                return true;
            }

            // 3. TLDs and hostnames reserved for local scope (RFC 6761)
            return host.equals("localhost") || host.endsWith(".localhost") || host.endsWith(".local");

        } catch (IllegalArgumentException e) {
            // Specific catch: origins with invalid URI syntax (e.g., forbidden characters like '_')
            // cannot be parsed as a valid URI, so they are fail-closed and not considered local.
            return false;
        }
    }
}
