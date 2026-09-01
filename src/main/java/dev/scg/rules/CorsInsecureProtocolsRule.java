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
                Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);

                if (resolved.isEmpty()) {
                    findings.add(new Finding(
                            id(),
                            Severity.INFO,
                            ("CORS origin key '%s' relies on an unresolved environment placeholder '%s'. " +
                                    "Static analysis cannot verify if the runtime origin uses an insecure protocol (http://); " +
                                    "ensure production origins strictly enforce https:// in your environment settings.")
                                    .formatted(originKey, rawValue),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                    continue;
                }

                List<String> insecureOrigins = findInsecureOrigins(resolved.get());

                if (!insecureOrigins.isEmpty()) {
                    findings.add(new Finding(
                            id(),
                            Severity.MEDIUM,
                            ("Insecure CORS origin detected in key '%s': %s. " +
                                    "Using 'http://' in non-development environments exposes the application to Man-in-the-Middle (MitM) attacks. " +
                                    "Use HTTPS for remote origins or restrict HTTP origins strictly to loopback addresses.")
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

        String[] tokens = value.split(",");
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
                return false;
            }

            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }

            host = host.toLowerCase(Locale.ROOT);

            // 1. Strict IPv4 loopback (127.0.0.0/8 according to RFC 1122)
            if (isIpv4Loopback(host)) {
                return true;
            }

            // 2. IPv6 loopback (::1, 0:0:0:0:0:0:0:1)
            if (host.equals("::1") || host.equals("0:0:0:0:0:0:0:1")) {
                return true;
            }

            // 3. TLD reserved for local scope by RFC 6761 (.localhost)
            return host.equals("localhost") || host.endsWith(".localhost");

        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean isIpv4Loopback(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }

        try {
            // Rejects leading zero in the first octet (e.g., "0127.0.0.1")
            if (parts[0].length() > 1 && parts[0].startsWith("0")) {
                return false;
            }

            int firstOctet = Integer.parseInt(parts[0]);
            if (firstOctet != 127) {
                return false;
            }

            for (int i = 1; i < 4; i++) {
                String part = parts[i];
                // Rejects leading zero in subsequent octets (e.g., "127.0.0.01")
                if (part.length() > 1 && part.startsWith("0")) {
                    return false;
                }

                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
