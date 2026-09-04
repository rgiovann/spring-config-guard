package dev.scg.core;

import java.net.URI;
import java.util.Locale;

/**
 * Recognizes whether a URL/origin points to a loopback or otherwise local-only address,
 * as opposed to a remote host reachable over the network. Extracted from
 * {@code CorsInsecureProtocolsRule} (SCG004) so any future rule that needs to exempt
 * "insecure protocol pointed at a local address" from a finding shares the same,
 * already-hardened logic instead of reimplementing it.
 * <p>
 * Deliberately narrow: covers RFC 1122 IPv4 loopback (127.0.0.0/8), RFC 4291 IPv6 loopback
 * (::1), and the RFC 6761 special-use "localhost" domain (including .localhost subdomains).
 * ".local" (mDNS/Bonjour) is intentionally NOT treated as loopback — unlike "localhost", it
 * has no guarantee of resolving to the local machine, so http:// there still deserves a
 * finding.
 */
public final class LoopbackAddresses {

    private LoopbackAddresses() {}

    /**
     * @param origin a full origin/URL string (e.g. "http://127.0.0.1:8080"). Malformed input
     *               is treated fail-closed — returns false (not loopback) rather than throwing.
     */
    public static boolean isLoopback(String origin) {
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

    private static boolean isIpv4Loopback(String host) {
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
