package dev.scg.rules;

import dev.scg.core.LoopbackAddresses;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CORS origin values as Spring's {@code CorsConfiguration} (spring-web 7.0.9) reads them, for the
 * rules that inspect {@code allowed-origins} and {@code allowed-origin-patterns}:
 * <ul>
 *     <li>a value is split on commas outside square brackets, so a pattern's port list
 *     ({@code http://localhost:[8080,8081]}) stays one origin, and each origin is trimmed, as is
 *     a trailing {@code /};</li>
 *     <li>in a pattern, {@code *} matches any sequence of characters, and a trailing {@code :[*]} or
 *     {@code :[8080,8081]} is a port list, not part of the host.</li>
 * </ul>
 */
public final class CorsOrigins {

    private static final Pattern PORT_SUFFIX = Pattern.compile("(.*):(\\[(\\*|\\d+(,\\d+)*)]|\\*|\\d+)");

    private CorsOrigins() {}

    /** The origins in a value, split as {@code CorsConfiguration} splits them. */
    public static List<String> split(String value) {
        List<String> origins = new ArrayList<>();
        int start = 0;
        boolean withinPortList = false;
        for (int i = 0; i < value.length(); i++) {
            switch (value.charAt(i)) {
                case '[' -> withinPortList = true;
                case ']' -> withinPortList = false;
                case ',' -> {
                    if (!withinPortList) {
                        add(origins, value.substring(start, i));
                        start = i + 1;
                    }
                }
                default -> { }
            }
        }
        add(origins, value.substring(start));
        return origins;
    }

    private static void add(List<String> origins, String origin) {
        String trimmed = origin.strip();
        if (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        if (!trimmed.isEmpty()) {
            origins.add(trimmed);
        }
    }

    /**
     * The host of an origin or pattern: what follows {@code ://}, without the port, a {@code *}
     * port or a port list. An IPv6 host keeps its brackets.
     */
    public static String host(String origin) {
        int schemeEnd = origin.indexOf("://");
        String hostAndPort = schemeEnd < 0 ? origin : origin.substring(schemeEnd + 3);
        Matcher port = PORT_SUFFIX.matcher(hostAndPort);
        return port.matches() && !port.group(1).isEmpty() ? port.group(1) : hostAndPort;
    }

    /**
     * Whether every origin a host can match is on the local machine ({@link LoopbackAddresses}).
     * With a wildcard, only when what follows the last {@code *} is a dot and a {@code localhost}
     * name ({@code *.localhost}): every match is then a subdomain of {@code localhost}. A wildcard
     * before an IP address ({@code *.127.0.0.1}) matches DNS names, not that address.
     */
    public static boolean isLoopbackHost(String host) {
        if (host.contains("*")) {
            String fixedSuffix = host.substring(host.lastIndexOf('*') + 1);
            return fixedSuffix.startsWith(".") && LoopbackAddresses.isLocalhostName(fixedSuffix.substring(1));
        }
        return LoopbackAddresses.isLoopbackHost(host);
    }
}
