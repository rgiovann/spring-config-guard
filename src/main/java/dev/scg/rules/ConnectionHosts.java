package dev.scg.rules;

import dev.scg.core.Finding;
import dev.scg.core.LoopbackAddresses;
import dev.scg.core.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The hosts a connection value points to, for the transport rules (SCG012, SCG014, SCG015, SCG016,
 * SCG017), and how they report a connection whose hosts are all on the local machine.
 * <p>
 * Traffic to a loopback address doesn't leave the host, so nobody on the network can read or alter
 * it; but a local forwarder (a proxy or sidecar on the same machine or pod) may relay it further,
 * and a client that discovers other nodes from the first one (Kafka's advertised listeners, a
 * MongoDB replica set) may then connect elsewhere. That is doubt, not proof: such a finding is
 * reported as {@link Severity#INFO} rather than silenced (CLAUDE.md, "Findings").
 * <p>
 * Only {@code localhost}, 127.0.0.0/8 and {@code ::1} count. Chromium resolves {@code *.localhost}
 * itself (SCG004), but a server-side client asks the system resolver, which had no answer for
 * {@code a.localhost} and so would ask DNS (VALIDATION.md, "SCG004 insecure origin scenarios"),
 * where an attacker could answer.
 * <p>
 * Only a host written literally counts: one that comes from a placeholder, even with a loopback
 * default ({@code ${DB_HOST:localhost}}), is usually replaced in deployment while the insecure
 * setting stays. A value is not read at all when the client may connect somewhere its hosts don't
 * say: an SRV scheme ({@code mongodb+srv://}, {@code jdbc:mysql+srv://}), looked up in DNS, or a
 * parameter that overrides the host or routes the connection elsewhere ({@code ?host=} for
 * PostgreSQL, {@code ;serverName=} for SQL Server, a SOCKS proxy, a failover partner).
 */
public final class ConnectionHosts {

    private static final Pattern HOST_NAME = Pattern.compile("[A-Za-z0-9._-]+");
    private static final Pattern PORT = Pattern.compile("\\d*");

    /**
     * Connection parameters that set the host or route the connection elsewhere, lower-cased: checked
     * against pgjdbc 42.7.4 ({@code host}, {@code PGHOST}) and mssql-jdbc 12.8.1 ({@code serverName},
     * {@code server}); the others are named in their drivers' documentation.
     */
    private static final List<String> HOST_OVERRIDING_PARAMETERS = List.of("host", "pghost", "servername", "server",
            "failoverpartner", "socksproxyhost", "proxyhost", "clientreroutealternateservername");

    private ConnectionHosts() {}

    /**
     * The hosts of a value with placeholders already resolved: one or more URIs or {@code host:port}
     * entries separated by commas ({@code jdbc:postgresql://a,b/db}, {@code http://a:9200,http://b:9200},
     * {@code a:9092,b:9092}). Empty when any entry's host can't be read (e.g. Oracle's
     * {@code jdbc:oracle:thin:@host:1521:SID}), so an unrecognized form is never taken for loopback.
     */
    public static Optional<List<String>> hosts(String value) {
        if (value.toLowerCase(Locale.ROOT).contains("+srv:") || overridesHost(value)) {
            return Optional.empty();
        }
        List<String> hosts = new ArrayList<>();
        for (String piece : value.split(",")) {
            String entry = piece.strip();
            if (entry.isEmpty()) {
                continue;
            }
            int schemeEnd = entry.indexOf("://");
            String rest = schemeEnd < 0 ? entry : entry.substring(schemeEnd + 3);
            int authorityEnd = indexOfAny(rest, "/?;#\\");
            String authority = authorityEnd < 0 ? rest : rest.substring(0, authorityEnd);
            authority = authority.substring(authority.lastIndexOf('@') + 1);
            Optional<String> host = host(authority);
            if (host.isEmpty()) {
                return Optional.empty();
            }
            hosts.add(host.get());
        }
        return hosts.isEmpty() ? Optional.empty() : Optional.of(List.copyOf(hosts));
    }

    /**
     * Whether every host of the value, as written, is a loopback address; false when a host can't be
     * read or the value holds a placeholder.
     */
    public static boolean allLoopback(String rawValue) {
        if (rawValue == null || rawValue.contains("${")) {
            return false;
        }
        return hosts(rawValue.strip()).map(hosts -> hosts.stream().allMatch(ConnectionHosts::isLoopback)).orElse(false);
    }

    private static boolean overridesHost(String value) {
        for (String parameter : value.split("[?&;]")) {
            int equals = parameter.indexOf('=');
            String name = equals > 0 ? parameter.substring(0, equals).strip().toLowerCase(Locale.ROOT) : "";
            if (HOST_OVERRIDING_PARAMETERS.contains(name)) {
                return true;
            }
        }
        return false;
    }

    /** {@code localhost}, 127.0.0.0/8 or {@code ::1}; not {@code *.localhost}. */
    static boolean isLoopback(String host) {
        String name = host.toLowerCase(Locale.ROOT);
        if (LoopbackAddresses.isLocalhostName(name)) {
            return name.equals("localhost");
        }
        return LoopbackAddresses.isLoopbackHost(name);
    }

    /**
     * The finding for a connection whose hosts are all loopback: INFO, with the reason appended. An
     * INFO finding is returned as it is.
     */
    public static Finding onLoopback(Finding finding) {
        if (finding.severity() == Severity.INFO) {
            return finding;
        }
        return new Finding(
                finding.ruleId(),
                Severity.INFO,
                finding.message() + " Lowered from " + finding.severity() + " to INFO: the connection only "
                        + "goes to loopback addresses, so its traffic doesn't leave the host, unless a local "
                        + "forwarder (a proxy or sidecar) relays it, or the client is sent on to other hosts from "
                        + "there (Kafka's advertised listeners, a MongoDB replica set).",
                finding.sourceFile(),
                finding.profileLabel());
    }

    private static Optional<String> host(String authority) {
        String host;
        String port;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) {
                return Optional.empty();
            }
            host = authority.substring(0, close + 1);
            String after = authority.substring(close + 1);
            if (!after.isEmpty() && !after.startsWith(":")) {
                return Optional.empty();
            }
            port = after.isEmpty() ? "" : after.substring(1);
        } else {
            int colon = authority.indexOf(':');
            host = colon < 0 ? authority : authority.substring(0, colon);
            port = colon < 0 ? "" : authority.substring(colon + 1);
            if (!HOST_NAME.matcher(host).matches()) {
                return Optional.empty();
            }
        }
        return PORT.matcher(port).matches() ? Optional.of(host) : Optional.empty();
    }

    private static int indexOfAny(String text, String characters) {
        for (int i = 0; i < text.length(); i++) {
            if (characters.indexOf(text.charAt(i)) >= 0) {
                return i;
            }
        }
        return -1;
    }
}
