package dev.scg.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds credentials embedded in a connection string or a JAAS configuration, by the shape of the
 * value alone. Every form below was confirmed against the client that reads it, in the versions
 * Spring Boot 4.1.1 manages (VALIDATION.md, "SCG007 credential forms"):
 * <ul>
 *     <li>user-info, {@code scheme://user:password@host}: MySQL, Redis, MongoDB, HTTP clients. Every
 *     node of a comma-separated list is checked. Stops at {@code / ? #}, so an {@code @} later in the
 *     path or query isn't read as user-info;</li>
 *     <li>a URL parameter ending in {@code password} after {@code ?}, {@code &} or {@code ;}:
 *     PostgreSQL, MySQL and MariaDB ({@code ?password=}), SQL Server and H2 ({@code ;password=}),
 *     and key store passwords passed the same way ({@code trustStorePassword=});</li>
 *     <li>Oracle's {@code jdbc:oracle:thin:user/password@host};</li>
 *     <li>a {@code password} key in a MySQL host specification, after {@code (} or {@code ,}:
 *     {@code jdbc:mysql://(host=db,user=app,password=...)} and
 *     {@code jdbc:mysql://address=(host=db)(password=...)}, in any {@code jdbc:mysql} sub-protocol
 *     ({@code replication}, {@code loadbalance});</li>
 *     <li>a JAAS option {@code password} or {@code clientSecret} (OAuthBearer), quoted or not: Kafka
 *     accepts all three spellings.</li>
 * </ul>
 * URL forms are only looked for in a value that starts with {@code jdbc:} or contains {@code ://};
 * JAAS options only in a value that names a {@code LoginModule}.
 */
final class EmbeddedCredentials {

    private static final Pattern USER_INFO = Pattern.compile("://[^/?#@:\\s]*:([^/?#@\\s]*)@");
    private static final Pattern PASSWORD_PARAMETER =
            Pattern.compile("[?&;][A-Za-z0-9._-]*password=([^&;#\\s]*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ORACLE_USER_PASSWORD =
            Pattern.compile("^jdbc:oracle:[a-z0-9]+:[^/@:\\s]+/([^@\\s]*)@", Pattern.CASE_INSENSITIVE);
    private static final Pattern MYSQL_HOST_PASSWORD =
            Pattern.compile("[(,]password=([^,)\\s]*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern JAAS_SECRET_OPTION = Pattern.compile(
            "(?<![A-Za-z])(?:password|clientSecret)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s;\"']*))",
            Pattern.CASE_INSENSITIVE);

    private EmbeddedCredentials() {
    }

    /** The credentials found, in order; an empty string for a slot present but empty ({@code user:@host}). */
    static List<String> find(String value) {
        List<String> found = new ArrayList<>();
        if (value == null || value.isBlank()) {
            return found;
        }
        if (value.contains("LoginModule")) {
            Matcher jaas = JAAS_SECRET_OPTION.matcher(value);
            while (jaas.find()) {
                found.add(firstNonNull(jaas.group(1), jaas.group(2), jaas.group(3)));
            }
        }
        boolean isConnectionString = value.toLowerCase(Locale.ROOT).startsWith("jdbc:") || value.contains("://");
        if (isConnectionString) {
            for (String node : value.split(",")) {
                Matcher userInfo = USER_INFO.matcher(node);
                if (userInfo.find()) {
                    found.add(userInfo.group(1));
                }
            }
            Matcher oracle = ORACLE_USER_PASSWORD.matcher(value.strip());
            if (oracle.find()) {
                found.add(oracle.group(1));
            }
            Matcher parameter = PASSWORD_PARAMETER.matcher(value);
            while (parameter.find()) {
                found.add(parameter.group(1));
            }
            if (value.strip().toLowerCase(Locale.ROOT).startsWith("jdbc:mysql")) {
                Matcher hostPassword = MYSQL_HOST_PASSWORD.matcher(value);
                while (hostPassword.find()) {
                    found.add(hostPassword.group(1));
                }
            }
        }
        return found;
    }

    private static String firstNonNull(String... values) {
        for (String value : values) {
            if (value != null) {
                return value;
            }
        }
        return "";
    }
}
