package dev.scg.rules;

import dev.scg.core.Finding;
import dev.scg.core.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectionHostsTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "jdbc:mysql://localhost:3306/app?useSSL=false             | localhost",
            "jdbc:postgresql://db1:5432,db2:5432/app                   | db1,db2",
            "jdbc:sqlserver://127.0.0.1;encrypt=false                  | 127.0.0.1",
            "jdbc:sqlserver://localhost\\SQLEXPRESS;encrypt=false      | localhost",
            "mongodb://user:secret@localhost:27017,localhost:27018/app | localhost,localhost",
            "redis://:secret@localhost:6379                            | localhost",
            "http://es1:9200,http://es2:9200                           | es1,es2",
            "rabbit.internal:5672,127.0.0.1:5672                       | rabbit.internal,127.0.0.1",
            "[::1]:9092                                                | [::1]",
            "jdbc:h2:tcp://localhost/~/test                            | localhost",
            "localhost                                                 | localhost"
    })
    @DisplayName("Reads the host of every URI or host:port entry, without user info, port or path")
    void readsHosts(String value, String expected) {
        assertThat(ConnectionHosts.hosts(value)).contains(List.of(expected.split(",")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"jdbc:oracle:thin:@localhost:1521:XE", "(DESCRIPTION=(ADDRESS=(HOST=localhost)))",
            "redis://:pa/ss@localhost:6379", "fe80::1:5432", ""})
    @DisplayName("A value whose hosts can't all be read gives none, so it is never taken for loopback")
    void unreadableValueGivesNoHosts(String value) {
        assertThat(ConnectionHosts.hosts(value)).isEqualTo(Optional.empty());
        assertThat(ConnectionHosts.allLoopback(value)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"jdbc:mysql://localhost/app", "jdbc:mysql://LOCALHOST/app", "http://127.0.0.2:8200",
            "[::1]:9092", "localhost:9092,127.0.0.1:9093"})
    @DisplayName("localhost, 127.0.0.0/8 and ::1 are loopback")
    void loopbackHosts(String value) {
        assertThat(ConnectionHosts.allLoopback(value)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://a.localhost:9200", "localhost:9092,kafka.internal:9092",
            "http://localhost.evil.com", "http://127.0.0.1.nip.io", "http://0.0.0.0:8200"})
    @DisplayName("A *.localhost name, a look-alike or one remote host among loopback ones is not loopback")
    void notLoopback(String value) {
        assertThat(ConnectionHosts.allLoopback(value)).isFalse();
    }

    @Test
    @DisplayName("A loopback finding becomes INFO and says why; an INFO finding is returned as it is")
    void onLoopback() {
        Finding high = new Finding("SCG012", Severity.HIGH, "TLS disabled.", "application.yml", "prod");

        Finding info = ConnectionHosts.onLoopback(high);

        assertThat(info.severity()).isEqualTo(Severity.INFO);
        assertThat(info.message()).startsWith("TLS disabled. Lowered from HIGH to INFO:")
                .contains("loopback addresses", "local forwarder");
        assertThat(info).extracting(Finding::ruleId, Finding::sourceFile, Finding::profileLabel)
                .containsExactly("SCG012", "application.yml", "prod");
        assertThat(ConnectionHosts.onLoopback(info)).isSameAs(info);
    }

    @ParameterizedTest
    @ValueSource(strings = {"jdbc:postgresql://localhost/db?host=prod-db.internal&sslmode=disable",
            "jdbc:postgresql://localhost/db?PGHOST=remote",
            "jdbc:sqlserver://localhost;serverName=remote;encrypt=false",
            "jdbc:sqlserver://localhost;failoverPartner=remote",
            "jdbc:mysql://localhost/app?socksProxyHost=proxy.internal",
            "mongodb://localhost/app?proxyHost=proxy.internal",
            "mongodb+srv://localhost/app", "jdbc:mysql+srv://localhost/app"})
    @DisplayName("A parameter that overrides the host or routes elsewhere, or an SRV scheme, makes the hosts unreadable")
    void hostOverridesMakeHostsUnreadable(String value) {
        assertThat(ConnectionHosts.hosts(value)).isEmpty();
        assertThat(ConnectionHosts.allLoopback(value)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"${KAFKA_BROKERS:localhost:9092}", "jdbc:mysql://${DB_HOST:localhost}/app",
            "${DB_URL:jdbc:mysql://localhost/app?useSSL=false}"})
    @DisplayName("A value holding a placeholder is never loopback, even with a loopback default")
    void placeholderIsNotLoopback(String value) {
        assertThat(ConnectionHosts.allLoopback(value)).isFalse();
    }
}
