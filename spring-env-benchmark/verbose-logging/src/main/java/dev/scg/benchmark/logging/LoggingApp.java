package dev.scg.benchmark.logging;

import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * One request carries a secret in each place a log can pick it up: POST /login?token=... with an
 * Authorization header and a JSON body, which runs a JdbcTemplate query and a JPA query with a
 * secret bound parameter and calls POST /echo through RestClient (Apache HttpClient 5) with its own
 * Authorization header and body. The scenario script then searches the log for each secret.
 */
@SpringBootApplication
public class LoggingApp {

    public static void main(String[] args) {
        SpringApplication.run(LoggingApp.class, args);
    }

    @RestController
    static class Login {

        private final JdbcTemplate jdbc;
        private final Accounts accounts;
        private final RestClient client;

        Login(JdbcTemplate jdbc, Accounts accounts, RestClient.Builder builder, Environment env) {
            this.jdbc = jdbc;
            this.accounts = accounts;
            this.client = builder.baseUrl("http://localhost:" + env.getProperty("server.port")).build();
        }

        @PostMapping("/login")
        String login(@RequestParam String token, @RequestBody Map<String, String> body) {
            jdbc.queryForObject("select count(*) from account where name = ?", Integer.class, "sql-param-secret");
            accounts.findByName("jpa-param-secret");
            return client.post().uri("/echo")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer outbound-header-secret")
                    .body(Map.of("apiKey", "outbound-body-secret"))
                    .retrieve().body(String.class);
        }

        @PostMapping("/echo")
        String echo(@RequestBody String body) {
            return "ok";
        }
    }
}
