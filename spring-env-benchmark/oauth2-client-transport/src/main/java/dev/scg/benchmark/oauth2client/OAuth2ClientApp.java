package dev.scg.benchmark.oauth2client;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Runs one client_credentials grant for the registration "scg" at startup, with the
 * ClientRegistrationRepository Spring Boot auto-configures from spring.security.oauth2.client.*,
 * and exits. There is no authorization server: the scenario script listens where the token-uri or
 * issuer-uri points and records whether the client spoke plain HTTP or TLS, and whether the request
 * carried the client secret.
 */
@SpringBootApplication
public class OAuth2ClientApp {

    public static void main(String[] args) {
        System.exit(SpringApplication.exit(SpringApplication.run(OAuth2ClientApp.class, args)));
    }

    @Bean
    ApplicationRunner authorizeOnce(ClientRegistrationRepository registrations) {
        return args -> {
            var manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations,
                    new InMemoryOAuth2AuthorizedClientService(registrations));
            try {
                manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("scg").principal("scg").build());
            } catch (RuntimeException expected) {
                System.out.println("GRANT-ATTEMPT-DONE: " + expected.getClass().getSimpleName());
            }
        };
    }
}
