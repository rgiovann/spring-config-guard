package dev.scg.benchmark.oauth2login;

import java.security.Principal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A web application whose only security is the oauth2Login Spring Boot auto-configures from
 * spring.security.oauth2.client.*: the scenario script drives its login (authorization_code) flow
 * with curl instead of a browser, and a listener stands in for the provider's token, JWK set and
 * user-info endpoints. /me answers the name of the user the login produced.
 */
@SpringBootApplication
@RestController
public class OAuth2LoginApp {

    public static void main(String[] args) {
        SpringApplication.run(OAuth2LoginApp.class, args);
    }

    @GetMapping("/me")
    String me(Principal principal) {
        return principal.getName();
    }
}
