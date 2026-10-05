package dev.scg.benchmark.health;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The same app with Spring Security: /actuator/health is open to everyone, and one user ("user",
 * role USER) can authenticate with HTTP Basic, so when-authorized can be compared for an anonymous
 * and an authenticated caller.
 */
@SpringBootApplication
public class HealthApp {

    public static void main(String[] args) {
        SpringApplication.run(HealthApp.class, args);
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Bean
    UserDetailsService users() {
        return new InMemoryUserDetailsManager(User.withUsername("user").password("{noop}pass").roles("USER").build());
    }
}
