package dev.scg.benchmark.vault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Imports configuration from Vault at startup (spring.config.import=optional:vault://, set by the
 * scenario script) and exits. There is no Vault server: the scenario script listens on Vault's port
 * and records whether the client spoke plain HTTP or started a TLS handshake.
 */
@SpringBootApplication
public class VaultApp {

    public static void main(String[] args) {
        System.exit(SpringApplication.exit(SpringApplication.run(VaultApp.class, args)));
    }
}
