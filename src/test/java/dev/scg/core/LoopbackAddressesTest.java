package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class LoopbackAddressesTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost:3000",
            "http://127.0.0.1:8080",
            "http://127.0.1.1:8080",
            "http://[::1]:3000",
            "http://app.localhost"
    })
    @DisplayName("Recognizes loopback/local-only origins")
    void recognizesLoopbackOrigins(String origin) {
        assertThat(LoopbackAddresses.isLoopback(origin)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://app.company.com",
            "http://app.local:8080",
            "http://127.attacker.com",
            "http://127.0.0.1.evil.org",
            "http://127.1.2.256",
            "http://127.0.0.1.com",
            "http://0127.0.0.1",
            "http://127.0.0.01",
            "http://localhost.attacker.com"
    })
    @DisplayName("Does not treat remote hosts, mDNS .local domains, or loopback-lookalike bypass attempts as loopback")
    void doesNotRecognizeNonLoopbackOrBypassAttempts(String origin) {
        assertThat(LoopbackAddresses.isLoopback(origin)).isFalse();
    }

    @Test
    @DisplayName("Fails closed (false) on a malformed URI instead of throwing")
    void failsClosedOnMalformedUri() {
        assertThat(LoopbackAddresses.isLoopback("http://an_invalid_syntax_origin.com")).isFalse();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    @DisplayName("Fails closed (false) on null, empty, or blank input")
    void failsClosedOnBlankInput(String origin) {
        assertThat(LoopbackAddresses.isLoopback(origin)).isFalse();
    }
}
