package dev.scg.benchmark.h2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** An empty web app with the H2 console module on its classpath; the scenarios turn the console on or off. */
@SpringBootApplication
public class H2ConsoleApp {

    public static void main(String[] args) {
        SpringApplication.run(H2ConsoleApp.class, args);
    }
}
