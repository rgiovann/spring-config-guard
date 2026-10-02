package dev.scg.benchmark.graphql;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

/** A one-query GraphQL endpoint at /graphql, the target of the CORS requests. */
@SpringBootApplication
public class GraphQlApp {

    public static void main(String[] args) {
        SpringApplication.run(GraphQlApp.class, args);
    }

    @Controller
    static class Queries {

        @QueryMapping
        String hello() {
            return "hello";
        }
    }
}
