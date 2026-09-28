package dev.scg.benchmark.spring_env_benchmark;

import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds benchmark properties so /actuator/configprops shows them exactly as Spring's Binder
 * resolves them: map entries merged key by key across base and profile, bracketed and dotted
 * spellings treated as the same key, lists taken from the highest-precedence source that defines
 * them, precedence already applied. /actuator/env can't show that, since it lists each property
 * source's raw keys separately.
 */
@ConfigurationProperties("app")
public record BenchmarkProperties(Map<String, String> bracketMap, ListCases lists, ObjectListCases objectLists,
        ShapeCases shapes) {

    /** One list per scenario of the same list written in different formats. */
    public record ListCases(
            List<String> propsComma,
            List<String> propsIndexed,
            List<String> spaced,
            List<String> propsEmpty,
            List<String> profileYamlEmpty,
            List<String> profilePropsEmpty,
            List<String> profileCommaOverIndexed,
            List<String> profileOmitsKey) {
    }

    /** One list of objects per scenario of a profile overriding part of a base list. */
    public record ObjectListCases(
            List<Server> partialOverride,
            List<Server> propertiesPartialOverride,
            List<Server> sameDirectoryOverride,
            List<Server> quotedIndex,
            List<Server> omitsKey) {
    }

    public record Server(String url, Integer port, String password) {
    }

    /** One property per scenario of a scalar and a map (or object) on the same key, by target type. */
    public record ShapeCases(
            Map<String, String> scalarThenMap,
            Map<String, String> mapThenScalar,
            String scalarThenMapAsString,
            String mapThenScalarAsString,
            Server scalarThenObject,
            Server objectThenScalar) {
    }
}
