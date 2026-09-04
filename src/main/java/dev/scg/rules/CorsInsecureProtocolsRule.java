package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.Locale;

public final class CorsInsecureProtocolsRule implements Rule {

    private static final Set<String> ORIGIN_KEYS = Set.of(
            "management.endpoints.web.cors.allowed-origins",
            "management.endpoints.web.cors.allowed-origin-patterns"
    );

    @Override
    public String id() {
        return "SCG004";
    }

    @Override
    public String description() {
        return "Use of an insecure protocol (http://) in non-loopback CORS origins";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        List<Finding> findings = new ArrayList<>();

        for (String originKey : ORIGIN_KEYS) {
            List<String> rawValues = RelaxedProperties.valuesForKeyOrListChildren(config.properties(), originKey);

            for (String rawValue : rawValues) {
                Optional<String> resolved = EnvironmentPlaceholder.resolve(rawValue);

                if (resolved.isEmpty()) {
                    findings.add(new Finding(
                            id(),
                            Severity.INFO,
                            ("CORS origin key '%s' relies on an unresolved environment placeholder '%s'. " +
                                    "Static analysis cannot verify if the runtime origin uses an insecure protocol (http://); " +
                                    "ensure production origins strictly enforce https:// in your environment settings.")
                                    .formatted(originKey, rawValue),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                    continue;
                }

                List<String> insecureOrigins = findInsecureOrigins(resolved.get());

                if (!insecureOrigins.isEmpty()) {
                    findings.add(new Finding(
                            id(),
                            Severity.MEDIUM,
                            ("Insecure CORS origin detected in key '%s': %s. " +
                                    "Using 'http://' in non-development environments exposes the application to Man-in-the-Middle (MitM) attacks. " +
                                    "Use HTTPS for remote origins or restrict HTTP origins strictly to loopback addresses.")
                                    .formatted(originKey, String.join(", ", insecureOrigins)),
                            config.sourceFile().toString(),
                            config.profileLabel()
                    ));
                }
            }
        }

        return findings;
    }

    private List<String> findInsecureOrigins(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }

        String[] tokens = value.split(",");
        List<String> insecure = new ArrayList<>();

        for (String token : tokens) {
            String origin = token.strip().toLowerCase(Locale.ROOT);
            if (origin.startsWith("http://") && !LoopbackAddresses.isLoopback(origin)) {
                insecure.add(token.strip());
            }
        }

        return insecure;
    }
}
