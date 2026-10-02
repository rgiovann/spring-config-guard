package dev.scg.rules;

import dev.scg.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * SCG008 — detects exposed Swagger/OpenAPI documentation and UI.
 *
 * <p>SpringDoc OpenAPI is opt-out (enabled by default when present on the classpath).
 * This rule triggers when any {@code springdoc.*} configuration property is detected in the effective
 * configuration, proving the application uses SpringDoc. What each flag turns off was checked in a
 * running Spring Boot 4.1.1 app with SpringDoc 3.1.1 (VALIDATION.md, "SCG008 SpringDoc scenarios"):</p>
 * <ul>
 *     <li>{@code springdoc.api-docs.enabled=false} turns SpringDoc off entirely: the spec and the
 *     Swagger UI both answer 404. Silent, whatever {@code springdoc.swagger-ui.enabled} says.</li>
 *     <li>{@code springdoc.swagger-ui.enabled=false} alone turns off the UI only: the spec at
 *     {@code /v3/api-docs} is still served (MEDIUM).</li>
 *     <li>Only {@code false}, in any case, disables: SpringDoc reads the flags through
 *     {@code @ConditionalOnProperty}, so {@code off}, {@code no} and {@code 0} leave everything on.</li>
 * </ul>
 *
 * <p>An environment placeholder without a static default (e.g., {@code ${ENABLE_DOCS}}), or one that
 * resolves to an empty value, in {@code springdoc.api-docs.enabled} is INFO: that flag decides whether
 * anything is exposed. In {@code springdoc.swagger-ui.enabled} it only decides whether the UI is, so the
 * spec's exposure is still reported as MEDIUM.</p>
 *
 * <p>Split across config locations (ADR-005), this rule can only err towards a false positive:
 * re-enabling SpringDoc takes a {@code springdoc.*} key, which triggers the rule in that location.</p>
 *
 * <p>Additionally, {@code springdoc.show-actuator=true} is evaluated as an aggravating factor that
 * expands the exposure surface by documenting Actuator endpoints in the OpenAPI spec.</p>
 *
 * <p>These property names are fixed facts about the SpringDoc library, not something a consumer
 * of this tool would ever need to override — so unlike SCG006/SCG007 this is a plain {@link Rule},
 * not a {@link ConfigurableRule}, mirroring {@link ActuatorExposureRule} and {@link H2ConsoleExposedRule}.</p>
 *
 * @see EnvironmentPlaceholder
 */
public final class SwaggerOpenApiExposedRule implements Rule {

    private static final String RULE_NAME = "SCG008";

    private static final String TARGET_PREFIX = "springdoc";
    private static final String API_DOCS_ENABLED_KEY = "springdoc.api-docs.enabled";
    private static final String SWAGGER_UI_ENABLED_KEY = "springdoc.swagger-ui.enabled";
    private static final String SHOW_ACTUATOR_KEY = "springdoc.show-actuator";

    @Override
    public String id() {
        return RULE_NAME;
    }

    @Override
    public String description() {
        return "Exposed Swagger/OpenAPI documentation or UI endpoints";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        Map<String, String> props = config.properties();

        // 1. Initial trigger: If NO property starts with 'springdoc.*', stay silent (absence of evidence).
        if (!RelaxedProperties.hasKeyWithPrefix(props, TARGET_PREFIX)) {
            return List.of();
        }

        List<Finding> findings = new ArrayList<>();

        // 2. Read raw values using relaxed binding
        String rawApiDocs = RelaxedProperties.get(props, API_DOCS_ENABLED_KEY);
        String rawSwaggerUi = RelaxedProperties.get(props, SWAGGER_UI_ENABLED_KEY);
        String rawShowActuator = RelaxedProperties.get(props, SHOW_ACTUATOR_KEY);

        // 3. springdoc.api-docs.enabled decides whether SpringDoc runs at all
        FlagState apiDocsState = evaluateFlagState(rawApiDocs);
        if (apiDocsState.isDisabled()) {
            return List.of(); // spec and UI both off (checked: 404 on both)
        }
        if (apiDocsState.isUncertain()) {
            findings.add(new Finding(
                    id(),
                    Severity.INFO,
                    ("SpringDoc property '%s' relies on an unresolved environment placeholder or empty fallback '%s'. " +
                            "Static analysis cannot verify if Swagger/OpenAPI endpoints are disabled at runtime; " +
                            "set 'springdoc.api-docs.enabled' to 'false' wherever exposure isn't intended.")
                            .formatted(API_DOCS_ENABLED_KEY, rawApiDocs),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
            return findings;
        }

        // 4. The spec is served; springdoc.swagger-ui.enabled only decides the UI
        FlagState swaggerUiState = evaluateFlagState(rawSwaggerUi);
        boolean isActuatorExposedInSwagger = evaluateFlagState(rawShowActuator).isEnabled();

        findings.add(new Finding(
                id(),
                Severity.MEDIUM,
                buildExposureMessage(swaggerUiState, rawSwaggerUi, isActuatorExposedInSwagger),
                config.sourceFile().toString(),
                config.profileLabel()
        ));

        return findings;
    }

    private FlagState evaluateFlagState(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return FlagState.NOT_SET; // Default behavior applies (enabled by default in SpringDoc)
        }

        String trimmed = rawValue.strip();
        Optional<String> resolved = EnvironmentPlaceholder.resolve(trimmed);

        if (resolved.isEmpty()) {
            return FlagState.UNRESOLVED;
        }

        String resolvedVal = resolved.get().strip().toLowerCase();
        if (resolvedVal.isBlank()) {
            return FlagState.EMPTY_FALLBACK;
        }

        if ("false".equals(resolvedVal)) {
            return FlagState.DISABLED;
        }

        if ("true".equals(resolvedVal)) {
            return FlagState.ENABLED;
        }

        return FlagState.OTHER_VALUE;
    }

    private String buildExposureMessage(FlagState swaggerUiState, String rawSwaggerUi, boolean isActuatorExposed) {
        StringBuilder msg = new StringBuilder();
        msg.append("SpringDoc OpenAPI is enabled by default when present on the classpath, regardless of profile. ");

        if (swaggerUiState.isDisabled()) {
            msg.append("The OpenAPI docs ('springdoc.api-docs.enabled') remain exposed; only the Swagger UI is disabled. ");
        } else if (swaggerUiState.isUncertain()) {
            msg.append(("The OpenAPI docs ('springdoc.api-docs.enabled') remain exposed; whether the Swagger UI is too " +
                    "depends on the unresolved value '%s' of 'springdoc.swagger-ui.enabled'. ").formatted(rawSwaggerUi));
        } else {
            msg.append("Both OpenAPI docs ('springdoc.api-docs.enabled') and Swagger UI ('springdoc.swagger-ui.enabled') remain exposed. ");
        }

        msg.append("Exposing API documentation increases the attack surface by revealing internal routes, schemas, and parameters. ");

        if (isActuatorExposed) {
            msg.append("AGGRAVATING FACTOR: 'springdoc.show-actuator' is set to 'true', exposing sensitive Spring Actuator endpoints inside the OpenAPI documentation. ");
        }

        msg.append("Set 'springdoc.api-docs.enabled=false', which turns off both the docs and the UI, unless exposing it in this profile is a deliberate, justified choice.");

        return msg.toString();
    }

    private enum FlagState {
        NOT_SET,
        ENABLED,
        DISABLED,
        UNRESOLVED,
        EMPTY_FALLBACK,
        OTHER_VALUE;

        boolean isDisabled() {
            return this == DISABLED;
        }

        boolean isEnabled() {
            return this == ENABLED;
        }

        boolean isUncertain() {
            return this == UNRESOLVED || this == EMPTY_FALLBACK;
        }
    }
}
