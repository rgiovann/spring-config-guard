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
 * configuration, proving the application uses SpringDoc, and neither {@code springdoc.api-docs.enabled}
 * nor {@code springdoc.swagger-ui.enabled} is explicitly resolved to {@code false}.</p>
 *
 * <p>If environment placeholders (e.g., {@code ${ENABLE_SWAGGER}}) are used without static defaults
 * or resolve to empty values, an {@code INFO} finding is generated to alert on runtime uncertainty.</p>
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
        return "Exposed Swagger/OpenAPI documentation or UI endpoints in production";
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

        // 3. Evaluate Placeholder resolution / uncertainty for api-docs and swagger-ui
        FlagState apiDocsState = evaluateFlagState(rawApiDocs);
        FlagState swaggerUiState = evaluateFlagState(rawSwaggerUi);

        // Check if either flag is in UNRESOLVED or EMPTY_FALLBACK state -> Emit INFO finding
        if (apiDocsState.isUncertain() || swaggerUiState.isUncertain()) {
            String uncertainKey = apiDocsState.isUncertain() ? API_DOCS_ENABLED_KEY : SWAGGER_UI_ENABLED_KEY;
            String rawVal = apiDocsState.isUncertain() ? rawApiDocs : rawSwaggerUi;

            findings.add(new Finding(
                    id(),
                    Severity.INFO,
                    ("SpringDoc property '%s' relies on an unresolved environment placeholder or empty fallback '%s'. " +
                            "Static analysis cannot verify if Swagger/OpenAPI endpoints are disabled at runtime; " +
                            "ensure 'springdoc.api-docs.enabled' and 'springdoc.swagger-ui.enabled' are explicitly set to 'false' in production.")
                            .formatted(uncertainKey, rawVal),
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
            return findings; // Early return on uncertainty
        }

        // 4. Check if BOTH flags are explicitly resolved to "false" -> Safe, stay silent!
        boolean isApiDocsDisabled = apiDocsState.isDisabled();
        boolean isSwaggerUiDisabled = swaggerUiState.isDisabled();

        if (isApiDocsDisabled && isSwaggerUiDisabled) {
            return List.of();
        }

        // 5. Aggravating factor: springdoc.show-actuator=true
        FlagState showActuatorState = evaluateFlagState(rawShowActuator);
        boolean isActuatorExposedInSwagger = showActuatorState.isEnabled();

        // 6. Build MEDIUM Finding for exposure
        String message = buildExposureMessage(isApiDocsDisabled, isSwaggerUiDisabled, isActuatorExposedInSwagger);

        findings.add(new Finding(
                id(),
                Severity.MEDIUM,
                message,
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

    private String buildExposureMessage(boolean isApiDocsDisabled, boolean isSwaggerUiDisabled, boolean isActuatorExposed) {
        StringBuilder msg = new StringBuilder();
        msg.append("SpringDoc OpenAPI is enabled by default in production. ");

        if (!isApiDocsDisabled && !isSwaggerUiDisabled) {
            msg.append("Both OpenAPI docs ('springdoc.api-docs.enabled') and Swagger UI ('springdoc.swagger-ui.enabled') remain exposed. ");
        } else if (!isApiDocsDisabled) {
            msg.append("OpenAPI docs ('springdoc.api-docs.enabled') remain exposed. ");
        } else {
            msg.append("Swagger UI ('springdoc.swagger-ui.enabled') remains exposed. ");
        }

        msg.append("Exposing API documentation in production increases the attack surface by revealing internal routes, schemas, and parameters. ");

        if (isActuatorExposed) {
            msg.append("AGGRAVATING FACTOR: 'springdoc.show-actuator' is set to 'true', exposing sensitive Spring Actuator endpoints inside the OpenAPI documentation. ");
        }

        msg.append("Explicitly set both 'springdoc.api-docs.enabled=false' and 'springdoc.swagger-ui.enabled=false' for production profiles.");

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
