package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Rule;
import dev.scg.core.Severity;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * SCG002 — Detecta spring.h2.console.enabled=true fora de perfis de dev/test/local.
 *
 * O H2 Console é uma interface web que permite execução de SQL arbitrário na aplicação.
 * É extremamente útil para desenvolvimento local, mas um vetor crítico de RCE
 * (Remote Code Execution) e vazamento de dados se exposto em ambientes produtivos.
 */
public final class H2ConsoleExposedRule implements Rule {

    private static final String H2_ENABLED_KEY = "spring.h2.console.enabled";

    private static final Set<String> SAFE_PROFILE_TOKENS = Set.of(
            "dev", "development", "test", "testing", "local"
    );

    private static final Set<String> TRUTHY_VALUES = Set.of(
            "true", "yes", "on", "1"
    );

    @Override
    public String id() {
        return "SCG002";
    }

    @Override
    public String description() {
        return "H2 console habilitado fora de perfil de dev/test/local";
    }

    @Override
    public List<Finding> check(EffectiveConfig config) {
        String currentProfile = config.profileLabel().toLowerCase(Locale.ROOT);

        if (isSafeProfile(currentProfile)) {
            return List.of(); // Perfis locais/dev são isentos da checagem
        }

        String enabledValue = config.properties().get(H2_ENABLED_KEY);
        if (isTruthy(enabledValue)) {
            return List.of(new Finding(
                    id(),
                    Severity.HIGH,
                    "H2 console habilitado (%s=%s) no perfil '%s'. "
                            .formatted(H2_ENABLED_KEY, enabledValue, config.profileLabel())
                            + "Risco elevado de execução remota de código (RCE) e exposição de dados. "
                            + "Desabilite via 'spring.h2.console.enabled=false' fora de ambientes locais.",
                    config.sourceFile().toString(),
                    config.profileLabel()
            ));
        }

        return List.of();
    }

    /**
     * Verifica se o nome do perfil contém algum token seguro (ex: 'dev', 'test', 'local').
     * A divisão por hífens, sublinhados ou pontos evita falsos negativos em palavras
     * como 'delivery' ou 'devices'.
     */
    private boolean isSafeProfile(String profile) {
        String[] tokens = profile.split("[-_.]");
        for (String token : tokens) {
            if (SAFE_PROFILE_TOKENS.contains(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Avalia se a propriedade booleana é verdadeira considerando o relaxed binding
     * do Spring Boot (true, yes, on, 1).
     */
    private boolean isTruthy(String value) {
        return value != null && TRUTHY_VALUES.contains(value.trim().toLowerCase(Locale.ROOT));
    }
}