package dev.scg.rules;

import dev.scg.core.EffectiveConfig;
import dev.scg.core.Finding;
import dev.scg.core.Rule;
import dev.scg.core.Severity;

import java.util.List;

/**
 * SCG002 — Detecta spring.h2.console.enabled=true fora de perfis de dev/test/local.
 *
 * O H2 Console é uma interface web que permite execução de SQL arbitrário na aplicação.
 * É extremamente útil para desenvolvimento local, mas um vetor crítico de RCE
 * (Remote Code Execution) e vazamento de dados se exposto em ambientes produtivos.
 *
 * spring.h2.console.settings.web-allow-others (default false) controla se o console
 * aceita conexões remotas, não só localhost. Quando true, o risco escala de "quem tem
 * acesso à rede interna" para "qualquer host que alcance a aplicação pela rede" — a
 * regra mantém HIGH nos dois casos (decisão deliberada: sem novo nível de severidade),
 * mas diferencia a mensagem do finding pra deixar claro o agravante.
 */
public final class H2ConsoleExposedRule implements Rule {

    private static final String H2_ENABLED_KEY = "spring.h2.console.enabled";
    private static final String WEB_ALLOW_OTHERS_KEY = "spring.h2.console.settings.web-allow-others";

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
        if (SafeProfileClassifier.isSafeProfile(config.profileLabel())) {
            return List.of(); // Perfis locais/dev são isentos da checagem
        }

        String enabledValue = config.properties().get(H2_ENABLED_KEY);
        if (!RelaxedBoolean.isTruthy(enabledValue)) {
            return List.of();
        }

        boolean allowsRemoteAccess = RelaxedBoolean.isTruthy(config.properties().get(WEB_ALLOW_OTHERS_KEY));

        return List.of(new Finding(
                id(),
                Severity.HIGH,
                buildMessage(enabledValue, config, allowsRemoteAccess),
                config.sourceFile().toString(),
                config.profileLabel()
        ));
    }

    private String buildMessage(String enabledValue, EffectiveConfig config, boolean allowsRemoteAccess) {
        StringBuilder message = new StringBuilder(
                "H2 console habilitado (%s=%s) no perfil '%s'. "
                        .formatted(H2_ENABLED_KEY, enabledValue, config.profileLabel())
        );

        if (allowsRemoteAccess) {
            message.append("AGRAVANTE: %s=true — o console aceita conexões remotas, não só localhost. "
                            .formatted(WEB_ALLOW_OTHERS_KEY))
                    .append("Risco crítico de execução remota de código (RCE) por qualquer host que alcance a aplicação pela rede. ")
                    .append("Desabilite as duas propriedades fora de ambientes locais.");
        } else {
            message.append("Risco elevado de execução remota de código (RCE) e exposição de dados. ")
                    .append("Desabilite via 'spring.h2.console.enabled=false' fora de ambientes locais.");
        }

        return message.toString();
    }
}