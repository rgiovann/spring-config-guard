package dev.scg.core;

import java.util.List;

/**
 * Contrato que toda regra de verificação implementa.
 *
 * Recebe o EffectiveConfig inteiro (não parâmetros soltos) por dois
 * motivos: (1) evita Long Parameter List conforme o contexto cresce
 * (hoje já são 3 informações: arquivo, profile, propriedades); (2)
 * Open/Closed — adicionar um campo novo em EffectiveConfig no futuro
 * não exige alterar a assinatura deste método, nem recompilar/tocar
 * em regras que não usam o campo novo.
 */
public interface Rule {

    String id();

    String description();

    List<Finding> check(EffectiveConfig config);
}