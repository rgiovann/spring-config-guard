package dev.scg.core;

import java.util.List;
import java.util.Map;

/**
 * Contrato que toda regra de verificação implementa.
 *
 * Propositalmente enxuto: uma regra só recebe o mapa de config já achatado
 * e o nome do arquivo (pra atribuir a origem no Finding). Isso significa que
 * escrever uma regra nova nunca exige entender ConfigLoader — só precisa
 * saber "que chaves eu quero checar". É esse desacoplamento que faz uma
 * regra nova custar 10 minutos, não 1 hora.
 */
public interface Rule {

    /** Identificador curto e estável (ex: "SCG001"). Não muda entre versões — é a chave que aparece em CI logs. */
    String id();

    /** Descrição curta e legível para humanos, exibida no --list-rules. */
    String description();

    /** Executa a checagem sobre um mapa de config já achatado. Pode devolver lista vazia. */
    List<Finding> check(Map<String, String> config, String sourceFile);
}
