package dev.scg.core;

import java.nio.file.Path;
import java.util.Map;

/**
 * Resultado do agrupamento de ConfigFileGrouper: um ConfigFile sintético
 * (documentos combinados de todos os arquivos físicos do mesmo grupo,
 * prontos para ProfileMerger.merge()) mais um mapa de rastreabilidade
 * que lembra, para cada profileLabel, qual arquivo físico originou aquele
 * profile — usado para corrigir EffectiveConfig.sourceFile() depois do merge,
 * já que ConfigFile só tem um único Path e o grupo pode ter vindo de vários
 * arquivos.
 */
public record GroupedConfigFile(ConfigFile mergedFile, Map<String, Path> sourceByProfileLabel) {
}
