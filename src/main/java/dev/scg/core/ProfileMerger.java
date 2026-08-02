package dev.scg.core;

import java.util.*;

/**
 * Funde o documento base (sem profile) de um ConfigFile com cada documento
 * de profile nomeado, produzindo uma EffectiveConfig por profile encontrado
 * + sempre uma EffectiveConfig para o base sozinho ("nenhum profile ativo").
 *
 * ConfigLoader já garante que existe no máximo 1 ConfigDocument por rótulo
 * de profile (documentos duplicados do mesmo rótulo já foram fundidos entre
 * si lá). ProfileMerger não precisa lidar com esse caso — só combina base
 * com profile, um de cada vez.
 *
 * Regra de merge: chave escalar do profile sobrescreve a do base; uma lista
 * inteira (identificada pelo prefixo antes do primeiro '[') é SUBSTITUÍDA,
 * nunca mesclada índice a índice — reflete o comportamento real do Spring
 * em runtime, onde redefinir uma lista descarta a lista anterior por completo.
 */
public final class ProfileMerger {

    private static final String BASE_PROFILE_LABEL = "base";

    public List<EffectiveConfig> merge(ConfigFile configFile) {
        Map<String, String> baseProperties = findBaseProperties(configFile);

        List<EffectiveConfig> result = new ArrayList<>();
        result.add(new EffectiveConfig(
                configFile.path(),
                BASE_PROFILE_LABEL,
                Collections.unmodifiableMap(stripEmptyListSentinels(baseProperties))
        ));

        for (ConfigDocument document : configFile.documents()) {
            if (document.profile().isEmpty()) {
                continue;
            }
            String profileLabel = document.profile().get();
            Map<String, String> merged = mergeProperties(baseProperties, document.properties());
            result.add(new EffectiveConfig(configFile.path(), profileLabel, Collections.unmodifiableMap(merged)));
        }

        return result;
    }

    private Map<String, String> findBaseProperties(ConfigFile configFile) {
        for (ConfigDocument document : configFile.documents()) {
            if (document.profile().isEmpty()) {
                return document.properties();
            }
        }
        return Map.of();
    }

    /**
     * Funde base + overlay (documento de profile). Chaves escalares do
     * overlay sobrescrevem as do base. Chaves de lista (formato "raiz[n]"
     * ou "raiz[n].subchave") no overlay fazem a lista inteira daquela raiz
     * ser REMOVIDA do base antes da sobreposição — não fica índice órfão
     * do base misturado com índice novo do overlay.
     */
    private Map<String, String> mergeProperties(Map<String, String> base, Map<String, String> overlay) {
        Map<String, String> merged = new LinkedHashMap<>(base);

        Set<String> listRootsInOverlay = new LinkedHashSet<>();
        for (String key : overlay.keySet()) {
            int bracketIdx = key.indexOf('[');
            if (bracketIdx >= 0) {
                listRootsInOverlay.add(key.substring(0, bracketIdx));
            } else if (key.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX)) {
                listRootsInOverlay.add(key.substring(0, key.length() - ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX.length()));
            }
        }

        for (String listRoot : listRootsInOverlay) {
            String bracketPrefix = listRoot + "[";
            String sentinelKey = listRoot + ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX;
            merged.keySet().removeIf(k -> k.startsWith(bracketPrefix) || k.equals(sentinelKey));
        }

        merged.putAll(overlay);
        return stripEmptyListSentinels(merged);
    }

    private static Map<String, String> stripEmptyListSentinels(Map<String, String> map) {
        Map<String, String> stripped = new LinkedHashMap<>(map);
        stripped.keySet().removeIf(k -> k.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX));
        return stripped;
    }
}