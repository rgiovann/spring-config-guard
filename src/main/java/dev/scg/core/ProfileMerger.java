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

     /**
     * Rótulo sintético usado para "nenhum profile ativo". Deliberadamente
     * um nome improvável de colidir com um profile Spring real (BL-02):
     * antes era a string simples "base", que colidia se algum profile real
     * fosse nomeado literalmente "base" (sintaticamente válido no Spring,
     * embora raro na prática). Pacote-visível de propósito, para que
     * ProfileMergerTest referencie esta constante em vez de duplicar a
     * string literal — evita o mesmo tipo de fragilidade se o valor mudar
     * de novo no futuro.
     */
    public static final String BASE_PROFILE_LABEL = "__spring_config_guard_base__";

    public List<EffectiveConfig> merge(ConfigFile configFile) {
        Map<String, String> baseProperties = findBaseProperties(configFile);

        List<EffectiveConfig> result = new ArrayList<>();
        result.add(new EffectiveConfig(
                configFile.path(),
                BASE_PROFILE_LABEL,
                Collections.unmodifiableMap(stripInternalSentinels(baseProperties))
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

        Set<String> canonicalListRootsInOverlay = new LinkedHashSet<>();
        Set<String> canonicalDotPrefixesInOverlay = new LinkedHashSet<>();
        Map<String, String> nullOverrides = new LinkedHashMap<>();

        for (String key : overlay.keySet()) {
            if (key.endsWith(ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX)) {
                String targetKey = key.substring(0, key.length() - ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX.length());
                nullOverrides.put(targetKey, null);

                String canonicalTarget = RelaxedProperties.canonicalize(targetKey);
                canonicalListRootsInOverlay.add(canonicalTarget);
                canonicalDotPrefixesInOverlay.add(canonicalTarget + ".");
            } else {
                int bracketIdx = key.indexOf('[');
                if (bracketIdx >= 0) {
                    String root = key.substring(0, bracketIdx);
                    canonicalListRootsInOverlay.add(RelaxedProperties.canonicalize(root));
                } else if (key.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX)) {
                    String root = key.substring(0, key.length() - ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX.length());
                    canonicalListRootsInOverlay.add(RelaxedProperties.canonicalize(root));
                } else if (isScalarRedefiningListInBase(key, base)) {
                    canonicalListRootsInOverlay.add(RelaxedProperties.canonicalize(key));
                }
            }
        }

        // Purga canônica: remove chaves indexadas de listas ou sub-propriedades (ponto)
        // herdadas do base que foram redefinidas no overlay
        merged.keySet().removeIf(baseKey -> {
            String canonicalBaseKey = RelaxedProperties.canonicalize(baseKey);
            String canonicalBaseRoot = extractCanonicalRoot(baseKey);

            boolean isListMatch = canonicalListRootsInOverlay.contains(canonicalBaseRoot);
            boolean isDotMatch = canonicalDotPrefixesInOverlay.stream().anyMatch(canonicalBaseKey::startsWith);

            return isListMatch || isDotMatch;
        });

        merged.putAll(overlay);
        merged.putAll(nullOverrides);
        return stripInternalSentinels(merged);
    }
    private String extractCanonicalRoot(String key) {
        String cleanKey = key;
        if (cleanKey.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX)) {
            cleanKey = cleanKey.substring(0, cleanKey.length() - ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX.length());
        } else if (cleanKey.endsWith(ConfigLoader.EMPTY_MAP_SENTINEL_SUFFIX)) {
            cleanKey = cleanKey.substring(0, cleanKey.length() - ConfigLoader.EMPTY_MAP_SENTINEL_SUFFIX.length());
        } else if (cleanKey.endsWith(ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX)) {
            cleanKey = cleanKey.substring(0, cleanKey.length() - ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX.length());
        }

        int bracketIdx = cleanKey.indexOf('[');
        if (bracketIdx >= 0) {
            cleanKey = cleanKey.substring(0, bracketIdx);
        }

        return RelaxedProperties.canonicalize(cleanKey);
    }

    /**
     * Detecta o cenário (b) do BL-03: overlayKey é uma chave escalar (sem
     * '[') cujo nome coincide exatamente com uma raiz de lista já indexada
     * no base (ex: overlayKey="cors.allowed-origins", e base tem
     * "cors.allowed-origins[0]"). Isso sinaliza relaxed-binding redefinindo
     * a lista inteira via string única.
     */
    private boolean isScalarRedefiningListInBase(String overlayKey, Map<String, String> base) {
        String canonicalOverlayKey = RelaxedProperties.canonicalize(overlayKey);
        return base.keySet().stream().anyMatch(baseKey -> {
            String canonicalBaseRoot = extractCanonicalRoot(baseKey);
            return canonicalBaseRoot.equals(canonicalOverlayKey);
        });
    }

    private static Map<String, String> stripInternalSentinels(Map<String, String> map) {
        Map<String, String> stripped = new LinkedHashMap<>(map);
        stripped.keySet().removeIf(k -> k.endsWith(ConfigLoader.EMPTY_LIST_SENTINEL_SUFFIX)
                || k.endsWith(ConfigLoader.EMPTY_MAP_SENTINEL_SUFFIX)
                || k.endsWith(ConfigLoader.NULL_SCALAR_SENTINEL_SUFFIX));
        return stripped;
    }
}