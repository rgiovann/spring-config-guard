package dev.scg.core;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Um único documento YAML dentro de um arquivo (delimitado por "---").
 * Para arquivos .properties, ou arquivos .yml sem "---", sempre existe
 * exatamente um ConfigDocument por arquivo, com profile vazio.
 *
 * Este é o "cru" — ainda não fundido com nada. ProfileMerger consome
 * uma lista de ConfigDocument (todos do mesmo arquivo) e produz
 * EffectiveConfig (o resultado já mesclado, pronto pras regras).
 */
public record ConfigDocument(
        Optional<String> profile,
        Map<String, String> properties
) {
    public ConfigDocument {
        Objects.requireNonNull(profile, "profile não pode ser null");
        Objects.requireNonNull(profile, "profile não pode ser null (use Optional.empty())");
        properties = Map.copyOf(properties);
    }
}