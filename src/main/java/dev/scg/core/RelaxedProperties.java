package dev.scg.core;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Optional;

/**
 * Compara e busca chaves de propriedade respeitando o relaxed binding do
 * Spring Boot: kebab-case, camelCase e snake_case dentro do mesmo segmento
 * (entre pontos) são a mesma propriedade. Confirmado na wiki oficial
 * (Relaxed Binding 2.0): a comparação real remove '-'/'_' e converte para
 * minúsculas — NÃO reconstrói kebab-case, evitando qualquer ambiguidade de
 * onde inserir hífen em acrônimos (ex: apiURL).
 *
 * Escopo deliberado: não trata a regra de env var (underscore vira ponto),
 * que é exclusiva de variáveis de ambiente do SO — ConfigLoader só lê
 * arquivos .properties/.yml, nunca env vars.
 */
public final class RelaxedProperties {

    private RelaxedProperties() {}

    public static String canonicalize(String key) {
        if (key == null) return null;
        StringBuilder result = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c == '-' || c == '_') continue;
            if (c == '.') {
                result.append('.');
            } else {
                result.append(Character.toLowerCase(c));
            }
        }
        return result.toString();
    }

    /** Busca exata de uma chave, tolerante a kebab-case/camelCase/snake_case. */
    public static String get(Map<String, String> properties, String canonicalKey) {
        String target = canonicalize(canonicalKey);
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            if (canonicalize(entry.getKey()).equals(target)) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Valores de uma chave OU de seus filhos indexados (key[0], key[1]...),
     * tolerante a relaxed binding. Usado por regras que precisam checar
     * tanto a forma escalar quanto a forma de lista YAML de uma propriedade.
     */
    public static List<String> valuesForKeyOrListChildren(Map<String, String> properties, String canonicalKey) {
        String target = canonicalize(canonicalKey);
        String bracketPrefix = target + "[";
        List<String> values = new ArrayList<>();
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            String actual = canonicalize(entry.getKey());
            if (actual.equals(target) || actual.startsWith(bracketPrefix)) {
                values.add(entry.getValue());
            }
        }
        return values;
    }

    /** Retorna a chave real presente no mapa que canonicaliza para canonicalKey, se houver. */
    public static Optional<String> findActualKey(Map<String, String> properties, String canonicalKey) {
        String target = canonicalize(canonicalKey);
        for (String actualKey : properties.keySet()) {
            if (canonicalize(actualKey).equals(target)) {
                return Optional.of(actualKey);
            }
        }
        return Optional.empty();
    }
}