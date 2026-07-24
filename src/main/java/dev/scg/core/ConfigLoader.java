package dev.scg.core;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import org.yaml.snakeyaml.Yaml;

/**
 * Encontra e carrega arquivos de configuração do Spring Boot
 * (application*.properties / application*.yml / .yaml) dentro de um diretório,
 * achatando cada um em um Map<String,String> de chave dotted -> valor.
 *
 * Por que achatar tudo em Map<String,String> em vez de manter a árvore do YAML?
 * Porque as regras não precisam navegar estrutura — elas só perguntam
 * "existe a chave management.endpoints.web.exposure.include, e qual o valor?".
 * Um mapa plano com chave dotted é exatamente como o Spring enxerga suas
 * próprias properties internamente (Environment.getProperty("a.b.c")).
 */
public final class ConfigLoader {

    /**
     * Varre o diretório em busca de arquivos application*.properties/yml/yaml
     * e devolve um ConfigFile por arquivo encontrado (não mescla entre arquivos —
     * cada Finding precisa apontar pro arquivo exato onde o problema está).
     *
     * Navegação Recursiva: Files.walk(dir) percorre o diretório e todas as suas
     * subpastas procurando arquivos.
     *
     * Filtro: A função isSpringConfigFile garante que só passem arquivos que
     * comecem com application e terminem com  .properties, .yml ou .yaml (ex:
     * application.yml, application-dev.properties).
     *
     * Decisão: Se terminar em .properties, ele chama o parser nativo do Java.
     * Se for .yml/.yaml, ele chama o parser manual.
     *
     * Uso do try-with-resources: O Stream<Path> do Files.walk abre recursos do
     * Sistema Operacional (handles de arquivos). O try (...) garante que tudo
     * seja fechado corretamente para evitar vazamento de memória.
     */
    public List<ConfigFile> loadDirectory(Path dir) throws IOException {
        List<ConfigFile> result = new ArrayList<>();
        if (!Files.isDirectory(dir)) {
            return result;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            List<Path> candidates = paths
                    .filter(Files::isRegularFile)
                    .filter(ConfigLoader::isSpringConfigFile)
                    .toList();

            for (Path p : candidates) {
                Map<String, String> flat = p.toString().endsWith(".properties")
                        ? loadProperties(p)
                        : loadYaml(p);
                result.add(new ConfigFile(p, flat));
            }
        }
        return result;
    }

    private static boolean isSpringConfigFile(Path p) {
        String name = p.getFileName().toString();
        return name.startsWith("application")
                && (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml"));
    }

    private Map<String, String> loadProperties(Path p) throws IOException {
        Properties props = new Properties();
        try (var in = Files.newInputStream(p)) {
            props.load(in);
        }
        Map<String, String> flat = new LinkedHashMap<>();
        for (String name : props.stringPropertyNames()) {
            flat.put(name, props.getProperty(name));
        }
        return flat;
    }

    private Map<String, String> loadYaml(Path p) throws IOException {

        Yaml yaml = new Yaml();

        try (var in = Files.newInputStream(p)) {

            Object root = yaml.load(in);

            Map<String, String> flat = new LinkedHashMap<>();

            flatten(root, "", flat);

            return flat;
        }
    }

    /**
     * Carrega um arquivo YAML do Spring Boot e o converte para um mapa plano
     * de propriedades.
     * Apenas valores escalares (folhas da árvore YAML) são adicionados ao mapa.
     * Nós intermediários (Map), listas e valores nulos não geram entradas.
     * Exemplo:
     * server:
     *   port: 8080
     * resulta em:
     * server.port=8080
     */

    private void flatten(Object yamlNode,
                         String prefix,
                         Map<String, String> flat) {

        if (yamlNode == null) {
            return;
        }

        if (yamlNode instanceof Map<?, ?> map) {

            for (var entry : map.entrySet()) {

                String child = prefix.isEmpty()
                        ? entry.getKey().toString()
                        : prefix + "." + entry.getKey();

                flatten(entry.getValue(), child, flat);
            }

        } else if (yamlNode instanceof List<?> list) {

            for (int i = 0; i < list.size(); i++) {
                flatten(list.get(i), prefix + "[" + i + "]", flat);
            }

        } else {

            flat.put(prefix, String.valueOf(yamlNode));

        }
    }
}
