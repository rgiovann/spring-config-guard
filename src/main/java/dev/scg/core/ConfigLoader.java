package dev.scg.core;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import org.yaml.snakeyaml.Yaml;
import java.nio.charset.StandardCharsets;

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
     * Varre um diretório recursivamente para carregar todos os arquivos de configuração do Spring Boot.
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
     * <p>O método percorre a árvore de arquivos a partir do diretório fornecido, filtra aqueles que
     * cumprem a convenção do Spring Boot através de {@link #isSpringConfigFile(Path)} e delega a leitura
     * para {@link #loadProperties(Path)} ou {@link #loadYaml(Path)} dependendo da extensão do arquivo.</p>
     *
     * @param dir o caminho {@link Path} do diretório raiz a ser varrido
     * @return uma lista de {@link ConfigFile} contendo o caminho e as propriedades achatadas de cada arquivo encontrado;
     *         retorna uma lista vazia se o caminho fornecido não for um diretório válido
     * @throws IOException se ocorrer algum erro de I/O ao percorrer a árvore de arquivos ou ao ler um deles
     * Navegação Recursiva: Files.walk(dir) percorre o diretório e todas as suas
     * subpastas procurando arquivos.
     *
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

    /**
     * Verifica se um determinado arquivo é um arquivo de configuração válido do Spring Boot.
     *
     * <p>A validação checa se o nome do arquivo inicia com a convenção {@code "application"}
     * e termina com uma das extensões suportadas ({@code .properties}, {@code .yml} ou {@code .yaml}).</p>
     *
     * @param p o caminho {@link Path} do arquivo a ser verificado
     * @return {@code true} se o arquivo seguir a convenção de nome e extensão do Spring;
     *         {@code false} caso contrário
     */
    private static boolean isSpringConfigFile(Path p) {
        String name = p.getFileName().toString();
        return name.startsWith("application")
                && (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml"));
    }

    /**
     * Carrega e processa um arquivo no formato {@code .properties}, convertendo seu conteúdo
     * em um mapa plano de chave-valor.
     *
     * <p>O arquivo é lido através da classe {@link Properties} e transferido para um
     * {@link LinkedHashMap} para garantir a preservação da ordem de inserção das propriedades.</p>
     *
     * @param p o caminho {@link Path} do arquivo de propriedades a ser carregado
     * @return um {@link Map} contendo as chaves e seus respectivos valores como String
     * @throws IOException se ocorrer algum erro de I/O ao abrir ou ler o arquivo
     */
    private Map<String, String> loadProperties(Path p) throws IOException {
        Properties props = new Properties();

        try (var reader = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
            props.load(reader);
        }

        Map<String, String> flat = new LinkedHashMap<>();
        for (String name : props.stringPropertyNames()) {
            flat.put(name, props.getProperty(name));
        }
        return flat;
    }

    /**
     * Carrega e processa um arquivo no formato YAML, convertendo sua estrutura hierárquica
     * em um mapa plano de propriedades (notação por pontos).
     *
     * <p>O arquivo é lido através da biblioteca SnakeYAML e achatado via {@link #flatten(Object, String, Map)}
     * para facilitar a verificação de regras de segurança no motor da aplicação.</p>
     *
     * @param p o caminho {@link Path} do arquivo YAML a ser carregado
     * @return um {@link Map} contendo as chaves em formato achatado e seus respectivos valores como String
     * @throws IOException se ocorrer algum erro de I/O ao abrir ou ler o arquivo
     */
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
     * Achata recursivamente a estrutura de nós gerada pelo parser de YAML (SnakeYAML),
     * convertendo mapas e listas aninhadas em uma estrutura plana de chave-valor.
     *
     * <p>Para objetos do tipo {@link Map}, as chaves são concatenadas utilizando a notação de ponto
     * (ex: {@code server.port}). Para coleções do tipo {@link List}, o índice do elemento é retido entre
     * colchetes (ex: {@code spring.profiles[0]}). Tipos escalares são convertidos em String e salvos
     * diretamente no mapa de saída.</p>
     *
     * @param yamlNode o nó atual da estrutura YAML (pode ser um {@link Map}, {@link List}, tipo escalar ou {@code null})
     * @param prefix o prefixo acumulado da chave até o nó atual
     * @param flat o mapa {@link Map} de destino onde as chaves achatadas e seus valores serão armazenados
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
