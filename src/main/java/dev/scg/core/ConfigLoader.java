package dev.scg.core;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import org.yaml.snakeyaml.Yaml;
import java.nio.charset.StandardCharsets;

/**
 * Encontra e carrega arquivos de configuração do Spring Boot
 * (application*.properties / application*.yml / .yaml) dentro de um diretório,
 * achatando cada um em um (ou mais) Map<String,String> de chave dotted -> valor.
 *
 * Um arquivo YAML pode conter múltiplos documentos separados por "---", cada
 * um opcionalmente associado a um profile via spring.config.activate.on-profile.
 * loadYaml devolve um ConfigDocument por rótulo de profile ENCONTRADO no arquivo
 * (documentos sem profile — incluindo múltiplos deles — são todos fundidos no
 * mesmo "base"; documentos com o mesmo profile nomeado também se fundem entre si).
 *
 * Importante: este método NÃO funde base com profile — isso é responsabilidade
 * do ProfileMerger, que consome a List<ConfigDocument> produzida aqui.
 */
public final class ConfigLoader {

    /** Chave de metadado do Spring que indica a qual profile um documento pertence. */
    private static final String ON_PROFILE_KEY = "spring.config.activate.on-profile";

    /** Rótulo interno usado na estrutura de agrupamento para representar "sem profile" (base). */
    private static final String BASE_LABEL = "";

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
                List<ConfigDocument> documents = p.toString().endsWith(".properties")
                        ? loadProperties(p)
                        : loadYaml(p);
                result.add(new ConfigFile(p, documents));
            }
        }
        return result;
    }

    private static boolean isSpringConfigFile(Path p) {
        String name = p.getFileName().toString();
        return name.startsWith("application")
                && (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml"));
    }

    private List<ConfigDocument> loadProperties(Path p) throws IOException {
        List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);

        // Estrutura intermediária para agrupar documentos pelo profile
        Map<String, List<Map<String, String>>> groupedByLabel = new LinkedHashMap<>();

        StringBuilder currentDocBuilder = new StringBuilder();

        for (String line : lines) {
            // O Spring Boot exige que o separador seja exatamente '#---' (ignorando espaços nas pontas)
            if (line.trim().equals("#---")) {
                processPropertiesDocument(currentDocBuilder.toString(), groupedByLabel);
                currentDocBuilder.setLength(0); // Limpa o buffer para o próximo documento
            } else {
                currentDocBuilder.append(line).append("\n");
            }
        }
        // Processa o último (ou único) bloco do arquivo
        processPropertiesDocument(currentDocBuilder.toString(), groupedByLabel);

        return buildConfigDocuments(groupedByLabel);
    }

    private void processPropertiesDocument(
            String rawContent,
            Map<String, List<Map<String, String>>> groupedByLabel
    ) throws IOException {
        if (rawContent.isBlank()) {
            return;
        }

        Properties props = new Properties();
        props.load(new StringReader(rawContent));

        if (props.isEmpty()) {
            return;
        }

        Map<String, String> flatDocument = new LinkedHashMap<>();
        for (String name : props.stringPropertyNames()) {
            flatDocument.put(name, props.getProperty(name));
        }

        // Extrai o profile usando a mesma chave constante ON_PROFILE_KEY
        String profileValue = flatDocument.get(ON_PROFILE_KEY);
        String label = (profileValue == null || profileValue.isBlank())
                ? BASE_LABEL
                : profileValue.strip();

        // Remove a chave de infraestrutura para não poluir as regras de linting
        flatDocument.remove(ON_PROFILE_KEY);

        groupedByLabel
                .computeIfAbsent(label, key -> new ArrayList<>())
                .add(flatDocument);
    }

    private List<ConfigDocument> buildConfigDocuments(
            Map<String, List<Map<String, String>>> groupedByLabel
    ) {
        List<ConfigDocument> result = new ArrayList<>();

        for (var entry : groupedByLabel.entrySet()) {
            String label = entry.getKey();
            List<Map<String, String>> mapsForLabel = entry.getValue();

            Map<String, String> merged = new LinkedHashMap<>();
            for (Map<String, String> flatDocument : mapsForLabel) {
                merged.putAll(flatDocument); // Último valor ganha em caso de chaves duplicadas no mesmo perfil
            }

            Optional<String> profile = label.equals(BASE_LABEL)
                    ? Optional.empty()
                    : Optional.of(label);

            result.add(new ConfigDocument(profile, merged));
        }

        // Mantém o invariante: todo ConfigFile possui ao menos 1 ConfigDocument
        if (result.isEmpty()) {
            result.add(new ConfigDocument(Optional.empty(), new LinkedHashMap<>()));
        }

        return result;
    }

    /**
     * Carrega um arquivo YAML que pode conter múltiplos documentos ("---"),
     * devolvendo um ConfigDocument por rótulo de profile distinto encontrado.
     *
     * Passo A/B/C (por documento bruto): achata, extrai spring.config.activate.on-profile
     * (tratando ausente/vazio como base, ponto de risco 5 — TODO warning fica pra quando
     * mexermos em Finding), remove a chave de metadado do mapa achatado (ponto de risco 4).
     *
     * Passo D (agrupamento): documentos com o MESMO rótulo (incluindo múltiplos "base")
     * são fundidos entre si, na ordem em que aparecem no arquivo — último valor de
     * chave duplicada vence, mesma regra que já usamos pra chave duplicada dentro
     * de um único documento.
     */
    private List<ConfigDocument> loadYaml(Path p) throws IOException {
        try (var in = Files.newInputStream(p)) {
            Yaml yaml = new Yaml();
            Iterable<Object> rawDocuments = yaml.loadAll(in);

            // LinkedHashMap preserva a ordem de PRIMEIRA aparição de cada rótulo no arquivo.
            Map<String, List<Map<String, String>>> groupedByLabel = new LinkedHashMap<>();

            for (Object rawDocument : rawDocuments) {
                if (rawDocument == null) {
                    // Ponto de risco 1: documento vazio (ex: "---" sozinho no fim do arquivo).
                    // Não gera ConfigDocument nenhum — simplesmente ignoramos.
                    continue;
                }

                Map<String, String> flatDocument = new LinkedHashMap<>();
                flatten(rawDocument, "", flatDocument);

                String profileValue = flatDocument.get(ON_PROFILE_KEY);
                String label = (profileValue == null || profileValue.isBlank())
                        ? BASE_LABEL
                        : profileValue.strip();

                // Ponto de risco 4: remove o metadado do mapa de dados — quem consome
                // o ConfigDocument não deveria enxergar essa chave como se fosse uma
                // propriedade de negócio comum.
                flatDocument.remove(ON_PROFILE_KEY);

                groupedByLabel
                        .computeIfAbsent(label, key -> new ArrayList<>())
                        .add(flatDocument);
            }

            return buildConfigDocuments(groupedByLabel);

        }
    }

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