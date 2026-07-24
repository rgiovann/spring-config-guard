package dev.scg.core;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

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

    /**
     * Parser YAML minimalista, feito à mão de propósito (v0.1 não tem
     * dependências externas — veja o README sobre trocar por snakeyaml).
     *
     * Suporta o que a maioria das configs do Spring realmente usa:
     * mapeamentos aninhados por indentação, comentários com #, valores
     * escalares (string/number/boolean), e LISTAS DE VALORES SIMPLES
     * (ex: "- https://a.com"), que viram chaves indexadas no estilo
     * relaxed-binding do próprio Spring: allowed-origins[0], allowed-origins[1]...
     *
     * NÃO suporta listas de mapas (ex: "- name: x\n  url: y") nem
     * âncoras/multi-doc — isso é uma limitação conhecida e documentada,
     * não um bug escondido. Se precisar disso, considere trocar por
     * snakeyaml (ver comentário no pom.xml).
     */
    private Map<String, String> loadYaml(Path p) throws IOException {
        List<String> lines = Files.readAllLines(p);
        Map<String, String> flat = new LinkedHashMap<>();
        // Pilha de (nível de indentação, prefixo de chave) para reconstruir
        // o caminho dotted conforme a indentação sobe e desce.
        Deque<int[]> indentStack = new ArrayDeque<>(); // [indent]
        Deque<String> keyStack = new ArrayDeque<>();

        // Estado da lista "corrente" sendo lida (Nível A: só valores simples).
        // Reseta sempre que a linha atual não é um item de lista, garantindo
        // que a próxima lista comece do índice 0.
        String currentListParentKey = null;
        int currentListIndex = -1;

        for (String rawLine : lines) {
            String line = stripComment(rawLine);
            if (line.isBlank()) continue;

            int indent = countLeadingSpaces(line);
            String content = line.strip();

            // Desempilha níveis mais profundos que a indentação atual
            while (!indentStack.isEmpty() && indentStack.peek()[0] >= indent) {
                indentStack.pop();
                keyStack.pop();
            }

            if (isListItem(content)) {
                String parentKey = keyStack.isEmpty() ? "" : keyStack.peek();
                int index = parentKey.equals(currentListParentKey) ? currentListIndex + 1 : 0;

                String itemValue = unquote(content.substring(1).strip());
                String fullKey = parentKey.isEmpty() ? "[" + index + "]" : parentKey + "[" + index + "]";
                flat.put(fullKey, itemValue);

                currentListParentKey = parentKey;
                currentListIndex = index;
                continue;
            }

            // Linha não é item de lista: qualquer lista em andamento termina aqui.
            currentListParentKey = null;
            currentListIndex = -1;

            int colonIdx = findKeyValueSeparator(content);
            if (colonIdx < 0) continue; // linha que não reconhecemos, ignora

            String key = content.substring(0, colonIdx).strip();
            String value = content.substring(colonIdx + 1).strip();
            String fullKey = keyStack.isEmpty() ? key : keyStack.peek() + "." + key;

            if (value.isEmpty()) {
                // é um mapeamento pai (as chaves filhas vêm nas próximas linhas)
                indentStack.push(new int[]{indent});
                keyStack.push(fullKey);
            } else {
                flat.put(fullKey, unquote(value));
            }
        }
        return flat;
    }

    /**
     * Detecta se a linha (já sem indentação, via .strip()) é um item de lista
     * YAML de valor simples: "- algo". Note o espaço exigido após o traço —
     * isso evita confundir com uma chave legítima que comece com hífen
     * (raro, mas possível: "-secret-key: valor" não deveria cair aqui).
     */
    private static boolean isListItem(String content) {
        return content.equals("-") || content.startsWith("- ");
    }

    private static String stripComment(String line) {
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);

            if (c == '\'' && !inDoubleQuote) {
                inSingleQuote = !inSingleQuote;
            } else if (c == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote;
            } else if (c == '#' && !inSingleQuote && !inDoubleQuote) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private static int countLeadingSpaces(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == ' ') i++;
        return i;
    }

    private static int findKeyValueSeparator(String content) {
        // ":" seguido de espaço ou fim de linha (evita confundir com valores tipo "http://...")
        for (int i = 0; i < content.length(); i++) {
            if (content.charAt(i) == ':' && (i == content.length() - 1 || content.charAt(i + 1) == ' ')) {
                return i;
            }
        }
        return -1;
    }

    private static String unquote(String value) {
        if (value.length() >= 2 &&
                ((value.startsWith("\"") && value.endsWith("\"")) ||
                 (value.startsWith("'") && value.endsWith("'")))) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }
}
