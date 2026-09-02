package dev.scg.core;

public interface ConfigurableRule extends Rule {

    /**
     * Define a constante raiz para o diretório de metadados no classpath.
     */
    String METADATA_BASE_PATH = "rules-metadata/";

    /**
     * Retorna apenas o nome do arquivo da regra (ex: "SCG006.yml").
     */

    /**
     * Resolve o caminho completo no classpath.
     * Nenhuma regra concreta precisa sobrescrever este método!
     */
    default String metadataResource() {
        return METADATA_BASE_PATH + id() +".yml";
    }

    void configure(java.util.Map<String, java.util.List<String>> metadata);
}