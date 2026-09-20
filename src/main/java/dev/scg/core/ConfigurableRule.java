package dev.scg.core;

public interface ConfigurableRule extends Rule {

    /**
     * Root constant for the metadata directory on the classpath.
     */
    String METADATA_BASE_PATH = "rules-metadata/";

    /**
     * Resolves the full classpath location for the rule's metadata file
     * (e.g. "SCG006.yml"). No concrete rule needs to override this method.
     */
    default String metadataResource() {
        return METADATA_BASE_PATH + id() +".yml";
    }

    void configure(java.util.Map<String, java.util.List<String>> metadata);
}