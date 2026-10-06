package dev.scg.core;

import java.nio.file.Path;
import java.util.List;

/**
 * One Spring Boot configuration unit, the result of ConfigFileGrouper (one
 * directory) or ConfigServerAssembler (one service): every document of its
 * files, in Spring Boot's source order, lowest precedence first. ProfileMerger
 * folds, in this order, the documents that apply to each set of active
 * profiles it evaluates.
 *
 * @param path      the representative path, used as the source file when no document applies
 * @param documents the documents in ascending precedence
 */
public record GroupedConfigFile(Path path, List<SourceDocument> documents) {

    public GroupedConfigFile {
        documents = List.copyOf(documents);
    }
}
