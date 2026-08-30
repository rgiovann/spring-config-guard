package dev.scg.core;

import java.nio.file.Path;
import java.util.Map;

/**
 * Result of ConfigFileGrouper grouping: a synthetic ConfigFile
 * (documents combined from all physical files in the same group,
 * ready for ProfileMerger.merge()) plus a traceability map
 * that keeps track, for each profileLabel, which physical file
 * originated that profile — used to correct EffectiveConfig.sourceFile()
 * after the merge, since ConfigFile only has a single Path and the group
 * may have originated from multiple files.
 */
public record GroupedConfigFile(ConfigFile mergedFile, Map<String, Path> sourceByProfileLabel) {
}
