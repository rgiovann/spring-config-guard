package dev.scg.core;

import java.nio.file.Path;
import java.util.List;

/** A configuration file already loaded and flattened, with its source path. */
public record ConfigFile(Path path, List<ConfigDocument> documents) {
}