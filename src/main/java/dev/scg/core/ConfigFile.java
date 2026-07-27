package dev.scg.core;

import java.nio.file.Path;
import java.util.List;

/** Um arquivo de config já carregado e achatado, com seu caminho de origem. */
public record ConfigFile(Path path, List<ConfigDocument> documents) {
}