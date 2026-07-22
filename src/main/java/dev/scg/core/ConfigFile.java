package dev.scg.core;

import java.nio.file.Path;
import java.util.Map;

/** Um arquivo de config já carregado e achatado, junto com seu caminho de origem. */
public record ConfigFile(Path path, Map<String, String> properties) {
}
