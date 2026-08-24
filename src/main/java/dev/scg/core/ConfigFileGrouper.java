package dev.scg.core;

import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Agrupa ConfigFile carregados individualmente por ConfigLoader.loadDirectory()
 * em unidades lógicas de configuração Spring Boot: application.{ext} (base) +
 * application-{profile}.{ext} (overlay), no mesmo diretório.
 *
 * Motivação (BL-15): ConfigLoader trata cada arquivo físico como um ConfigFile
 * independente, então ProfileMerger nunca funde application.yml com
 * application-prod.yml — cada um vira uma "config efetiva" isolada, cega para
 * o conteúdo do outro. Essa classe corrige isso numa camada separada, sem
 * reabrir o contrato já validado de ConfigLoader/ProfileMerger.
 *
 * Regra de profile para arquivo específico (application-{profile}.ext): o
 * nome do arquivo é a ÚNICA fonte de verdade. Confirmado que um Spring Boot
 * real rejeita (InvalidConfigDataPropertyException) qualquer
 * spring.config.activate.on-profile dentro desse tipo de arquivo — os dois
 * mecanismos (nome de arquivo vs. on-profile) são mutuamente exclusivos por
 * design do próprio framework, não uma questão de precedência a resolver.
 *
 * Escopo: agrupamento por convenção simples (mesmo diretório; prefixo
 * "application" já garantido por ConfigLoader.isSpringConfigFile). Nome-base
 * customizado (spring.config.name) e múltiplos diretórios com precedência
 * ficam fora de escopo — ver BL-17.
 */
public final class ConfigFileGrouper {

    private static final String PROFILE_SPECIFIC_PREFIX = "application-";

    public List<GroupedConfigFile> group(List<ConfigFile> rawFiles) {
        Map<Path, List<ConfigFile>> byDirectory = rawFiles.stream()
                .collect(Collectors.groupingBy(
                        file -> file.path().toAbsolutePath().getParent(),
                        LinkedHashMap::new,
                        Collectors.toList()
                ));

        List<GroupedConfigFile> result = new ArrayList<>();
        for (List<ConfigFile> filesInDirectory : byDirectory.values()) {
            result.add(mergeGroup(filesInDirectory));
        }
        return result;
    }

    private GroupedConfigFile mergeGroup(List<ConfigFile> filesInDirectory) {
        List<ConfigDocument> combinedDocuments = new ArrayList<>();
        Map<String, Path> sourceByProfileLabel = new LinkedHashMap<>();

        // Primeira passada: arquivos específicos de profile. Path desses
        // arquivos tem prioridade na rastreabilidade — se uma propriedade
        // aparece tanto no arquivo específico quanto num documento multi-doc
        // do base para o mesmo profile (caso raro), preferimos apontar para
        // o arquivo específico, mais provável de ser "onde consertar".
        for (ConfigFile file : filesInDirectory) {
            Optional<String> filenameProfile = extractProfileFromFilename(file.path());
            if (filenameProfile.isEmpty()) {
                continue;
            }
            for (ConfigDocument document : file.documents()) {
                combinedDocuments.add(new ConfigDocument(filenameProfile, document.properties()));
                sourceByProfileLabel.put(filenameProfile.get(), file.path());
            }
        }

        // Segunda passada: arquivo(s) base. Comportamento de multi-documento
        // via on-profile já resolvido corretamente por ConfigLoader — não
        // reprocessamos o profile aqui, só registramos a origem física.
        for (ConfigFile file : filesInDirectory) {
            if (extractProfileFromFilename(file.path()).isPresent()) {
                continue; // já tratado na primeira passada
            }
            for (ConfigDocument document : file.documents()) {
                combinedDocuments.add(document);
                String label = document.profile().orElse(ProfileMerger.BASE_PROFILE_LABEL);
                sourceByProfileLabel.putIfAbsent(label, file.path());
            }
        }

        Path representativePath = filesInDirectory.get(0).path();
        return new GroupedConfigFile(
                new ConfigFile(representativePath, combinedDocuments),
                sourceByProfileLabel
        );
    }

    /**
     * Extrai o profile do nome do arquivo, convenção application-{profile}.{ext}.
     * Optional.empty() para o arquivo base (application.{ext}, sem sufixo) ou
     * para um sufixo vazio malformado (application-.yml — edge case não testado,
     * tratado defensivamente como "sem profile" em vez de lançar exceção).
     */
    private Optional<String> extractProfileFromFilename(Path path) {
        String filename = path.getFileName().toString();
        if (!filename.startsWith(PROFILE_SPECIFIC_PREFIX)) {
            return Optional.empty();
        }

        int dotIndex = filename.lastIndexOf('.');
        String nameWithoutExtension = dotIndex >= 0 ? filename.substring(0, dotIndex) : filename;
        String profile = nameWithoutExtension.substring(PROFILE_SPECIFIC_PREFIX.length());

        return profile.isBlank() ? Optional.empty() : Optional.of(profile);
    }
}