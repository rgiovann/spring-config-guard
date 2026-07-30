package dev.scg.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes do ProfileMerger — a peça que funde o documento base (sem profile)
 * de um ConfigFile com cada documento de profile nomeado, produzindo a
 * List<EffectiveConfig> que o RuleEngine efetivamente avalia.
 *
 * Diferente de ConfigLoaderTest, aqui construímos ConfigFile/ConfigDocument
 * diretamente em memória (sem passar por parsing de YAML/properties), para
 * isolar e testar só a lógica de merge, não a leitura de arquivo.
 */
class ProfileMergerTest {

    private static final Path FAKE_PATH = Path.of("application.yml");

    private final ProfileMerger merger = new ProfileMerger();

    private EffectiveConfig findByLabel(List<EffectiveConfig> configs, String label) {
        return configs.stream()
                .filter(e -> e.profileLabel().equals(label))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Nenhuma EffectiveConfig encontrada com label: " + label));
    }

    @Test
    @DisplayName("Arquivo com apenas documento base (sem profile nomeado) deve gerar exatamente 1 EffectiveConfig")
    void arquivoComApenasBaseDeveGerarUmaUnicaEffectiveConfig() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("server.port", "8080"))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        assertEquals(1, result.size());
        assertEquals("base", result.get(0).profileLabel());
        assertEquals("8080", result.get(0).properties().get("server.port"));
    }

    @Test
    @DisplayName("Deve fundir base com profile nomeado sem contaminação cruzada, herdando o que o profile não sobrescreveu")
    void deveFundirBaseComProfileNomeadoSemContaminacaoCruzada() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of(
                        "server.port", "8080",
                        "management.endpoint.env.enabled", "false"
                ))),
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of(
                        "management.endpoints.web.exposure.include", "*"
                )))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        assertEquals(2, result.size());

        EffectiveConfig base = findByLabel(result, "base");
        EffectiveConfig dev = findByLabel(result, "dev");

        // base não deve ter sido contaminado pelo profile dev
        assertFalse(base.properties().containsKey("management.endpoints.web.exposure.include"));
        assertEquals("8080", base.properties().get("server.port"));

        // dev deve ter TANTO o que é dele quanto o que herdou do base
        assertEquals("*", dev.properties().get("management.endpoints.web.exposure.include"));
        assertEquals("8080", dev.properties().get("server.port"));
        assertEquals("false", dev.properties().get("management.endpoint.env.enabled"));
    }

    @Test
    @DisplayName("Profile deve sobrescrever chave escalar que também existe no base")
    void profileDeveSobrescreverChaveEscalarQueTambemExisteNoBase() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of("logging.level.root", "INFO"))),
                new ConfigDocument(Optional.of("prod"), new LinkedHashMap<>(Map.of("logging.level.root", "WARN")))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        assertEquals("WARN", findByLabel(result, "prod").properties().get("logging.level.root"));
        assertEquals("INFO", findByLabel(result, "base").properties().get("logging.level.root"));
    }

    @Test
    @DisplayName("Lista deve ser SUBSTITUÍDA inteira pelo profile, não mesclada índice a índice")
    void listaDeveSerSubstituidaInteiraPeloProfileNaoMescladaIndiceAIndice() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins[0]", "a.com");
        baseProps.put("cors.allowed-origins[1]", "b.com");
        baseProps.put("cors.allowed-origins[2]", "c.com");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.allowed-origins[0]", "x.com"); // profile só redefine o índice 0

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("x.com", dev.properties().get("cors.allowed-origins[0]"));
        assertFalse(dev.properties().containsKey("cors.allowed-origins[1]"),
                "índice [1] do base não deveria sobrar quando o profile redefine a lista");
        assertFalse(dev.properties().containsKey("cors.allowed-origins[2]"),
                "índice [2] do base não deveria sobrar quando o profile redefine a lista");

        // base não deve ter sido afetado pelo merge feito para "dev"
        assertEquals(3, findByLabel(result, "base").properties().size());
    }

    @Test
    @DisplayName("Lista de mapas (Nível B) também deve ser substituída inteira, não mesclada por sub-chave")
    void listaDeMapasTambemDeveSerSubstituidaInteira() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.origins[0].name", "producao");
        baseProps.put("cors.origins[0].url", "https://a.com");
        baseProps.put("cors.origins[1].name", "staging");
        baseProps.put("cors.origins[1].url", "https://b.com");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.origins[0].name", "local");
        devProps.put("cors.origins[0].url", "http://localhost");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("local", dev.properties().get("cors.origins[0].name"));
        assertFalse(dev.properties().containsKey("cors.origins[1].name"));
        assertFalse(dev.properties().containsKey("cors.origins[1].url"));
    }

    @Test
    @DisplayName("Arquivo onde TODO bloco declara profile (nenhum base explícito) deve gerar base com mapa vazio")
    void arquivoSemBaseExplicitoDeveGerarBaseComMapaVazio() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of("server.port", "9090"))),
                new ConfigDocument(Optional.of("prod"), new LinkedHashMap<>(Map.of("logging.level.root", "WARN")))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        assertEquals(3, result.size()); // base(vazio) + dev + prod
        assertTrue(findByLabel(result, "base").properties().isEmpty());

        EffectiveConfig dev = findByLabel(result, "dev");
        assertEquals("9090", dev.properties().get("server.port"));
        assertFalse(dev.properties().containsKey("logging.level.root"));
    }

    @Test
    @DisplayName("Merges de profiles diferentes não devem compartilhar estado nem mutar o mapa original do base")
    void mergesDeProfilesDiferentesNaoDevemCompartilharEstado() {
        Map<String, String> baseProps = new LinkedHashMap<>(Map.of("a", "1"));
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of("b", "2"))),
                new ConfigDocument(Optional.of("prod"), new LinkedHashMap<>(Map.of("c", "3")))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        EffectiveConfig dev = findByLabel(result, "dev");
        EffectiveConfig prod = findByLabel(result, "prod");

        assertFalse(dev.properties().containsKey("c"), "dev não deveria enxergar chave exclusiva de prod");
        assertFalse(prod.properties().containsKey("b"), "prod não deveria enxergar chave exclusiva de dev");
        assertEquals(1, baseProps.size(), "o mapa original do documento base não deveria ser mutado pelo merge");
    }

    @Test
    @DisplayName("Base + dois profiles nomeados no mesmo arquivo devem gerar 3 EffectiveConfig completas e independentes")
    void baseComDoisProfilesNomeadosDeveGerarTresEffectiveConfigsIndependentes() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of(
                        "server.port", "8080",
                        "logging.level.root", "INFO"
                ))),
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of(
                        "management.endpoints.web.exposure.include", "*"
                ))),
                new ConfigDocument(Optional.of("prod"), new LinkedHashMap<>(Map.of(
                        "logging.level.root", "WARN"
                )))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        assertEquals(3, result.size()); // base + dev + prod

        EffectiveConfig base = findByLabel(result, "base");
        EffectiveConfig dev = findByLabel(result, "dev");
        EffectiveConfig prod = findByLabel(result, "prod");

        // base: só o que é dele, intacto
        assertEquals("8080", base.properties().get("server.port"));
        assertEquals("INFO", base.properties().get("logging.level.root"));
        assertFalse(base.properties().containsKey("management.endpoints.web.exposure.include"));

        // dev: herda porta e logging do base, ganha sua própria exposure
        assertEquals("8080", dev.properties().get("server.port"));
        assertEquals("INFO", dev.properties().get("logging.level.root"));
        assertEquals("*", dev.properties().get("management.endpoints.web.exposure.include"));

        // prod: herda porta do base, mas SOBRESCREVE logging.level.root, e não tem exposure nenhuma
        assertEquals("8080", prod.properties().get("server.port"));
        assertEquals("WARN", prod.properties().get("logging.level.root"));
        assertFalse(prod.properties().containsKey("management.endpoints.web.exposure.include"));
    }
}