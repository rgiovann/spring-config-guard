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
        assertEquals(ProfileMerger.BASE_PROFILE_LABEL, result.get(0).profileLabel());
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

        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
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
        assertEquals("INFO", findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL).properties().get("logging.level.root"));
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
        assertEquals(3, findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL).properties().size());
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
        assertTrue(findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL).properties().isEmpty());

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

        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
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

    @Test
    @DisplayName("Profile deve poder adicionar uma lista nova mesmo que base não a tenha")
    void profileAdicionaListaNovaQueNaoExisteNoBase() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("server.port", "8080")),
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of(
                        "cors.origins[0]", "http://localhost"
                )))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("8080", dev.properties().get("server.port"));
        assertEquals("http://localhost", dev.properties().get("cors.origins[0]"));
    }

    @Test
    @DisplayName("Profile deve poder expandir uma lista com mais índices do que o base tinha")
    void profileDeveExpandirListaComMaisIndicesQueOBase() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("app.tags[0]", "v1");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("app.tags[0]", "v2");
        devProps.put("app.tags[1]", "v3");
        devProps.put("app.tags[2]", "v4");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);

        // dev deve ter os 3 elementos NOVOS do profile, não uma mistura com o base
        assertEquals(3, dev.properties().size());
        assertEquals("v2", dev.properties().get("app.tags[0]"));
        assertEquals("v3", dev.properties().get("app.tags[1]"));
        assertEquals("v4", dev.properties().get("app.tags[2]"));

        // base não deve ter sido afetado pelo merge feito para "dev"
        assertEquals(1, base.properties().size());
        assertEquals("v1", base.properties().get("app.tags[0]"));
    }

    @Test
    @DisplayName("Profile deve conseguir sobrescrever duas listas distintas simultaneamente, sem interferência cruzada")
    void profileSobrescreveMultiplasListasDistintasSimultaneamente() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.origins[0]", "a.com");
        baseProps.put("cors.origins[1]", "b.com");
        baseProps.put("logging.ignored[0]", "foo");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.origins[0]", "x.com");
        devProps.put("logging.ignored[0]", "bar");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals(2, dev.properties().size());
        assertEquals("x.com", dev.properties().get("cors.origins[0]"));
        assertFalse(dev.properties().containsKey("cors.origins[1]"),
                "cors.origins[1] do base deveria ter sido removido junto com a purga de cors.origins[0]");
        assertEquals("bar", dev.properties().get("logging.ignored[0]"));
    }

    @Test
    @DisplayName("BL-03(b): chave escalar (relaxed-binding) redefinindo lista do base deve purgar índices órfãos")
    void chaveEscalarRedefinindoListaDoBaseDevePurgarIndicesOrfaos() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins[0]", "a.com");
        baseProps.put("cors.allowed-origins[1]", "b.com");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.allowed-origins", "explicit-value"); // relaxed-binding do Spring

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("explicit-value", dev.properties().get("cors.allowed-origins"));
        assertFalse(dev.properties().containsKey("cors.allowed-origins[0]"),
                "índice órfão do base não deveria sobreviver quando o profile redefine via escalar");
        assertFalse(dev.properties().containsKey("cors.allowed-origins[1]"));
        assertEquals(1, dev.properties().size());
    }

    @Test
    @DisplayName("BL-03(b): redefinição escalar de uma lista não deve afetar outra lista não relacionada")
    void redefinicaoEscalarNaoDeveAfetarListaNaoRelacionada() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.origins[0]", "a.com");
        baseProps.put("cors.origins[1]", "b.com");
        baseProps.put("logging.ignored[0]", "foo");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.origins", "escalar-novo");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("escalar-novo", dev.properties().get("cors.origins"));
        assertFalse(dev.properties().containsKey("cors.origins[0]"));
        assertEquals("foo", dev.properties().get("logging.ignored[0]"), "lista não relacionada deveria continuar herdada intacta");
    }

    @Test
    @DisplayName("LIMITAÇÃO CONHECIDA: se existirem 2 documentos base (violando invariante do ConfigLoader), apenas o primeiro é usado e o segundo é silenciosamente perdido")
    void doisDocumentosBaseApenasPrimeiroEUsadoSegundoEPerdido() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of("a", "1"))),
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of("b", "2"))), // ignorado
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of("c", "3")))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig dev = findByLabel(result, "dev");

        // TODO(backlog): esta é uma violação da invariante que o ConfigLoader
        // garante na prática (nunca entrega 2 documentos com profile vazio no
        // mesmo ConfigFile). Este teste documenta o comportamento ATUAL do
        // ProfileMerger sob essa violação — não é o comportamento desejado.
        // Ver item de backlog "findBaseProperties perde dado silenciosamente
        // se invariante de documento único-base for violada".
        assertEquals("1", base.properties().get("a"));
        assertNull(base.properties().get("b"), "'b' do segundo documento base é perdido — comportamento conhecido, não corrigido");

        assertEquals("1", dev.properties().get("a"));
        assertNull(dev.properties().get("b"), "'b' nunca chega no profile dev, pois nem chegou no base");
        assertEquals("3", dev.properties().get("c"));
    }

    @Test
    @DisplayName("Documento base posicionado após profiles nomeados ainda deve ser encontrado e usado como base, independente de ordem")
    void baseAposProfilesDeveSerEncontradoIndependenteDeOrdem() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.of("dev"), new LinkedHashMap<>(Map.of("x", "1"))),
                new ConfigDocument(Optional.empty(), new LinkedHashMap<>(Map.of("base-only", "true")))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("true", base.properties().get("base-only"));
        assertEquals("true", dev.properties().get("base-only"), "dev deveria herdar base-only mesmo o base estando depois na lista");
        assertEquals("1", dev.properties().get("x"));
    }

    @Test
    @DisplayName("Merge não deve mutar o mapa original do documento de profile")
    void mergeNaoDeveMutarMapaDoProfile() {
        Map<String, String> profileProps = new LinkedHashMap<>(Map.of("x", "1"));
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("a", "1")),
                new ConfigDocument(Optional.of("dev"), profileProps)
        ));

        merger.merge(file);

        assertEquals(1, profileProps.size());
        assertEquals("1", profileProps.get("x"));
    }
    @Test
    @DisplayName("EffectiveConfig.properties() deve ser protegido contra mutação externa (BL-01 corrigido)")
    void effectiveConfigDeveSerProtegidoContraMutacaoExterna() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("a", "1")),
                new ConfigDocument(Optional.of("dev"), Map.of("x", "1"))
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertThrows(UnsupportedOperationException.class,
                () -> base.properties().put("chave-maliciosa", "valor-injetado"),
                "EffectiveConfig do base deveria bloquear mutação externa");

        assertThrows(UnsupportedOperationException.class,
                () -> dev.properties().put("chave-maliciosa", "valor-injetado"),
                "EffectiveConfig do profile deveria bloquear mutação externa");
    }

    @Test
    @DisplayName("BL-03(a): profile com lista vazia explícita deve limpar a lista perigosa herdada do base")
    void profileComListaVaziaExplicitaDeveLimparListaDoBase() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins[0]", "*");

        Map<String, String> prodProps = new LinkedHashMap<>();
        prodProps.put("cors.allowed-origins.__empty_list__", "true");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("prod"), prodProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig prod = findByLabel(result, "prod");
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);

        assertFalse(prod.properties().containsKey("cors.allowed-origins[0]"));
        assertFalse(prod.properties().containsKey("cors.allowed-origins.__empty_list__"),
                "a sentinela nunca deveria sobrar no resultado final exposto a uma Rule");
        assertEquals("*", base.properties().get("cors.allowed-origins[0]"),
                "base não deveria ser afetado pelo merge feito para prod");
    }

    @Test
    @DisplayName("BL-03(a): profile pode redefinir lista vazia como não-vazia, substituindo por completo")
    void profileRedefineListaVaziaComoNaoVazia() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins[0]", "a.com");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("cors.allowed-origins[0]", "novo.com");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertEquals("novo.com", dev.properties().get("cors.allowed-origins[0]"));
    }

    @Test
    @DisplayName("BL-03(a): base com lista vazia explícita, profile que não menciona a chave, deve herdar vazio sem vazar sentinela")
    void baseComListaVaziaHerdaVazioSemVazarSentinela() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("cors.allowed-origins.__empty_list__", "true");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("server.port", "9090");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);

        assertFalse(dev.properties().containsKey("cors.allowed-origins[0]"));
        assertFalse(dev.properties().containsKey("cors.allowed-origins.__empty_list__"));
        assertFalse(base.properties().containsKey("cors.allowed-origins.__empty_list__"));
        assertEquals("9090", dev.properties().get("server.port"));
    }

    @Test
    @DisplayName("BL-03(a): lista de objetos vazia (não só lista de escalares) também deve purgar corretamente via sentinela")
    void listaDeObjetosVaziaTambemDevePurgarCorretamente() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("users[0].name", "admin");
        baseProps.put("users[0].role", "SUPERUSER");
        baseProps.put("users[1].name", "guest");
        baseProps.put("users[1].role", "READONLY");

        Map<String, String> prodProps = new LinkedHashMap<>();
        prodProps.put("users.__empty_list__", "true");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("prod"), prodProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig prod = findByLabel(result, "prod");
        EffectiveConfig base = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);

        assertTrue(prod.properties().isEmpty(), "lista de objetos inteira deveria ter sido purgada");
        assertEquals(4, base.properties().size(), "base não deveria ser afetado pelo merge feito para prod");
    }

    @Test
    @DisplayName("BL-02 resolvido: profile explicitamente chamado 'base' não colide mais com o rótulo sintético")
    void profileExplicitamenteChamadoBaseNaoColideMaisComRotuloSintetico() {
        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), Map.of("a", "1")),
                new ConfigDocument(Optional.of("base"), Map.of("b", "2"))
        ));

        List<EffectiveConfig> result = merger.merge(file);

        assertEquals(2, result.size());

        EffectiveConfig sintetico = findByLabel(result, ProfileMerger.BASE_PROFILE_LABEL);
        EffectiveConfig doUsuario = findByLabel(result, "base");

        assertFalse(sintetico.properties().containsKey("b"), "o rótulo sintético não deveria ter herdado nada do profile 'base' real");
        assertEquals("1", doUsuario.properties().get("a"));
        assertEquals("2", doUsuario.properties().get("b"));
    }

    @Test
    @DisplayName("BL-08: Map vazio no profile NÃO deve purgar chaves do base (diferente de lista)")
    void mapVazioNoProfileNaoDevePurgarChavesDoBase() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("headers.x-app-name", "minha-app");
        baseProps.put("headers.x-region", "brasil");

        Map<String, String> prodProps = new LinkedHashMap<>();
        prodProps.put("headers.__empty_map__", "true"); // "headers: {}" no profile

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("prod"), prodProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig prod = findByLabel(result, "prod");

        assertEquals("minha-app", prod.properties().get("headers.x-app-name"),
                "Map funde por chave — diferente de List, headers:{} não apaga o que o base definiu");
        assertEquals("brasil", prod.properties().get("headers.x-region"));
        assertFalse(prod.properties().containsKey("headers.__empty_map__"),
                "a sentinela nunca deveria sobrar no resultado exposto a uma Rule");
    }

    @Test
    @DisplayName("BL-09: Profile com escalar null explícito deve redefinir chave do base para null")
    void profileComNullExplicitoDeveRedefinirChaveParaNull() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("app.feature-x.enabled", "true");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("app.feature-x.enabled.__null_scalar__", "true");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertTrue(dev.properties().containsKey("app.feature-x.enabled"), "A chave deve existir no mapa");
        assertNull(dev.properties().get("app.feature-x.enabled"), "O valor da chave deve ser null");
    }

    @Test
    @DisplayName("BL-09: Profile com escalar null em nó que era objeto no base deve purgar sub-chaves e resultar em null")
    void profileComNullEmNoObjetoDevePurgarSubChaves() {
        Map<String, String> baseProps = new LinkedHashMap<>();
        baseProps.put("db.connection.timeout", "30");
        baseProps.put("db.connection.host", "localhost");

        Map<String, String> devProps = new LinkedHashMap<>();
        devProps.put("db.connection.__null_scalar__", "true");

        ConfigFile file = new ConfigFile(FAKE_PATH, List.of(
                new ConfigDocument(Optional.empty(), baseProps),
                new ConfigDocument(Optional.of("dev"), devProps)
        ));

        List<EffectiveConfig> result = merger.merge(file);
        EffectiveConfig dev = findByLabel(result, "dev");

        assertFalse(dev.properties().containsKey("db.connection.timeout"));
        assertFalse(dev.properties().containsKey("db.connection.host"));
        assertTrue(dev.properties().containsKey("db.connection"));
        assertNull(dev.properties().get("db.connection"));
    }

}