package dev.scg.core;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes do parser YAML manual em ConfigLoader.loadYaml.
 *
 * Cada teste isola um comportamento específico da lógica de indentação
 * (pilha), separação de comentários, ou tratamento de valores — para que,
 * se algum deles quebrar no futuro (ex: ao refatorar pra usar snakeyaml),
 * fique óbvio exatamente qual comportamento regrediu.
 */
class ConfigLoaderTest {

    @Test
    @DisplayName("Deve achatar o YAML mesmo com níveis de indentação complexos")
    void deveAchatarYamlComNiveisDeIndentacaoComplexos(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                server:
                  port: 8080
                  servlet:
                    context-path: /api
                """);

        assertEquals("8080", values.get("server.port"));
        assertEquals("/api", values.get("server.servlet.context-path"));
    }

    @Test
    @DisplayName("Deve achatar múltiplos níveis de aninhamento no YAML")
    void deveAchatarMultiplosNiveisDeAninhamento(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  database:
                    connection:
                      timeout: 30
                """);

        assertEquals("30", values.get("app.database.connection.timeout"));
    }

    @Test
    @DisplayName("Deve desempilhar múltiplos níveis de aninhamento ao retornar para a raiz no YAML")
    void deveDesempilharMultiplosNiveisDeUmaVezAoVoltarParaRaiz(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                a:
                  b:
                    c:
                      d: valor
                e: outro
                """);

        assertEquals("valor", values.get("a.b.c.d"));
        assertEquals("outro", values.get("e"));
    }

    @Test
    @DisplayName("Deve ignorar linhas em branco e comentários ao processar o arquivo")
    void deveIgnorarComentariosELinhasEmBranco(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                # Comentario de topo
                servidor:
                  # Comentario de bloco
                  porta: 8080 # porta principal

                  host: localhost
                """);

        assertEquals("8080", values.get("servidor.porta"));
        assertEquals("localhost", values.get("servidor.host"));
    }

    @Test
    @DisplayName("Deve remover aspas e espaços extras das extremidades dos valores")
    void deveLimparAspasEEspacosExtrasDosValores(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  nome:   "Meu Sistema"
                  versao: '1.0.0'
                """);

        assertEquals("Meu Sistema", values.get("app.nome"));
        assertEquals("1.0.0", values.get("app.versao"));
    }

    @Test
    @DisplayName("Deve manter os dois-pontos (:) como parte do valor quando estiverem dentro de uma String no YAML")
    void deveTratarDoisPontosDentroDoValorComoParteDoValor(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                servidor:
                  url: https://api.exemplo.com:443/v1
                  horario: "10:30"
                """);

        assertEquals("https://api.exemplo.com:443/v1", values.get("servidor.url"));
        assertEquals("10:30", values.get("servidor.horario"));
    }

    @Test
    @DisplayName("Deve retornar um mapa vazio ao processar um arquivo contendo apenas comentários")
    void deveRetornarMapaVazioParaArquivoSoComComentarios(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                # Apenas comentarios

                # Outro comentario
                """);

        assertTrue(values.isEmpty());
    }

    @Test
    @DisplayName("Não deve gerar entrada no mapa para uma chave pai que não possui filhos no YAML")
    void chavePaiSemFilhosNaoDeveGerarEntradaNoMapa(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                banco:
                  host: localhost
                config:
                """);

        assertEquals("localhost", values.get("banco.host"));
        assertFalse(values.containsKey("config"), "chave pai sem filhos não deveria virar entrada com valor vazio");
    }

    @Test
    @DisplayName("Deve concatenar corretamente uma chave já pontilhada ao prefixo do nó pai no YAML")
    void deveConcatenarChaveJaPontilhadaComPrefixoDeAninhamento(@TempDir Path tempDir) throws IOException {
        // Padrão comum em config Spring real: misturar "server.port: 8080" (chave já
        // dotted, uma linha só) com blocos aninhados de verdade no mesmo arquivo.
        Map<String, String> values = parse(tempDir, """
                server.port: 8080
                management:
                  endpoint:
                    health.show-details: always
                """);

        assertEquals("8080", values.get("server.port"));
        assertEquals("always", values.get("management.endpoint.health.show-details"));
    }

    @Test
    @DisplayName("Deve resetar o caminho das chaves ao alternar entre blocos irmãos no YAML")
    void deveResetarCaminhoDeChaveEntreBlocosIrmaos(@TempDir Path tempDir) throws IOException {
        // Diferente do caso de dedent linear: aqui dois blocos filhos do MESMO pai
        // aparecem em sequência. Garante que o keyStack não "vaza" moduleA para moduleB.
        Map<String, String> values = parse(tempDir, """
                app:
                  moduleA:
                    enabled: true
                  moduleB:
                    enabled: false
                """);

        assertEquals("true", values.get("app.moduleA.enabled"));
        assertEquals("false", values.get("app.moduleB.enabled"));
    }

    @Test
    @DisplayName("Deve sobrescrever o valor mantendo a última ocorrência quando houver chave duplicada no mesmo nível")
    void chaveDuplicadaNoMesmoNivelDeveUsarUltimoValor(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  name: Primeiro
                  name: Segundo
                """);

        assertEquals("Segundo", values.get("app.name"));
    }

    @Test
    @DisplayName("Deve diferenciar uma String vazia explícita com aspas de um nó pai sem valor no YAML")
    void stringVaziaExplicitaComAspasDeveDiferenciarDeNoPaiSemValor(@TempDir Path tempDir) throws IOException {
        // "" (com aspas) é um VALOR válido (string vazia). É diferente de uma chave
        // pai sem filhos (como no teste chavePaiSemFilhosNaoDeveGerarEntradaNoMapa).
        Map<String, String> values = parse(tempDir, """
                app:
                  description: ""
                  metadata:
                    owner: time-x
                """);

        assertTrue(values.containsKey("app.description"));
        assertEquals("", values.get("app.description"));
        assertEquals("time-x", values.get("app.metadata.owner"));
    }

    @Test
    @DisplayName("Deve processar corretamente arquivos YAML com níveis de indentação não padronizados")
    void deveFuncionarComLargurasDeIndentacaoNaoPadronizadas(@TempDir Path tempDir) throws IOException {
        // YAML não exige indentação de largura fixa — só exige que filhos tenham
        // indentação MAIOR que o pai. A pilha compara indent relativo, não múltiplos de 2.
        Map<String, String> values = parse(tempDir, """
                app:
                      database:
                            timeout: 30
                """);

        assertEquals("30", values.get("app.database.timeout"));
    }

    @Test
    @DisplayName("Deve converter uma lista de valores simples em chaves indexadas [0], [1] no YAML")
    void deveSuportarListaDeValoresSimplesComoChavesIndexadas(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
            app:
              tags:
                - java
                - spring
              name: Test
            """);

        assertEquals("java", values.get("app.tags[0]"));
        assertEquals("spring", values.get("app.tags[1]"));
        assertEquals("Test", values.get("app.name"));
    }

    @Test
    @DisplayName("Deve resetar os índices [0], [1] para cada nova lista encontrada no YAML")
    void duasListasSeguidasDevemResetarIndiceEntreElas(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
            app:
              primeira:
                - a
                - b
              segunda:
                - x
                - y
                - z
            """);

        assertEquals("a", values.get("app.primeira[0]"));
        assertEquals("b", values.get("app.primeira[1]"));
        assertEquals("x", values.get("app.segunda[0]"));
        assertEquals("z", values.get("app.segunda[2]"));
    }

    @Test
    @DisplayName("Deve manter o caractere hash (#) no valor quando estiver entre aspas no YAML")
    void hashDentroDeAspasDeveSerPreservado(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  password: "secr3t#123"
                """);

        // Comportamento ATUAL (incorreto): o valor fica truncado e com aspa sobrando.
        assertEquals("secr3t#123", values.get("app.password"),
                "Deveria ter preservado hash dentro de aspas.");
    }

    @Test
    @DisplayName("Deve carregar e processar corretamente um arquivo .properties válido")
    void shouldLoadPropertiesFileCorrectly(@TempDir Path tempDir) throws IOException {
        // 1. Arrange: Cria o arquivo application.properties temporário
        Path propertiesFile = tempDir.resolve("application.properties");
        String content = """
            # Comentário que deve ser ignorado
            server.port=8080
            spring.datasource.url: jdbc:postgresql://localhost:5432/db
            app.description = Aplicação de Teste
            """;
        Files.writeString(propertiesFile, content);

        ConfigLoader configLoader = new ConfigLoader();

        // 2. Act
        List<ConfigFile> configFiles = configLoader.loadDirectory(tempDir);

        // 3. Assert (usando org.junit.jupiter.api.Assertions.*)
        assertEquals(1, configFiles.size(), "Deveria ter encontrado exatamente 1 arquivo");

        ConfigFile configFile = configFiles.getFirst();
        assertEquals(propertiesFile, configFile.path());

        Map<String, String> properties = configFile.documents().get(0).properties();

        assertNotNull(properties);
        assertEquals("8080", properties.get("server.port"));
        assertEquals("jdbc:postgresql://localhost:5432/db", properties.get("spring.datasource.url"));
        assertEquals("Aplicação de Teste", properties.get("app.description"));
    }

    @Test
    @DisplayName("Deve carregar arquivos .properties e .yml do mesmo diretório")
    void shouldLoadBothYamlAndPropertiesFilesFromDirectory(@TempDir Path tempDir) throws IOException {
        // Arrange
        Path propFile = tempDir.resolve("application.properties");
        Files.writeString(propFile, "server.port=8080\n");

        Path yamlFile = tempDir.resolve("application.yml");
        Files.writeString(yamlFile, "server:\n  port: 9090\n");

        ConfigLoader configLoader = new ConfigLoader();

        // Act
        List<ConfigFile> configFiles = configLoader.loadDirectory(tempDir);

        // Assert
        assertEquals(2, configFiles.size(), "Deveria ter carregado 2 arquivos de configuração");
    }

    @Test
    @DisplayName("Deve carregar e achatar listas no YAML com notação de índice [0], [1]")
    void shouldFlattenYamlListsWithIndexNotation(@TempDir Path tempDir) throws IOException {
        String content = """
            spring:
              profiles:
                active:
                  - dev
                  - local
            management:
              endpoints:
                web:
                  exposure:
                    include:
                      - health
                      - info
            """;

        Map<String, String> props = parse(tempDir, content);

        assertEquals("dev", props.get("spring.profiles.active[0]"));
        assertEquals("local", props.get("spring.profiles.active[1]"));
        assertEquals("health", props.get("management.endpoints.web.exposure.include[0]"));
        assertEquals("info", props.get("management.endpoints.web.exposure.include[1]"));
    }

    @Test
    @DisplayName("Deve processar arquivo YAML vazio sem lançar exceções")
    void shouldHandleEmptyYamlFileWithoutExceptions(@TempDir Path tempDir) throws IOException {
        Map<String, String> props = parse(tempDir, "");

        assertTrue(props.isEmpty(), "O mapa de propriedades para YAML vazio deve ser vazio");
    }

    @Test
    @DisplayName("Deve carregar arquivo .properties preservando caracteres e acentuação em UTF-8")
    void shouldLoadPropertiesFileWithUtf8Encoding(@TempDir Path tempDir) throws IOException {
        Path propFile = tempDir.resolve("application.properties");
        String content = """
            # Configurações com acentos
            server.port=8080
            app.description=Aplicação de Teste com Acentuação
            app.empty-value=
            """;
        Files.writeString(propFile, content);

        List<ConfigFile> result = new ConfigLoader().loadDirectory(tempDir);

        assertEquals(1, result.size());
        Map<String, String> props = result.getFirst().documents().get(0).properties();

        assertEquals("8080", props.get("server.port"));
        assertEquals("Aplicação de Teste com Acentuação", props.get("app.description"));
        assertEquals("", props.get("app.empty-value"));
    }

    @Test
    @DisplayName("Deve ignorar arquivos que não seguem a convenção application*.properties/yml/yaml")
    void shouldIgnoreNonSpringConfigFiles(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("readme.txt"), "instrucoes=true");
        Files.writeString(tempDir.resolve("config.yml"), "server:\n  port: 8080");
        Files.writeString(tempDir.resolve("application.json"), "{}");

        List<ConfigFile> result = new ConfigLoader().loadDirectory(tempDir);

        assertTrue(result.isEmpty(), "Nenhum arquivo fora da convenção do Spring deveria ser carregado");
    }

    @Test
    @DisplayName("Deve achatar lista de mapas (Nível B) automaticamente via snakeyaml")
    void deveSuportarListaDeMapasComSnakeyaml(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
            cors:
              origins:
                - name: producao
                  url: https://a.com
                - name: staging
                  url: https://b.com
            """);

        assertEquals("producao", values.get("cors.origins[0].name"));
        assertEquals("https://a.com", values.get("cors.origins[0].url"));
        assertEquals("staging", values.get("cors.origins[1].name"));
        assertEquals("https://b.com", values.get("cors.origins[1].url"));
    }

    @Test
    @DisplayName("Documento YAML vazio ou ausente após separador '---' não deve quebrar o parsing")
    void documentoVazioAposUltimoSeparadorNaoDeveQuebrar(@TempDir Path tempDir) throws IOException {
        // Sub-caso A: "---" sozinho no fim do arquivo (documento fantasma no final)
        List<ConfigDocument> docsA = parseYaml(tempDir, "caseA", """
            server:
              port: 8080
            ---
            """);

        assertEquals(1, docsA.size(), "o '---' final sozinho não deveria gerar documento fantasma");
        assertTrue(docsA.get(0).profile().isEmpty());
        assertEquals("8080", docsA.get(0).properties().get("server.port"));

        // Sub-caso B: dois "---" seguidos (documento vazio no meio do arquivo)
        List<ConfigDocument> docsB = parseYaml(tempDir, "caseB", """
            server:
              port: 8080
            ---
            ---
            spring:
              config:
                activate:
                  on-profile: dev
            management:
              endpoints:
                web:
                  exposure:
                    include: "*"
            """);

        assertEquals(2, docsB.size(), "o bloco vazio entre os dois '---' deveria ser ignorado, não virar documento");
        assertTrue(docsB.get(0).profile().isEmpty());
        assertEquals("8080", docsB.get(0).properties().get("server.port"));
        assertEquals(Optional.of("dev"), docsB.get(1).profile());
        assertEquals("*", docsB.get(1).properties().get("management.endpoints.web.exposure.include"));
    }

    //===============================================================================================//
    //===============================================================================================//

    @Test
    @DisplayName("Deve separar um .properties em 2 documentos usando '#---' como separador")
    void devePropertiesComHashTresTracosSepararDoisDocumentos(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            server.port=8080
            #---
            spring.config.activate.on-profile=dev
            management.endpoints.web.exposure.include=*
            """);

        assertEquals(2, docs.size());
        assertTrue(docs.get(0).profile().isEmpty());
        assertEquals("8080", docs.get(0).properties().get("server.port"));

        assertEquals(Optional.of("dev"), docs.get(1).profile());
        assertEquals("*", docs.get(1).properties().get("management.endpoints.web.exposure.include"));
    }

    /**
     * Este é o teste de regressão do bug que encontramos: o Spring Boot aceita
     * tanto "#---" quanto "!---" como separador de documento em .properties.
     * Antes da correção, "!---" era tratado como uma linha de comentário comum
     * (ignorada), e os dois blocos ficavam indevidamente fundidos num só.
     */
    @Test
    @DisplayName("Deve separar um .properties em 2 documentos usando '!---' como separador (mesmo comportamento de '#---')")
    void devePropertiesComExclamacaoTresTracosSepararDoisDocumentos(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            server.port=8080
            !---
            spring.config.activate.on-profile=dev
            management.endpoints.web.exposure.include=*
            """);

        assertEquals(2, docs.size());
        assertTrue(docs.get(0).profile().isEmpty());
        assertEquals(Optional.of("dev"), docs.get(1).profile());
        assertEquals("*", docs.get(1).properties().get("management.endpoints.web.exposure.include"));

        // Ponto crítico do bug original: sem o profile "dev", exposure.include=*
        // não deveria "vazar" para o documento base.
        assertFalse(docs.get(0).properties().containsKey("management.endpoints.web.exposure.include"));
    }

    @Test
    @DisplayName("Deve fundir dois blocos .properties que compartilham o mesmo profile nomeado")
    void duasBlocosPropertiesComMesmoProfileDevemSerFundidos(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            #---
            spring.config.activate.on-profile=dev
            server.port=9090
            #---
            spring.config.activate.on-profile=dev
            management.endpoints.web.exposure.include=*
            """);

        assertEquals(1, docs.size());
        assertEquals(Optional.of("dev"), docs.get(0).profile());
        assertEquals("9090", docs.get(0).properties().get("server.port"));
        assertEquals("*", docs.get(0).properties().get("management.endpoints.web.exposure.include"));
    }

    @Test
    @DisplayName("Deve gerar 1 documento base vazio para .properties vazio ou só com comentários")
    void propertiesVazioOuSoComentarioDeveGerarUmDocumentoBaseVazio(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            # apenas um comentario
            # outro comentario
            """);

        assertEquals(1, docs.size());
        assertTrue(docs.get(0).profile().isEmpty());
        assertTrue(docs.get(0).properties().isEmpty());
    }

    @Test
    @DisplayName("Deve gerar apenas 1 documento base quando o .properties não tem nenhum separador (não-regressão)")
    void propertiesSemSeparadorDeveGerarApenasUmDocumentoBase(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            server.port=8080
            app.name=MeuApp
            """);

        assertEquals(1, docs.size());
        assertTrue(docs.get(0).profile().isEmpty());
        assertEquals("8080", docs.get(0).properties().get("server.port"));
        assertEquals("MeuApp", docs.get(0).properties().get("app.name"));
    }

    @Test
    @DisplayName("A chave spring.config.activate.on-profile deve ser removida do mapa final em .properties")
    void onProfileDeveSerRemovidoDoMapaFinalEmProperties(@TempDir Path tempDir) throws IOException {
        List<ConfigDocument> docs = parseProperties(tempDir, """
            #---
            spring.config.activate.on-profile=dev
            server.port=9090
            """);

        assertEquals(1, docs.size());
        assertFalse(docs.get(0).properties().containsKey("spring.config.activate.on-profile"),
                "a chave de metadado não deveria sobrar no mapa de propriedades de negócio");
    }


    private Map<String, String> parse(Path tempDir, String yamlContent) throws IOException {
        Files.writeString(tempDir.resolve("application.yml"), yamlContent);
        List<ConfigFile> configFiles = new ConfigLoader().loadDirectory(tempDir);
        assertEquals(1, configFiles.size());
        return configFiles.getFirst().documents().get(0).properties();
    }
    /**
     * Análogo ao parse(), mas para .properties e devolvendo a List<ConfigDocument>
     * completa (não o mapa achatado de 1 documento só) — necessário porque aqui
     * queremos verificar quantos documentos foram produzidos e como cada um
     * ficou, não só o resultado final de um documento único.
     */
    private List<ConfigDocument> parseProperties(Path tempDir, String content) throws IOException {
        Path file = tempDir.resolve("application.properties");
        Files.writeString(file, content);
        List<ConfigFile> configFiles = new ConfigLoader().loadDirectory(tempDir);
        assertEquals(1, configFiles.size());
        return configFiles.getFirst().documents();
    }
    private List<ConfigDocument> parseYaml(Path tempDir, String subDirName, String yamlContent) throws IOException {
        Path subDir = tempDir.resolve(subDirName);
        Files.createDirectories(subDir);
        Files.writeString(subDir.resolve("application.yml"), yamlContent);
        List<ConfigFile> configFiles = new ConfigLoader().loadDirectory(subDir);
        assertEquals(1, configFiles.size());
        return configFiles.getFirst().documents();
    }

}