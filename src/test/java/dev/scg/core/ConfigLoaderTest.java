package dev.scg.core;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

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
    void deveRetornarMapaVazioParaArquivoSoComComentarios(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                # Apenas comentarios

                # Outro comentario
                """);

        assertTrue(values.isEmpty());
    }

    @Test
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
    void chaveDuplicadaNoMesmoNivelDeveUsarUltimoValor(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  name: Primeiro
                  name: Segundo
                """);

        assertEquals("Segundo", values.get("app.name"));
    }

    @Test
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

    /**
     * TESTE DE CARACTERIZAÇÃO (não é um "deveria passar assim").
     *
     * Documenta um bug conhecido: stripComment() corta a linha no primeiro '#',
     * mesmo se ele estiver dentro de uma string entre aspas. Isso significa que
     * um valor como "secr3t#123" é truncado incorretamente.
     *
     * Este teste existe para que, se alguém corrigir esse bug no futuro, o teste
     * QUEBRE de propósito — te forçando a vir aqui e atualizar a expectativa
     * conscientemente, em vez de a correção passar despercebida.
     *
     * TODO(SCG): tornar stripComment "quote-aware" antes de escrever qualquer
     * regra que precise inspecionar o CONTEÚDO de valores (não só a chave).
     */
    @Test
    void hashDentroDeAspasQuebraOValor(@TempDir Path tempDir) throws IOException {
        Map<String, String> values = parse(tempDir, """
                app:
                  password: "secr3t#123"
                """);

        // Comportamento ATUAL (incorreto): o valor fica truncado e com aspa sobrando.
        assertEquals("secr3t#123", values.get("app.password"),
                "se este assert falhar, o bug do '#' dentro de aspas foi corrigido — "
                        + "atualize este teste para assertEquals(\"secr3t#123\", ...) e remova este comentário");
    }

    private static String stripComment(String line) {
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);

            if (c == '\'' && !inDoubleQuote) {
                inSingleQuote = !inSingleQuote;
            } else if (c == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote;
            } else if (c == '#' && !inSingleQuote && !inDoubleQuote) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private Map<String, String> parse(Path tempDir, String yamlContent) throws IOException {
        Files.writeString(tempDir.resolve("application.yml"), yamlContent);
        List<ConfigFile> configFiles = new ConfigLoader().loadDirectory(tempDir);
        assertEquals(1, configFiles.size());
        return configFiles.get(0).properties();
    }
}