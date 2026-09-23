package dev.scg.benchmark;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.scg.core.*;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Harness de validação do ProfileMerger contra uma aplicação Spring Boot real
 * (projeto separado {@code spring-env-benchmark}, fora deste repositório -- o
 * SCG não depende do Spring Boot, então essa app nunca vira dependência do
 * build; ver BACKLOG.md e VALIDATION.md para o motivo e os passos completos).
 *
 * <p>Pré-requisito: subir a aplicação 'spring-env-benchmark' na porta 8081
 * com o perfil 'prod' ativo
 * (ex: {@code mvn spring-boot:run "-Dspring-boot.run.profiles=prod"}).
 *
 * <p>A comparação não pode ser um diff cru de chave a chave: o Spring real
 * mantém {@code app.relaxed-binding-test} (do base) e {@code app.relaxedBindingTest}
 * (do profile) como duas entradas físicas separadas em PropertySources
 * diferentes -- a resolução por relaxed binding só acontece na hora de
 * *ler* a propriedade, não fisicamente. O {@code ProfileMerger} do SCG já
 * resolve isso estaticamente (só sobra uma chave, a do profile). Por isso
 * o mapa extraído do Actuator é canonicalizado ({@link RelaxedProperties#canonicalize})
 * antes de comparar, e o valor mantido por chave canônica é o da fonte de
 * MAIOR precedência que a declara -- não basta pegar a última ocorrência
 * bruta.
 */
@Disabled("Benchmark manual. Exige a aplicação spring-env-benchmark rodando na porta 8081.")
class ActuatorEnvComparisonTest {

    private static final String ACTUATOR_URL = "http://localhost:8081/actuator/env";
    private static final Path BENCHMARK_RESOURCES_PATH =
            Path.of("../spring-env-benchmark/src/main/resources");

    @Test
    void compareProfileMergerWithActuatorEnv() throws Exception {
        Map<String, String> scgProperties = scgEffectiveConfigForProfile("prod").properties();

        System.out.println("=== SCG EffectiveConfig (profile: prod) ===");
        new LinkedHashMap<>(scgProperties).forEach((k, v) -> System.out.println(k + " = " + v));
        System.out.println("============================================\n");

        String actuatorJson = fetchActuatorEnv();
        System.out.println("=== Spring Boot /actuator/env (raw) ===");
        System.out.println(actuatorJson);
    }

    @Test
    void validateProfileMergerAgainstSpringActuator() throws Exception {
        EffectiveConfig scgConfig = scgEffectiveConfigForProfile("prod");
        Map<String, String> scg = scgConfig.properties();

        String actuatorJson = fetchActuatorEnv();
        Map<String, String> spring = canonicalConfigResourceProperties(actuatorJson);

        // 1. Override escalar simples
        assertEquals(
                spring.get(RelaxedProperties.canonicalize("app.scalar-property")),
                RelaxedProperties.get(scg, "app.scalar-property"),
                "Override escalar simples deve ser idêntico"
        );

        // 2. Redefinição de lista -- a base tinha 2 itens, o profile redefine pra 1;
        // o resultado tem que ser exatamente o item novo, sem sobra do índice antigo.
        assertEquals("prod-single-item", scg.get("app.list-property[0]"),
                "Primeiro item da lista deve ser o valor redefinido pelo profile");
        assertNull(scg.get("app.list-property[1]"),
                "SCG não deve manter o segundo elemento da lista base após o override");

        // 3. Relaxed binding: base escreve 'relaxed-binding-test' (kebab-case), o
        // profile sobrescreve como 'relaxedBindingTest' (camelCase) -- têm que
        // resolver pro MESMO valor (o do profile) nos dois lados, apesar da
        // grafia diferente.
        String canonicalRelaxedKey = RelaxedProperties.canonicalize("app.relaxed-binding-test");
        assertEquals("camel-override", spring.get(canonicalRelaxedKey),
                "Spring real deve resolver a chave canônica pro valor do profile, não da base");
        assertEquals("camel-override", RelaxedProperties.get(scg, "app.relaxed-binding-test"),
                "SCG deve resolver a mesma chave canônica, escrita em kebab-case, pro valor do profile");
        assertEquals("camel-override", RelaxedProperties.get(scg, "app.relaxedBindingTest"),
                "E também escrita em camelCase -- é a mesma propriedade");

        // 4. Override para null explícito. O /actuator/env serializa um valor
        // null como string vazia (limitação da própria técnica de comparação,
        // não do SCG -- documentado no VALIDATION.md); no SCG, a chave
        // permanece no mapa com valor Java null de verdade.
        assertEquals("", spring.get(RelaxedProperties.canonicalize("app.nullable-override")),
                "Spring real serializa o override null como string vazia no JSON do /actuator/env");
        assertTrue(scg.containsKey("app.nullable-override"),
                "SCG deve manter a chave (não removê-la) quando o profile a sobrescreve com null");
        assertNull(scg.get("app.nullable-override"),
                "SCG deve resolver o override null como Java null de verdade, não string vazia");

        // 5. Placeholder com default, variável de ambiente não definida em
        // nenhum dos dois lados -- Spring resolve em runtime, SCG resolve
        // estaticamente; ambos devem bater no mesmo default.
        assertEquals(
                spring.get(RelaxedProperties.canonicalize("app.placeholder-with-default")),
                RelaxedProperties.get(scg, "app.placeholder-with-default"),
                "Sem a env var definida, os dois devem resolver pro mesmo valor de default"
        );

        System.out.println("Todos os critérios do benchmark do ProfileMerger bateram com o Spring Boot real.");
    }

    private EffectiveConfig scgEffectiveConfigForProfile(String profile) throws Exception {
        List<GroupedConfigFile> groups = new ConfigFileGrouper()
                .group(new ConfigLoader().loadDirectory(BENCHMARK_RESOURCES_PATH));

        for (GroupedConfigFile group : groups) {
            for (EffectiveConfig ec : new ProfileMerger().merge(group.mergedFile())) {
                if (profile.equalsIgnoreCase(ec.profileLabel())) {
                    return ec;
                }
            }
        }
        throw new IllegalStateException("Perfil '" + profile + "' não foi encontrado no merge do SCG");
    }

    private String fetchActuatorEnv() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(ACTUATOR_URL)).GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "Servidor Spring deve estar ativo na porta 8081");
        return response.body();
    }

    /**
     * Extrai só os PropertySources baseados em arquivo (cobre tanto a grafia
     * antiga do Spring Boot, {@code "applicationConfig: [...]"}, quanto a
     * atual no Boot 4.x, {@code "Config resource '...' via location '...'"} --
     * confirmado contra uma app real nesta sessão, não assumido de doc),
     * ignora systemEnvironment/systemProperties/etc., e resolve por chave
     * CANÔNICA (relaxed binding), mantendo o valor da fonte de maior
     * precedência -- o array do /actuator/env já vem ordenado da maior pra
     * menor precedência, então processar na ordem direta e nunca sobrescrever
     * uma chave canônica já vista resolve certo, sem precisar reimplementar
     * o merge do Spring.
     */
    private Map<String, String> canonicalConfigResourceProperties(String jsonResponse) throws Exception {
        Map<String, String> canonical = new LinkedHashMap<>();
        JsonNode root = new ObjectMapper().readTree(jsonResponse);

        for (JsonNode source : root.get("propertySources")) {
            String name = source.get("name").asText();
            if (!name.contains("Config resource") && !name.startsWith("applicationConfig:")) {
                continue;
            }

            JsonNode properties = source.get("properties");
            var fields = properties.fields();
            while (fields.hasNext()) {
                var entry = fields.next();
                String rawKey = entry.getKey();
                String canonicalKey = rawKey.contains("[")
                        ? rawKey // list index keys already match SCG's own bracket notation; don't canonicalize
                        : RelaxedProperties.canonicalize(rawKey);

                // First occurrence wins -- propertySources is already ordered
                // highest-precedence first by Spring itself.
                canonical.putIfAbsent(canonicalKey, entry.getValue().path("value").asText(""));
            }
        }
        return canonical;
    }
}
