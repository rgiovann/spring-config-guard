package dev.scg;

import dev.scg.core.*;
import dev.scg.rules.ActuatorExposureRule;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

/**
 * Entry point do CLI. Uso: java -jar spring-config-guard.jar [diretorio]
 *
 * Exit code 1 se houver algum Finding de severidade HIGH — é isso que faz
 * a ferramenta útil em CI (o build falha automaticamente).
 */
public final class Main {
/*
    public static void main(String[] args) throws IOException {
        // Não confiamos no locale do ambiente (runners de CI muitas vezes
        // vêm com locale POSIX, sem UTF-8). Forçamos explicitamente aqui
        // em vez de depender de -Dfile.encoding externo.
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));

        // Se você não passar nenhum argumento, ele assume Path.of("."),
        // ou seja, o diretório atual onde o comando tá sendo executado.
        Path target = args.length > 0 ? Path.of(args[0]) : Path.of(".");

        // ConfigLoader busca todos os arquivos no formato application*.properties
        // ou application*.yml dentro da pasta alvo.

        ConfigLoader loader = new ConfigLoader();
        List<ConfigFile> configFiles = loader.loadDirectory(target);

        if (configFiles.isEmpty()) {
            System.out.println("Nenhum application*.properties/yml encontrado em: " + target.toAbsolutePath());
            return;
        }

        RuleEngine engine = new RuleEngine(List.of(
                new ActuatorExposureRule()
                // próximas regras entram aqui, uma linha cada
        ));

        List<Finding> findings = engine.run(configFiles);

        System.out.println("spring-config-guard — " + configFiles.size() + " arquivo(s) analisado(s), "
                + engine.rules().size() + " regra(s) ativa(s)\n");

        if (findings.isEmpty()) {
            System.out.println("Nenhum problema encontrado.");
            return;
        }

        boolean hasHigh = false;
        for (Finding f : findings) {
            System.out.println(f);
            if (f.severity() == Severity.HIGH) hasHigh = true;
        }

        System.out.println("\n" + findings.size() + " achado(s) no total.");

        if (hasHigh) {
            System.exit(1); // faz o build falhar em CI quando plugado como step
        }
    }
*/
public static void main(String[] args) throws IOException {
    System.out.println("spring-config-guard: pipeline em refatoração (multi-profile), Main desativado temporariamente.");

    // TODO: reativar quando ProfileMerger existir.
    // O bloco abaixo está comentado porque RuleEngine.run() agora espera
    // List<EffectiveConfig>, e ainda não temos a peça que converte
    // List<ConfigFile> -> List<EffectiveConfig>.

        /*
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        Path target = args.length > 0 ? Path.of(args[0]) : Path.of(".");
        ConfigLoader loader = new ConfigLoader();
        List<ConfigFile> configFiles = loader.loadDirectory(target);
        if (configFiles.isEmpty()) {
            System.out.println("Nenhum application*.properties/yml encontrado em: " + target.toAbsolutePath());
            return;
        }
        RuleEngine engine = new RuleEngine(List.of(new ActuatorExposureRule()));
        List<Finding> findings = engine.run(configFiles);
        ...
        */
}
}
