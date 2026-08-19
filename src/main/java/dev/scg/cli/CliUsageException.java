package dev.scg.cli;

/** Erro de uso da CLI (argumento ausente, malformado, ou diretório inválido). */
public final class CliUsageException extends RuntimeException {
    public CliUsageException(String message) {
        super(message);
    }
}