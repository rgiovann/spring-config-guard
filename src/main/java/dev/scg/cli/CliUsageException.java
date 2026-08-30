package dev.scg.cli;

/** CLI usage error (missing or malformed argument, or invalid directory). */
public final class CliUsageException extends RuntimeException {
    public CliUsageException(String message) {
        super(message);
    }
}