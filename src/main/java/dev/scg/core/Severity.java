package dev.scg.core;

/**
 * Severidade de um achado (finding). Usada tanto para exibição no relatório
 * quanto para decidir o exit code do processo (útil em CI).
 */
public enum Severity {
    HIGH,
    MEDIUM,
    LOW,
    INFO // Represents operational warnings, analytical uncertainties, or recommendations without confirmed risk.
}
