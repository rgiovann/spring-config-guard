package dev.scg.core;

/**
 * Severity of a finding. Used both for display in the report and to
 * decide the process's exit code (useful in CI).
 */
public enum Severity {
    HIGH,
    MEDIUM,
    LOW,
    INFO // Represents operational warnings, analytical uncertainties, or recommendations without confirmed risk.
}
