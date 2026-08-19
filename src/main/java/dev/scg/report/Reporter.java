package dev.scg.report;

import dev.scg.core.Finding;

import java.io.PrintStream;
import java.util.List;

public interface Reporter {
    void report(List<Finding> findings, PrintStream out);
}