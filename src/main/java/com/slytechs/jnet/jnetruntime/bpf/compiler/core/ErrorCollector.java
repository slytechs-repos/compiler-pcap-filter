package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

import java.util.ArrayList;
import java.util.List;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;

/**
 * Collects and manages compiler errors.
 */
public class ErrorCollector {

    private final List<CompilerException> errors = new ArrayList<>();

    /**
     * Adds an error to the collector.
     *
     * @param exception the compiler exception to add
     */
    public void addError(CompilerException exception) {
        errors.add(exception);
    }

    /**
     * Checks if any errors have been collected.
     *
     * @return true if errors are present, false otherwise
     */
    public boolean hasErrors() {
        return !errors.isEmpty();
    }

    /**
     * Gets the list of collected errors.
     *
     * @return the list of errors
     */
    public List<CompilerException> getErrors() {
        return errors;
    }

    /**
     * Clears all collected errors.
     */
    public void clear() {
        errors.clear();
    }
}
