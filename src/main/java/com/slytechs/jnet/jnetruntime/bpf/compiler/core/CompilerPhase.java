package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;

/**
 * Represents a phase in the compilation pipeline.
 */
public abstract class CompilerPhase {

    protected CompilerContext context;

    /**
     * Executes the compiler phase.
     *
     * @throws CompilerException if an error occurs during execution
     */
    public abstract void execute() throws CompilerException;

    /**
     * Validates the results of the compiler phase.
     *
     * @throws CompilerException if validation fails
     */
    protected abstract void validate() throws CompilerException;
}
