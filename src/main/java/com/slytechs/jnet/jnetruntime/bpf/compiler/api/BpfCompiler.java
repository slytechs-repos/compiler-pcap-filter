package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

import com.slytechs.jnet.jnetruntime.bpf.compiler.core.CompilerOptions;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.ASTNode;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.TokenType;
import com.slytechs.jnet.jnetruntime.bpf.vm.core.BpfProgram;

/**
 * The primary interface for compiling source code into BPF programs.
 */
public interface BpfCompiler {

	/**
	 * Compiles the given source code into a BPF program.
	 *
	 * @param source the source code to compile
	 * @return the compiled BPF program
	 * @throws CompilerException if a compilation error occurs
	 */
	BpfProgram compile(String source) throws CompilerException;

	/**
	 * Compiles the given source code into a BPF program using the specified
	 * compiler options.
	 *
	 * @param source  the source code to compile
	 * @param options the compiler options to use
	 * @return the compiled BPF program
	 * @throws CompilerException if a compilation error occurs
	 */
	BpfProgram compile(String source, CompilerOptions options) throws CompilerException;

	/**
	 * Returns the compiler dialect being used.
	 *
	 * @return the compiler dialect
	 */
	<T extends TokenType, N extends ASTNode> CompilerDialect<T, N> getDialect();

	/**
	 * Sets the compiler options to use during compilation.
	 *
	 * @param options the compiler options to set
	 */
	void setOptions(CompilerOptions options);

	/**
	 * Gets the current compiler options.
	 *
	 * @return the compiler options
	 */
	CompilerOptions getOptions();
}
