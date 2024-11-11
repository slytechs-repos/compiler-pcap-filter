package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

/**
 * Represents the context of the compiler during compilation.
 */
public class CompilerContext {
	private final ErrorCollector errorCollector = new ErrorCollector();
	private final SymbolTable symbolTable = new SymbolTable();

	/**
	 * Gets the error collector.
	 *
	 * @return the error collector
	 */
	public ErrorCollector getErrorCollector() {
		return errorCollector;
	}

	/**
	 * Gets the symbol table.
	 *
	 * @return the symbol table
	 */
	public SymbolTable getSymbolTable() {
		return symbolTable;
	}
}
