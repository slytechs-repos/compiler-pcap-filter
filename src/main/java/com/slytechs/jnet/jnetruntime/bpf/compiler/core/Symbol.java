package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

/**
 * Represents a symbol in the compiler, such as variables, functions, etc.
 */
public interface Symbol {

	/**
	 * Gets the name of the symbol.
	 *
	 * @return the symbol's name
	 */
	String getName();

	/**
	 * Gets the type of the symbol.
	 *
	 * @return the symbol's type
	 */
	SymbolType getType();

	/**
	 * Gets the scope in which the symbol is defined.
	 *
	 * @return the symbol's scope
	 */
	Scope getScope();
}
