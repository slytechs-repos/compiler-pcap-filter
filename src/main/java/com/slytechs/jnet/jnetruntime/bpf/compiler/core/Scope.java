package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

import java.util.HashMap;
import java.util.Map;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.Position;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.SemanticException;

/**
 * Represents a scope in the compiler, which can contain symbols.
 */
public class Scope {

	private final Scope parent;
	private final Map<String, Symbol> symbols = new HashMap<>();

	/**
	 * Constructs a new Scope with an optional parent scope.
	 *
	 * @param parent the parent scope, or null if this is the global scope
	 */
	public Scope(Scope parent) {
		this.parent = parent;
	}

	/**
	 * Defines a new symbol in this scope.
	 *
	 * @param symbol the symbol to define
	 * @throws SemanticException if the symbol already exists in this scope
	 */
	public void define(Symbol symbol) throws SemanticException {
		String name = symbol.getName();
		if (symbols.containsKey(name)) {
			Position position = null; // You may include position tracking in symbols
			throw new SemanticException(
					"Symbol already defined: " + name,
					position,
					name,
					"Duplicate symbol in the same scope.");
		}
		symbols.put(name, symbol);
	}

	/**
	 * Looks up a symbol by name, searching this scope and parent scopes.
	 *
	 * @param name the name of the symbol
	 * @return the symbol, or null if not found
	 */
	public Symbol lookup(String name) {
		Symbol symbol = symbols.get(name);
		if (symbol != null) {
			return symbol;
		} else if (parent != null) {
			return parent.lookup(name);
		} else {
			return null;
		}
	}

	/**
	 * Gets the parent scope.
	 *
	 * @return the parent scope, or null if this is the global scope
	 */
	public Scope getParent() {
		return parent;
	}
}
