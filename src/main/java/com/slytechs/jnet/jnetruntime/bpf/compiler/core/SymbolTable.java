package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.SemanticException;

/**
 * Manages symbols and scopes during compilation.
 */
public class SymbolTable {

    private Scope currentScope;

    /**
     * Constructs a new SymbolTable with a global scope.
     */
    public SymbolTable() {
        currentScope = new Scope(null); // Global scope
    }

    /**
     * Enters a new scope.
     */
    public void enterScope() {
        currentScope = new Scope(currentScope);
    }

    /**
     * Exits the current scope and returns to the parent scope.
     *
     * @throws IllegalStateException if there is no parent scope
     */
    public void exitScope() {
        if (currentScope.getParent() == null) {
            throw new IllegalStateException("Cannot exit global scope");
        }
        currentScope = currentScope.getParent();
    }

    /**
     * Defines a new symbol in the current scope.
     *
     * @param symbol the symbol to define
     * @throws SemanticException if the symbol is already defined in the current scope
     */
    public void define(Symbol symbol) throws SemanticException {
        currentScope.define(symbol);
    }

    /**
     * Looks up a symbol by name in the current scope and parent scopes.
     *
     * @param name the name of the symbol
     * @return the symbol, or null if not found
     */
    public Symbol lookup(String name) {
        return currentScope.lookup(name);
    }

    /**
     * Gets the current scope.
     *
     * @return the current scope
     */
    public Scope getCurrentScope() {
        return currentScope;
    }
}
