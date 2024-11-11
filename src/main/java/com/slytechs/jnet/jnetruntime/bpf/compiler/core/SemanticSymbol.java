package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

/**
 * Concrete implementation of the Symbol interface.
 */
public class SemanticSymbol implements Symbol {

    private final String name;
    private final SymbolType type;
    private final Scope scope;

    /**
     * Constructs a new SemanticSymbol.
     *
     * @param name  the name of the symbol
     * @param type  the type of the symbol
     * @param scope the scope in which the symbol is defined
     */
    public SemanticSymbol(String name, SymbolType type, Scope scope) {
        this.name = name;
        this.type = type;
        this.scope = scope;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public SymbolType getType() {
        return type;
    }

    @Override
    public Scope getScope() {
        return scope;
    }
}
