package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

/**
 * Represents semantic errors during compilation.
 */
public class SemanticException extends CompilerException {

    private static final long serialVersionUID = 6000829665300949959L;
	private final String symbolName;
    private final String details;

    /**
     * Constructs a new SemanticException with the specified details.
     *
     * @param message    the detail message
     * @param position   the position where the error occurred
     * @param symbolName the symbol related to the exception
     * @param details    additional details about the error
     */
    public SemanticException(String message, Position position, String symbolName, String details) {
        super(message, position);
        this.symbolName = symbolName;
        this.details = details;
    }

    /**
     * Gets the symbol name related to the exception.
     *
     * @return the symbol name
     */
    public String getSymbolName() {
        return symbolName;
    }

    /**
     * Gets additional details about the semantic error.
     *
     * @return the details
     */
    public String getDetails() {
        return details;
    }
}
