package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

/**
 * Represents errors that occur during lexing.
 */
public class LexicalException extends CompilerException {

    private static final long serialVersionUID = 534426555517942576L;
	private final String invalidToken;
    private final int lineNumber;
    private final int columnNumber;

    /**
     * Constructs a new LexicalException with the specified details.
     *
     * @param message      the detail message
     * @param position     the position where the error occurred
     * @param invalidToken the invalid token encountered
     */
    public LexicalException(String message, Position position, String invalidToken) {
        super(message, position);
        this.invalidToken = invalidToken;
        this.lineNumber = position != null ? position.getLine() : -1;
        this.columnNumber = position != null ? position.getColumn() : -1;
    }

    /**
     * Gets the invalid token that caused the exception.
     *
     * @return the invalid token
     */
    public String getInvalidToken() {
        return invalidToken;
    }

    /**
     * Gets the line number where the error occurred.
     *
     * @return the line number
     */
    public int getLineNumber() {
        return lineNumber;
    }

    /**
     * Gets the column number where the error occurred.
     *
     * @return the column number
     */
    public int getColumnNumber() {
        return columnNumber;
    }
}
