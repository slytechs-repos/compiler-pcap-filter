package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Token;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.TokenType;

/**
 * Represents errors that occur during parsing.
 */
public class ParserException extends CompilerException {

    private static final long serialVersionUID = -1903633913657690243L;
	private final TokenType expectedToken;
    private final Token<?> foundToken;

    /**
     * Constructs a new ParserException with the specified details.
     *
     * @param message       the detail message
     * @param position      the position where the error occurred
     * @param expectedToken the expected token type
     * @param foundToken    the token that was found instead
     */
    public ParserException(String message, Position position, TokenType expectedToken, Token<?> foundToken) {
        super(message, position);
        this.expectedToken = expectedToken;
        this.foundToken = foundToken;
    }

    /**
     * Gets the expected token type.
     *
     * @return the expected token type
     */
    public TokenType getExpectedToken() {
        return expectedToken;
    }

    /**
     * Gets the token that was found instead of the expected token.
     *
     * @return the found token
     */
    public Token<?> getFoundToken() {
        return foundToken;
    }
}
