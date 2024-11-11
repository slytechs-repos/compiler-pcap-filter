package com.slytechs.jnet.jnetruntime.bpf.compiler.frontend;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.ParserException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.Position;

/**
 * Base functionality for dialect-specific parsers.
 *
 * @param <T> the token type enum that implements TokenType
 * @param <N> the AST node type specific to the dialect
 */
public abstract class AbstractParser<T extends TokenType, N extends ASTNode> implements Parser<T, N> {

	protected final Lexer<T> lexer;
	protected Token<T> currentToken;

	/**
	 * Constructs a new AbstractParser with the given lexer.
	 *
	 * @param lexer the lexer to use
	 * @throws CompilerException if a lexical error occurs during initialization
	 */
	public AbstractParser(Lexer<T> lexer) throws CompilerException {
		this.lexer = lexer;
		this.currentToken = lexer.nextToken();
	}

	/**
	 * Matches the current token with the expected token type.
	 *
	 * @param expectedType the expected token type
	 * @throws ParserException   if the token does not match
	 * @throws CompilerException if a lexical error occurs
	 */
	protected void match(T expectedType) throws ParserException, CompilerException {
		if (currentToken == null || currentToken.getType() != expectedType) {

			Position position = (currentToken != null)
					? currentToken.getPosition()
					: null;

			throw new ParserException(
					"Unexpected token: expected " + expectedType + " but found " +
							(currentToken != null ? currentToken.getType() : "EOF"),
					position,
					expectedType,
					currentToken);
		}

		// Advance to the next token
		currentToken = lexer.nextToken();
	}

	// The parse method remains abstract
	@Override
	public abstract N parse() throws CompilerException;
}
