package com.slytechs.jnet.jnetruntime.bpf.compiler.frontend;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;

/**
 * Interface for the lexer.
 *
 * @param <T> the token type enum that implements TokenType
 */
public interface Lexer<T extends TokenType> {

	/**
	 * Returns the next token from the input.
	 *
	 * @return the next token
	 * @throws CompilerException if a lexical error occurs
	 */
	Token<T> nextToken() throws CompilerException;
}
