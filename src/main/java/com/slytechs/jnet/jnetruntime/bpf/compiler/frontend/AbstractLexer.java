package com.slytechs.jnet.jnetruntime.bpf.compiler.frontend;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.LexicalException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.Position;

/**
 * Base functionality for dialect-specific lexers.
 *
 * @param <T> the token type enum that implements TokenType
 */
public abstract class AbstractLexer<T extends TokenType> implements Lexer<T> {

	protected final String input;
	protected int position;
	protected int lineNumber = 1;
	protected int columnNumber = 1;

	/**
	 * Constructs a new AbstractLexer with the given input.
	 *
	 * @param input the source code to lex
	 */
	public AbstractLexer(String input) {
		this.input = input;
		this.position = 0;
	}

	/**
	 * Reports a lexical error.
	 *
	 * @param message      the error message
	 * @param invalidToken the invalid token encountered
	 * @throws LexicalException the exception thrown
	 */
	protected void reportLexicalError(String message, String invalidToken) throws LexicalException {
		Position position = new Position(lineNumber, columnNumber);
		throw new LexicalException(message, position, invalidToken);
	}

	/**
	 * Checks if the end of the input has been reached.
	 *
	 * @return true if at the end of input, false otherwise
	 */
	protected boolean isEOF() {
		return position >= input.length();
	}

	protected boolean isEOF(int index) {
		return (position + index) >= input.length();
	}

	protected boolean has() {
		return !isEOF();
	}

	protected boolean has(int index) {
		return !isEOF(index);
	}

	/**
	 * Consumes the next character in the input.
	 *
	 * @return the next character
	 */
	protected char nextChar() {
		char ch = input.charAt(position++);
		if (ch == '\n') {
			lineNumber++;
			columnNumber = 1;
		} else {
			columnNumber++;
		}
		return ch;
	}

	/**
	 * Peeks at the next character without consuming it.
	 *
	 * @return the next character
	 */
	protected char peekChar() {
		return input.charAt(position);
	}

	protected int skip(int count) {
		while (!isEOF() && count-- > 0)
			nextChar();

		return count;
	}

	protected char peekCharAt(int index) {
		return input.charAt(position + index);
	}

	// The nextToken method remains abstract
	@Override
	public abstract Token<T> nextToken() throws CompilerException;
}
