package com.slytechs.jnet.compiler.dialect.dialect.ntpl;

import java.util.HashSet;
import java.util.Set;

import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.Position;
import com.slytechs.jnet.compiler.frontend.AbstractLexer;
import com.slytechs.jnet.compiler.frontend.Token;

/**
 * Concrete lexer for the NTPL compilerFrontend.
 */
public class NtplLexer extends AbstractLexer {

	private static final Set<String> KEYWORDS = new HashSet<>();

	static {
		KEYWORDS.add("IF");
		KEYWORDS.add("MAC_ADDR");
		// Add more keywords as needed
	}

	public NtplLexer(String input) {
		super(input);
	}

	@Override
	public Token nextToken() throws CompilerException {
		skipWhitespace();

		if (isEOF()) {
			return new Token(NtplTokenType.EOF, "", new Position(lineNumber, columnNumber));
		}

		char ch = peekChar();

		if (Character.isLetter(ch)) {
			return readIdentifierOrKeyword();
		} else if (Character.isDigit(ch)) {
			return readNumber();
		} else if (ch == '"') {
			return readString();
		} else {
			reportLexicalError("Invalid character", String.valueOf(ch));
			return null; // Unreachable
		}
	}

	private void skipWhitespace() {
		while (!isEOF() && Character.isWhitespace(peekChar())) {
			nextChar();
		}
	}

	private Token readIdentifierOrKeyword() {
		StringBuilder sb = new StringBuilder();
		Position start = new Position(lineNumber, columnNumber);

		while (!isEOF() && Character.isLetterOrDigit(peekChar())) {
			sb.append(nextChar());
		}

		String value = sb.toString().toUpperCase();

		if (KEYWORDS.contains(value)) {
			return new Token(NtplTokenType.KEYWORD, value, start);
		} else {
			return new Token(NtplTokenType.IDENTIFIER, value, start);
		}
	}

	private Token readNumber() {
		StringBuilder sb = new StringBuilder();
		Position start = new Position(lineNumber, columnNumber);

		while (!isEOF() && Character.isDigit(peekChar())) {
			sb.append(nextChar());
		}

		String value = sb.toString();
		return new Token(NtplTokenType.NUMBER, value, start);
	}

	private Token readString() throws CompilerException {
		Position start = new Position(lineNumber, columnNumber);
		nextChar(); // Consume the opening quote

		StringBuilder sb = new StringBuilder();

		while (!isEOF() && peekChar() != '"') {
			sb.append(nextChar());
		}

		if (isEOF()) {
			reportLexicalError("Unterminated string literal", sb.toString());
		}

		nextChar(); // Consume the closing quote
		String value = sb.toString();
		return new Token(NtplTokenType.STRING, value, start);
	}
}
