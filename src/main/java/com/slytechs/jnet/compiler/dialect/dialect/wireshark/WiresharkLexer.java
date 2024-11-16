package com.slytechs.jnet.compiler.dialect.dialect.wireshark;

import java.util.HashSet;
import java.util.Set;

import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.Position;
import com.slytechs.jnet.compiler.frontend.AbstractLexer;
import com.slytechs.jnet.compiler.frontend.Token;

/**
 * Concrete lexer for the Wireshark compilerFrontend.
 */
public class WiresharkLexer extends AbstractLexer {

	private static final Set<String> OPERATORS = new HashSet<>();

	static {
		OPERATORS.add("==");
		OPERATORS.add("!=");
		OPERATORS.add(">");
		OPERATORS.add("<");
		OPERATORS.add(">=");
		OPERATORS.add("<=");
		OPERATORS.add("and");
		OPERATORS.add("or");
		OPERATORS.add("not");
		// Add more operators as needed
	}

	public WiresharkLexer(String input) {
		super(input);
	}

	@Override
	public Token nextToken() throws CompilerException {
		skipWhitespace();

		if (isEOF()) {
			return new Token(WiresharkTokenType.EOF, "", new Position(lineNumber, columnNumber));
		}

		char ch = peekChar();

		if (Character.isLetter(ch)) {
			return readIdentifierOrKeyword();
		} else if (Character.isDigit(ch)) {
			return readNumber();
		} else if (ch == '"') {
			return readString();
		} else if (isOperatorStart(ch)) {
			return readOperator();
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

		while (!isEOF() && (Character.isLetterOrDigit(peekChar()) || peekChar() == '.' || peekChar() == '_')) {
			sb.append(nextChar());
		}

		String value = sb.toString();

		if (OPERATORS.contains(value)) {
			return new Token(WiresharkTokenType.OPERATOR, value, start);
		} else {
			return new Token(WiresharkTokenType.FIELD_NAME, value, start);
		}
	}

	private Token readNumber() {
		StringBuilder sb = new StringBuilder();
		Position start = new Position(lineNumber, columnNumber);

		while (!isEOF() && Character.isDigit(peekChar())) {
			sb.append(nextChar());
		}

		String value = sb.toString();
		return new Token(WiresharkTokenType.NUMBER, value, start);
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
		return new Token(WiresharkTokenType.STRING, value, start);
	}

	private boolean isOperatorStart(char ch) {
		return ch == '=' || ch == '!' || ch == '>' || ch == '<';
	}

	private Token readOperator() throws CompilerException {
		Position start = new Position(lineNumber, columnNumber);
		char ch = nextChar();
		String value = String.valueOf(ch);

		if ((ch == '=' || ch == '!' || ch == '>' || ch == '<') && !isEOF()) {
			char nextCh = peekChar();
			if (nextCh == '=') {
				value += nextChar();
			}
		}

		if (!OPERATORS.contains(value)) {
			reportLexicalError("Invalid operator", value);
		}

		return new Token(WiresharkTokenType.RELATIONAL_OP, value, start);
	}
}
