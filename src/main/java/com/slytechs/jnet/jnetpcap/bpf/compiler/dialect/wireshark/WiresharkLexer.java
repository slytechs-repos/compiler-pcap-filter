package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark;

import java.util.HashSet;
import java.util.Set;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.Position;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.AbstractLexer;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Token;

/**
 * Concrete lexer for the Wireshark dialect.
 */
public class WiresharkLexer extends AbstractLexer<WiresharkTokenType> {

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
    public Token<WiresharkTokenType> nextToken() throws CompilerException {
        skipWhitespace();

        if (isEOF()) {
            return new Token<>(WiresharkTokenType.EOF, "", new Position(lineNumber, columnNumber));
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

    private Token<WiresharkTokenType> readIdentifierOrKeyword() {
        StringBuilder sb = new StringBuilder();
        Position start = new Position(lineNumber, columnNumber);

        while (!isEOF() && (Character.isLetterOrDigit(peekChar()) || peekChar() == '.' || peekChar() == '_')) {
            sb.append(nextChar());
        }

        String value = sb.toString();

        if (OPERATORS.contains(value)) {
            return new Token<>(WiresharkTokenType.OPERATOR, value, start);
        } else {
            return new Token<>(WiresharkTokenType.FIELD_NAME, value, start);
        }
    }

    private Token<WiresharkTokenType> readNumber() {
        StringBuilder sb = new StringBuilder();
        Position start = new Position(lineNumber, columnNumber);

        while (!isEOF() && Character.isDigit(peekChar())) {
            sb.append(nextChar());
        }

        String value = sb.toString();
        return new Token<>(WiresharkTokenType.NUMBER, value, start);
    }

    private Token<WiresharkTokenType> readString() throws CompilerException {
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
        return new Token<>(WiresharkTokenType.STRING, value, start);
    }

    private boolean isOperatorStart(char ch) {
        return ch == '=' || ch == '!' || ch == '>' || ch == '<';
    }

    private Token<WiresharkTokenType> readOperator() throws CompilerException {
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

        return new Token<>(WiresharkTokenType.RELATIONAL_OP, value, start);
    }
}
