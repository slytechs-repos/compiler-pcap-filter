package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.ntpl;

import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.ParserException;
import com.slytechs.jnet.compiler.frontend.ASTNode;
import com.slytechs.jnet.compiler.frontend.AbstractParser;
import com.slytechs.jnet.compiler.frontend.Lexer;

/**
 * Concrete parser for the NTPL compilerFrontend.
 */
public class NtplParser extends AbstractParser {

	public NtplParser(Lexer lexer) throws CompilerException {
		super(lexer);
	}

	@Override
	public ASTNode parse() throws CompilerException {
		ASTNode node = parseStatement();
		if (currentToken.getType() != NtplTokenType.EOF) {
			throw new ParserException("Unexpected token after end of statement", currentToken.getPosition(), null,
					currentToken);
		}
		return node;
	}

	private ASTNode parseStatement() throws CompilerException {
		if (currentToken.getType() == NtplTokenType.KEYWORD && currentToken.getValue().equals("IF")) {
			match(NtplTokenType.KEYWORD);
			String condition = currentToken.getValue();
			match(NtplTokenType.NUMBER);
			// Parse the rest of the filter expression
			// Placeholder implementation
			return new FilterExpressionNode(condition);
		} else {
			throw new ParserException("Expected 'IF' keyword", currentToken.getPosition(), null, currentToken);
		}
	}
}
