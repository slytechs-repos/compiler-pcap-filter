package com.slytechs.jnet.compiler.dialect.dialect.wireshark;

import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.ParserException;
import com.slytechs.jnet.compiler.frontend.ASTNode;
import com.slytechs.jnet.compiler.frontend.AbstractParser;
import com.slytechs.jnet.compiler.frontend.Lexer;

/**
 * Concrete parser for the Wireshark compilerFrontend.
 */
public class WiresharkParser extends AbstractParser {

	public WiresharkParser(Lexer lexer) throws CompilerException {
		super(lexer);
	}

	@Override
	public ASTNode parse() throws CompilerException {
		ASTNode node = parseExpression();
		if (currentToken.getType() != WiresharkTokenType.EOF) {
			throw new ParserException("Unexpected token after end of expression", currentToken.getPosition(), null,
					currentToken);
		}
		return node;
	}

	private ASTNode parseExpression() throws CompilerException {
		ASTNode left = parseTerm();

		while (currentToken.getType() == WiresharkTokenType.OPERATOR && (currentToken.getValue().equals("and")
				|| currentToken.getValue().equals("or"))) {
			String operator = currentToken.getValue();
			match(WiresharkTokenType.OPERATOR);
			ASTNode right = parseTerm();
			left = new LogicalExpressionNode(operator, left, right);
		}

		return left;
	}

	private ASTNode parseTerm() throws CompilerException {
		if (currentToken.getType() == WiresharkTokenType.OPERATOR && currentToken.getValue().equals("not")) {
			match(WiresharkTokenType.OPERATOR);
			ASTNode operand = parseFactor();
			return new UnaryExpressionNode("not", operand);
		} else {
			return parseFactor();
		}
	}

	private ASTNode parseFactor() throws CompilerException {
		if (currentToken.getType() == WiresharkTokenType.FIELD_NAME) {
			String fieldName = currentToken.getValue();
			match(WiresharkTokenType.FIELD_NAME);

			String operator = currentToken.getValue();
			match(WiresharkTokenType.RELATIONAL_OP);

			String value = currentToken.getValue();
			if (currentToken.getType() == WiresharkTokenType.STRING || currentToken
					.getType() == WiresharkTokenType.NUMBER) {
				match(currentToken.getType());
			} else {
				throw new ParserException("Expected a value", currentToken.getPosition(), null, currentToken);
			}

			return new FieldComparisonNode(fieldName, operator, value);
		} else {
			throw new ParserException("Unexpected token: " + currentToken.getValue(), currentToken.getPosition(), null,
					currentToken);
		}
	}
}
