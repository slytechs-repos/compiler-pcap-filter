package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.ParserException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.AbstractParser;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer;

/**
 * Concrete parser for the Wireshark dialect.
 */
public class WiresharkParser extends AbstractParser<WiresharkTokenType, WiresharkASTNode> {

	public WiresharkParser(Lexer<WiresharkTokenType> lexer) throws CompilerException {
		super(lexer);
	}

	@Override
	public WiresharkASTNode parse() throws CompilerException {
		WiresharkASTNode node = parseExpression();
		if (currentToken.getType() != WiresharkTokenType.EOF) {
			throw new ParserException("Unexpected token after end of expression", currentToken.getPosition(), null,
					currentToken);
		}
		return node;
	}

	private WiresharkASTNode parseExpression() throws CompilerException {
		WiresharkASTNode left = parseTerm();

		while (currentToken.getType() == WiresharkTokenType.OPERATOR && (currentToken.getValue().equals("and")
				|| currentToken.getValue().equals("or"))) {
			String operator = currentToken.getValue();
			match(WiresharkTokenType.OPERATOR);
			WiresharkASTNode right = parseTerm();
			left = new LogicalExpressionNode(operator, left, right);
		}

		return left;
	}

	private WiresharkASTNode parseTerm() throws CompilerException {
		if (currentToken.getType() == WiresharkTokenType.OPERATOR && currentToken.getValue().equals("not")) {
			match(WiresharkTokenType.OPERATOR);
			WiresharkASTNode operand = parseFactor();
			return new UnaryExpressionNode("not", operand);
		} else {
			return parseFactor();
		}
	}

	private WiresharkASTNode parseFactor() throws CompilerException {
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
