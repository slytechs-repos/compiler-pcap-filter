package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.pcap;

import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.ParserException;
import com.slytechs.jnet.compiler.frontend.ASTNode;
import com.slytechs.jnet.compiler.frontend.AbstractParser;
import com.slytechs.jnet.compiler.frontend.Lexer;

/**
 * Concrete parser for the Pcap compilerFrontend.
 */
public class PcapParser extends AbstractParser {

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "PcapParser []";
	}

	public PcapParser(Lexer lexer) throws CompilerException {
		super(lexer);
	}

	@Override
	public ASTNode parse() throws CompilerException {
		ASTNode node = parseExpression();

		if (currentToken.getType() != PcapTokenType.EOF) {
			throw new ParserException("Unexpected token after end of expression",
					currentToken.getPosition(),
					null,
					currentToken);
		}

		return node;
	}

	private ASTNode parseExpression() throws CompilerException {
		ASTNode left = parseTerm();

		while (currentToken.getType() == PcapTokenType.OPERATOR
				&& (false

						|| currentToken.getValue().equals("and")
						|| currentToken.getValue().equals("or")
						|| currentToken.getValue().equals("&&")
						|| currentToken.getValue().equals("||")

				)) {

			String operator = currentToken.getValue();
			match(PcapTokenType.OPERATOR);

			ASTNode right = parseTerm();

			left = new BinaryExpressionNode(operator, left, right);
		}

		return left;
	}

	private ASTNode parseTerm() throws CompilerException {
		if (currentToken.getType() == PcapTokenType.OPERATOR
				&& (false

						|| currentToken.getValue().equals("not")
						|| currentToken.getValue().equals("!")

				)) {

			String operator = currentToken.getValue();
			match(PcapTokenType.OPERATOR);

			ASTNode operand = parseFactor();

			return new UnaryExpressionNode(operator, operand);

		} else {
			return parseFactor();
		}
	}

	private ASTNode parseFactor() throws CompilerException {
		if (currentToken.getType() == PcapTokenType.LEFT_PAREN) {
			match(PcapTokenType.LEFT_PAREN);

			ASTNode expr = parseExpression();
			match(PcapTokenType.RIGHT_PAREN);

			return expr;

		} else if (currentToken.getType() == PcapTokenType.PROTOCOL) {
			String protocol = currentToken.getValue();
			match(PcapTokenType.PROTOCOL);

			return new ProtocolNode(protocol);

		} else if (currentToken.getType() == PcapTokenType.KEYWORD) {
			String keyword = currentToken.getValue();
			match(PcapTokenType.KEYWORD);

			if (keyword.equals("port")) {
				String port = currentToken.getValue();
				match(PcapTokenType.NUMBER);

				return new PortNode(port);

			} else if (keyword.equals("host")) {
				String host = currentToken.getValue();
				if (false
						|| currentToken.getType() == PcapTokenType.NUMBER
						|| currentToken.getType() == PcapTokenType.IDENTIFIER) {

					match(currentToken.getType());

					return new HostNode(host);

				} else {
					throw new ParserException("Expected host address", currentToken.getPosition(), null, currentToken);
				}
			} else {
				throw new ParserException("Unexpected keyword: " + keyword, currentToken.getPosition(), null,
						currentToken);
			}
		} else {
			throw new ParserException("Unexpected token: " + currentToken.getValue(), currentToken.getPosition(), null,
					currentToken);
		}
	}
}
