package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.pcap;

import com.slytechs.jnet.compiler.frontend.ASTNode;

/**
 * Represents a unary expression node in the Pcap AST.
 */
public class UnaryExpressionNode extends ASTNode {

	private final String operator;
	private final ASTNode operand;

	public UnaryExpressionNode(String operator, ASTNode operand) {
		this.operator = operator;
		this.operand = operand;
	}

	public String getOperator() {
		return operator;
	}

	public ASTNode getOperand() {
		return operand;
	}
}
