package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap;

/**
 * Represents a unary expression node in the Pcap AST.
 */
public class UnaryExpressionNode extends PcapASTNode {

	private final String operator;
	private final PcapASTNode operand;

	public UnaryExpressionNode(String operator, PcapASTNode operand) {
		this.operator = operator;
		this.operand = operand;
	}

	public String getOperator() {
		return operator;
	}

	public PcapASTNode getOperand() {
		return operand;
	}
}
