package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap;

/**
 * Represents a binary expression node in the Pcap AST.
 */
public class BinaryExpressionNode extends PcapASTNode {

	private final String operator;
	private final PcapASTNode left;
	private final PcapASTNode right;

	public BinaryExpressionNode(String operator, PcapASTNode left, PcapASTNode right) {
		this.operator = operator;
		this.left = left;
		this.right = right;
	}

	public String getOperator() {
		return operator;
	}

	public PcapASTNode getLeft() {
		return left;
	}

	public PcapASTNode getRight() {
		return right;
	}
}
