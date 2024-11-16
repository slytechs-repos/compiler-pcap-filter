package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.pcap;

import com.slytechs.jnet.compiler.frontend.ASTNode;

/**
 * Represents a binary expression node in the Pcap AST.
 */
public class BinaryExpressionNode extends ASTNode {

	private final String operator;
	private final ASTNode left;
	private final ASTNode right;

	public BinaryExpressionNode(String operator, ASTNode left, ASTNode right) {
		this.operator = operator;
		this.left = left;
		this.right = right;
	}

	public String getOperator() {
		return operator;
	}

	public ASTNode getLeft() {
		return left;
	}

	public ASTNode getRight() {
		return right;
	}
}
