package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.ntpl;

/**
 * Represents a filter expression node in the NTPL AST.
 */
public class FilterExpressionNode extends NtplASTNode {

	private final String condition;

	public FilterExpressionNode(String condition) {
		this.condition = condition;
	}

	public String getCondition() {
		return condition;
	}

	// Implement visitor pattern methods if needed
}
