package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.ntpl;

import com.slytechs.jnet.compiler.frontend.ASTNode;

/**
 * Represents a filter expression node in the NTPL AST.
 */
public class FilterExpressionNode extends ASTNode {

	private final String condition;

	public FilterExpressionNode(String condition) {
		this.condition = condition;
	}

	public String getCondition() {
		return condition;
	}

	// Implement visitor pattern methods if needed
}
