package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.wireshark;

import com.slytechs.jnet.compiler.frontend.ASTNode;

/**
 * Represents a field comparison node in the Wireshark AST.
 */
public class FieldComparisonNode extends ASTNode {

	private final String fieldName;
	private final String operator;
	private final String value;

	public FieldComparisonNode(String fieldName, String operator, String value) {
		this.fieldName = fieldName;
		this.operator = operator;
		this.value = value;
	}

	public String getFieldName() {
		return fieldName;
	}

	public String getOperator() {
		return operator;
	}

	public String getValue() {
		return value;
	}

	// Implement visitor pattern methods if needed
}
