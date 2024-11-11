package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark;

/**
 * Represents a field comparison node in the Wireshark AST.
 */
public class FieldComparisonNode extends WiresharkASTNode {

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
