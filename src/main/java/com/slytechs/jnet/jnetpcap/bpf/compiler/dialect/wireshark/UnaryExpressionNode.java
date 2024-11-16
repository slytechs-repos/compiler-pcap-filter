package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark;

/**
 * Represents a unary expression node in the Wireshark AST.
 */
public class UnaryExpressionNode extends WiresharkASTNode {

    private final String operator;
    private final WiresharkASTNode operand;

    public UnaryExpressionNode(String operator, WiresharkASTNode operand) {
        this.operator = operator;
        this.operand = operand;
    }

    public String getOperator() {
        return operator;
    }

    public WiresharkASTNode getOperand() {
        return operand;
    }
}
