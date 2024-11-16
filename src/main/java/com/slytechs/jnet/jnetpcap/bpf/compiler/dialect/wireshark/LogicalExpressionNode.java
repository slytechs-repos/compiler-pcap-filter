package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark;

/**
 * Represents a logical expression node in the Wireshark AST.
 */
public class LogicalExpressionNode extends WiresharkASTNode {

    private final String operator;
    private final WiresharkASTNode left;
    private final WiresharkASTNode right;

    public LogicalExpressionNode(String operator, WiresharkASTNode left, WiresharkASTNode right) {
        this.operator = operator;
        this.left = left;
        this.right = right;
    }

    public String getOperator() {
        return operator;
    }

    public WiresharkASTNode getLeft() {
        return left;
    }

    public WiresharkASTNode getRight() {
        return right;
    }
}
