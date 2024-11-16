package com.slytechs.jnet.compiler.dialect.dialect.wireshark;

import com.slytechs.jnet.compiler.frontend.ASTNode;

/**
 * Represents a logical expression node in the Wireshark AST.
 */
public class LogicalExpressionNode extends ASTNode {

    private final String operator;
    private final ASTNode left;
    private final ASTNode right;

    public LogicalExpressionNode(String operator, ASTNode left, ASTNode right) {
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
