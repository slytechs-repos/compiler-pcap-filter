package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.List;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CodeGenerationException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.core.AbstractBpfCompiler;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Parser;
import com.slytechs.jnet.jnetruntime.bpf.compiler.ir.BpfIR;
import com.slytechs.jnet.jnetruntime.bpf.compiler.ir.IRBuilder;
import com.slytechs.jnet.jnetruntime.bpf.vm.core.BpfInstruction;
import com.slytechs.jnet.jnetruntime.bpf.vm.core.BpfProgram;
import com.slytechs.jnet.jnetruntime.bpf.vm.instruction.BpfOpcode;

public class WiresharkCompiler extends AbstractBpfCompiler<WiresharkTokenType, WiresharkASTNode> {

    public WiresharkCompiler() {
        this.dialect = new WiresharkDialectImpl();
    }

    @Override
    protected Lexer<WiresharkTokenType> createLexer(String source) throws CompilerException {
        return new WiresharkLexer(source);
    }

    @Override
    protected Parser<WiresharkTokenType, WiresharkASTNode> createParser(Lexer<WiresharkTokenType> lexer) throws CompilerException {
        return new WiresharkParser(lexer);
    }

    @Override
    protected BpfIR generateIR(WiresharkASTNode ast) throws CompilerException {
        IRBuilder irBuilder = new IRBuilder();
        emitInstructions(ast, irBuilder);
        return irBuilder;
    }

    @Override
    protected BpfProgram generateProgram(BpfIR ir) throws CompilerException {
        try {
            List<BpfInstruction> instructions = ir.getInstructions();
            return new BpfProgram(instructions.toArray(new BpfInstruction[0]));
        } catch (Exception e) {
            throw new CodeGenerationException("Failed to generate BPF program", null, e);
        }
    }

    private void emitInstructions(WiresharkASTNode node, IRBuilder irBuilder) throws CompilerException {
        if (node instanceof FieldComparisonNode) {
            generateFieldComparisonInstructions((FieldComparisonNode) node, irBuilder);
        } else if (node instanceof LogicalExpressionNode) {
            LogicalExpressionNode logicalNode = (LogicalExpressionNode) node;
            emitInstructions(logicalNode.getLeft(), irBuilder);
            emitInstructions(logicalNode.getRight(), irBuilder);
            generateLogicalOperatorInstructions(logicalNode.getOperator(), irBuilder);
        } else if (node instanceof UnaryExpressionNode) {
            UnaryExpressionNode unaryNode = (UnaryExpressionNode) node;
            emitInstructions(unaryNode.getOperand(), irBuilder);
            generateUnaryOperatorInstructions(unaryNode.getOperator(), irBuilder);
        } else {
            throw new CompilerException("Unsupported AST node type: " + node.getClass(), null);
        }
    }

    private void generateFieldComparisonInstructions(FieldComparisonNode node, IRBuilder irBuilder) throws CompilerException {
        String fieldName = node.getFieldName();
        String operator = node.getOperator();
        String value = node.getValue();

        int offset = getFieldOffset(fieldName);
        if (offset == -1) {
            throw new CompilerException("Unknown field: " + fieldName, null);
        }

        BpfOpcode comparisonOpcode = getComparisonOpcode(operator);
        int immediateValue = parseValue(value);

        // Load field value
        irBuilder.emit(BpfInstruction.create(BpfOpcode.LD_ABS_W, 0, 0, offset));

        // Compare with immediate value
        irBuilder.emit(BpfInstruction.create(comparisonOpcode, 1, 0, immediateValue));

        // Drop packet if comparison fails
        irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0));

        // Accept packet if comparison succeeds
        irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0xFFFFFFFF));
    }

    private int getFieldOffset(String fieldName) {
        switch (fieldName) {
            case "ip.src":
                return 14 + 12; // Ethernet header + IP source address offset
            case "ip.dst":
                return 14 + 16; // Ethernet header + IP destination address offset
            case "tcp.port":
                return 14 + 20 + 2; // Ethernet + IP header + TCP dest port offset
            default:
                return -1; // Unknown field
        }
    }

    private BpfOpcode getComparisonOpcode(String operator) throws CompilerException {
        switch (operator) {
            case "==":
                return BpfOpcode.JMP_JEQ_K;
            case "!=":
                // For '!=' operator, we need to invert the condition
                return BpfOpcode.JMP_JEQ_K;
            case ">":
                return BpfOpcode.JMP_JGT_K;
            case "<":
                return BpfOpcode.JMP_JGE_K;
            case ">=":
                return BpfOpcode.JMP_JGE_K;
            case "<=":
                return BpfOpcode.JMP_JGT_K;
            default:
                throw new CompilerException("Unsupported operator: " + operator, null);
        }
    }

    private int parseValue(String value) throws CompilerException {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            try {
                InetAddress address = InetAddress.getByName(value);
                byte[] bytes = address.getAddress();
                return ByteBuffer.wrap(bytes).getInt();
            } catch (UnknownHostException ex) {
                throw new CompilerException("Invalid value: " + value, null);
            }
        }
    }

    private void generateLogicalOperatorInstructions(String operator, IRBuilder irBuilder) throws CompilerException {
        if (operator.equals("and")) {
            throw new CompilerException("Logical 'and' operator not implemented yet", null);
        } else if (operator.equals("or")) {
            throw new CompilerException("Logical 'or' operator not implemented yet", null);
        } else {
            throw new CompilerException("Unsupported logical operator: " + operator, null);
        }
    }

    private void generateUnaryOperatorInstructions(String operator, IRBuilder irBuilder) throws CompilerException {
        if (operator.equals("not")) {
            throw new CompilerException("Unary 'not' operator not implemented yet", null);
        } else {
            throw new CompilerException("Unsupported unary operator: " + operator, null);
        }
    }
}
