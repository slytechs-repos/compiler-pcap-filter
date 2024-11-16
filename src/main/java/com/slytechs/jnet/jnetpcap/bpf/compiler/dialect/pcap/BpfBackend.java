/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.pcap;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.List;

import com.slytechs.jnet.compiler.BackendDialect;
import com.slytechs.jnet.compiler.CodeGenerationException;
import com.slytechs.jnet.compiler.CompilerBackend;
import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.frontend.ASTNode;
import com.slytechs.jnet.jnetpcap.bpf.compiler.ir.BpfIR;
import com.slytechs.jnet.jnetpcap.bpf.compiler.ir.IRBuilder;
import com.slytechs.jnet.jnetpcap.bpf.vm.core.BpfInstruction;
import com.slytechs.jnet.jnetpcap.bpf.vm.core.BpfProgram;
import com.slytechs.jnet.jnetpcap.bpf.vm.instruction.BpfOpcode;

/**
 * @author Mark Bednarczyk
 *
 */
public class BpfBackend implements CompilerBackend<BpfProgram, BpfIR> {

	/**
	 * @see com.slytechs.jnet.compiler.IRDialect#generateIR(com.slytechs.jnet.compiler.frontend.ASTNode)
	 */
	@Override
	public BpfIR generateIR(ASTNode ast) throws CompilerException {
		IRBuilder irBuilder = new IRBuilder();

		emitInstructions(ast, irBuilder);

		return irBuilder;
	}

	/**
	 * @see com.slytechs.jnet.compiler.IRDialect#generateProgram(com.slytechs.jnet.compiler.ir.IRNode)
	 */
	@Override
	public BpfProgram generateProgram(BpfIR ir) throws CompilerException {
		try {
			List<BpfInstruction> instructions = ir.getInstructions();
			return new BpfProgram(instructions.toArray(new BpfInstruction[0]));

		} catch (Exception e) {
			throw new CodeGenerationException("Failed to generate BPF program", null, e);
		}
	}

	private void emitInstructions(ASTNode node, IRBuilder irBuilder) throws CompilerException {
		if (node instanceof ProtocolNode protocolNode) {
			generateProtocolInstructions(protocolNode, irBuilder);

		} else if (node instanceof PortNode portNode) {
			generatePortInstructions(portNode, irBuilder);

		} else if (node instanceof HostNode hostNode) {
			generateHostInstructions(hostNode, irBuilder);

		} else if (node instanceof BinaryExpressionNode binaryNode) {
			String operator = binaryNode.getOperator();
			if (operator.equals("and") || operator.equals("&&")) {
				generateAndOperatorInstructions(binaryNode, irBuilder);

			} else if (operator.equals("or") || operator.equals("||")) {
				generateOrOperatorInstructions(binaryNode, irBuilder);

			} else {
				throw new CompilerException("Unsupported binary operator: " + operator, null);
			}

		} else if (node instanceof UnaryExpressionNode unaryNode) {
			String operator = unaryNode.getOperator();
			emitInstructions(unaryNode.getOperand(), irBuilder);
			generateUnaryOperatorInstructions(operator, irBuilder);

		} else {
			throw new CompilerException("Unsupported AST node type: " + node.getClass(), null);
		}
	}

	private void generateUnaryOperatorInstructions(String operator, IRBuilder irBuilder) throws CompilerException {
		if (operator.equals("not") || operator.equals("!")) {
			// Evaluate operand
			// Assuming the result is in the accumulator (A register)

			// Load immediate 0 into X register
			irBuilder.emit(BpfInstruction.create(BpfOpcode.LDX_IMM, 0, 0, 0));

			// Swap A and X (so A contains 0, X contains the result)
			irBuilder.emit(BpfInstruction.create(BpfOpcode.TAX, 0, 0, 0));
			irBuilder.emit(BpfInstruction.create(BpfOpcode.TXA, 0, 0, 0));

			// Perform A = A ^ X (logical NOT)
			irBuilder.emit(BpfInstruction.create(BpfOpcode.XOR_K, 0, 0, 0));

		} else {
			throw new CompilerException("Unsupported unary operator: " + operator, null);
		}
	}

	private void generateOrOperatorInstructions(BinaryExpressionNode node, IRBuilder irBuilder)
			throws CompilerException {
		int acceptLabel = irBuilder.getNextLabel();
		int endLabel = irBuilder.getNextLabel();

		// Evaluate left operand
		emitInstructions(node.getLeft(), irBuilder);

		// If result is true, jump to acceptLabel
		irBuilder.emitJumpIfTrue(acceptLabel);

		// Evaluate right operand
		emitInstructions(node.getRight(), irBuilder);

		// If result is true, jump to acceptLabel
		irBuilder.emitJumpIfFalse(acceptLabel);

		// Both operands are false, reject packet
		irBuilder.emitReject();

		// Jump to endLabel
		irBuilder.emitJump(endLabel);

		// acceptLabel: Accept packet
		irBuilder.addLabel(acceptLabel);
		irBuilder.emitAccept();

		// endLabel:
		irBuilder.addLabel(endLabel);
	}

	private void generateAndOperatorInstructions(BinaryExpressionNode node, IRBuilder irBuilder)
			throws CompilerException {
		int falseLabel = irBuilder.getNextLabel();
		int endLabel = irBuilder.getNextLabel();

		// Evaluate left operand
		emitInstructions(node.getLeft(), irBuilder);

		// If result is false, jump to falseLabel
		irBuilder.emitJumpIfFalse(falseLabel);

		// Evaluate right operand
		emitInstructions(node.getRight(), irBuilder);

		// If result is false, jump to falseLabel
		irBuilder.emitJumpIfFalse(falseLabel);

		// Both operands are true, accept packet
		irBuilder.emitAccept();

		// Jump to endLabel
		irBuilder.emitJump(endLabel);

		// falseLabel: Reject packet
		irBuilder.addLabel(falseLabel);
		irBuilder.emitReject();

		// endLabel:
		irBuilder.addLabel(endLabel);
	}

	private void generateProtocolInstructions(ProtocolNode node, IRBuilder irBuilder) throws CompilerException {
		String protocol = node.getProtocol().toLowerCase();
		int protocolNumber;

		switch (protocol) {
		case "tcp":
			protocolNumber = 6;
			break;
		case "udp":
			protocolNumber = 17;
			break;
		case "icmp":
			protocolNumber = 1;
			break;
		default:
			throw new CompilerException("Unsupported protocol: " + protocol, null);
		}

		// Load the IP protocol field (offset 23 in Ethernet + IP header)
		irBuilder.emit(BpfInstruction.create(BpfOpcode.LD_ABS_B, 0, 0, 23));

		// Compare it with the protocol number
		// jt = 1 (skip over 'drop' instruction), jf = 0
		irBuilder.emit(BpfInstruction.create(BpfOpcode.JMP_JEQ_K, 1, 0, protocolNumber));

		// Drop packet
		irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0));

		// Accept packet
		irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0xFFFFFFFF));
	}

	private void generatePortInstructions(PortNode node, IRBuilder irBuilder) throws CompilerException {
		int port;
		try {
			port = Integer.parseInt(node.getPort());
		} catch (NumberFormatException e) {
			throw new CompilerException("Invalid port number: " + node.getPort(), null);
		}

		// Load the destination port from TCP/UDP header
		int offset = 14 + 20 + 2; // Ethernet (14) + IP (20) + TCP/UDP dest port offset (2)
		irBuilder.emit(BpfInstruction.create(BpfOpcode.LD_ABS_H, 0, 0, offset));

		// Compare it with the port number
		irBuilder.emit(BpfInstruction.create(BpfOpcode.JMP_JEQ_K, 1, 0, port));

		// Drop packet
		irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0));

		// Accept packet
		irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0xFFFFFFFF));
	}

	private void generateHostInstructions(HostNode node, IRBuilder irBuilder) throws CompilerException {
		String host = node.getHost();
		int ipAddress;
		try {
			InetAddress address = InetAddress.getByName(host);
			byte[] bytes = address.getAddress();
			ipAddress = ByteBuffer.wrap(bytes).getInt();
		} catch (UnknownHostException e) {
			throw new CompilerException("Invalid host address: " + host, null);
		}

		// Load the source IP address (offset 26) or destination IP (offset 30)
		int offset = 14 + 12; // Ethernet (14) + IP source address offset (12)
		irBuilder.emit(BpfInstruction.create(BpfOpcode.LD_ABS_W, 0, 0, offset));

		// Compare it with the IP address
		irBuilder.emit(BpfInstruction.create(BpfOpcode.JMP_JEQ_K, 1, 0, ipAddress));

		// Drop packet
		irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0));

		// Accept packet
		irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0xFFFFFFFF));
	}

	private void generateBinaryOperatorInstructions(String operator, IRBuilder irBuilder) throws CompilerException {
		// Implement logic for 'and' and 'or' operators
		if (operator.equals("and") || operator.equals("&&")) {
			throw new CompilerException("Logical 'and' operator not implemented yet", null);
		} else if (operator.equals("or") || operator.equals("||")) {
			throw new CompilerException("Logical 'or' operator not implemented yet", null);
		} else {
			throw new CompilerException("Unsupported binary operator: " + operator, null);
		}
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerBackend#backendDialect()
	 */
	@Override
	public BackendDialect backendDialect() {
		return BackendDialect.BERKLEY_PACKET_FILTER;
	}

}
