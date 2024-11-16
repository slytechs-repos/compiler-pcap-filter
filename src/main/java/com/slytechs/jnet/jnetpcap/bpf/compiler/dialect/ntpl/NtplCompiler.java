package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.ntpl;

import java.util.List;

import com.slytechs.jnet.compiler.CodeGenerationException;
import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.core.AbstractCompiler;
import com.slytechs.jnet.compiler.frontend.ASTNode;
import com.slytechs.jnet.compiler.frontend.Lexer;
import com.slytechs.jnet.compiler.frontend.Parser;
import com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.pcap.BpfBackend;
import com.slytechs.jnet.jnetpcap.bpf.compiler.ir.BpfIR;
import com.slytechs.jnet.jnetpcap.bpf.compiler.ir.IRBuilder;
import com.slytechs.jnet.jnetpcap.bpf.vm.core.BpfInstruction;
import com.slytechs.jnet.jnetpcap.bpf.vm.core.BpfProgram;
import com.slytechs.jnet.jnetpcap.bpf.vm.instruction.BpfOpcode;

public class NtplCompiler extends AbstractCompiler<BpfIR, BpfProgram> {

	public NtplCompiler() {
		super(new NtplFrontend(), new BpfBackend());
	}

	@Override
	protected Lexer createLexer(String source) throws CompilerException {
		return new NtplLexer(source);
	}

	@Override
	protected Parser createParser(Lexer lexer) throws CompilerException {
		return new NtplParser(lexer);
	}

	@Override
	protected BpfIR generateIR(ASTNode ast) throws CompilerException {
		IRBuilder irBuilder = new IRBuilder();
		emitInstructions(ast, irBuilder);
		return irBuilder;
	}

	@Override
	protected BpfProgram generateProgram(BpfIR ir) throws CompilerException {
		try {
			List<BpfInstruction> instructions = ((IRBuilder) ir).getInstructions();
			return new BpfProgram(instructions.toArray(new BpfInstruction[0]));
		} catch (Exception e) {
			throw new CodeGenerationException("Failed to generate BPF program", null, e);
		}
	}

	private void emitInstructions(ASTNode node, IRBuilder irBuilder) throws CompilerException {
		if (node instanceof FilterExpressionNode) {
			generateFilterExpressionInstructions((FilterExpressionNode) node, irBuilder);
		} else {
			throw new CompilerException("Unsupported AST node type: " + node.getClass(), null);
		}
	}

	private void generateFilterExpressionInstructions(FilterExpressionNode node, IRBuilder irBuilder)
			throws CompilerException {
		String condition = node.getCondition();

		if (condition.startsWith("MAC_ADDR == ")) {
			String macAddress = condition.substring("MAC_ADDR == ".length()).trim().replace("\"", "");
			byte[] macBytes = parseMacAddress(macAddress);

			for (int i = 0; i < 6; i++) {
				// Load the byte from the packet (Ethernet header starts at offset 0)
				irBuilder.emit(BpfInstruction.create(BpfOpcode.LD_ABS_B, 0, 0, i));

				// Compare with the corresponding byte from the MAC address
				irBuilder.emit(BpfInstruction.create(BpfOpcode.JMP_JEQ_K, 1, 0, macBytes[i] & 0xFF));

				// If not equal, drop packet
				irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0));
			}

			// If all bytes match, accept packet
			irBuilder.emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0xFFFFFFFF));
		} else {
			throw new CompilerException("Unsupported condition: " + condition, null);
		}
	}

	private byte[] parseMacAddress(String macAddress) throws CompilerException {
		String[] macParts = macAddress.split(":");
		if (macParts.length != 6) {
			throw new CompilerException("Invalid MAC address: " + macAddress, null);
		}
		byte[] macBytes = new byte[6];
		try {
			for (int i = 0; i < 6; i++) {
				macBytes[i] = (byte) Integer.parseInt(macParts[i], 16);
			}
		} catch (NumberFormatException e) {
			throw new CompilerException("Invalid MAC address: " + macAddress, null);
		}
		return macBytes;
	}
}
