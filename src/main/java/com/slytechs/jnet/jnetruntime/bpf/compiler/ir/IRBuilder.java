package com.slytechs.jnet.jnetruntime.bpf.compiler.ir;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.vm.core.BpfInstruction;
import com.slytechs.jnet.jnetruntime.bpf.vm.instruction.BpfOpcode;

/**
 * Constructs and manipulates the intermediate representation.
 */
public class IRBuilder implements BpfIR {
	private final List<BpfInstruction> instructions = new ArrayList<>();
	private final Map<Integer, Integer> labelPositions = new HashMap<>();
	private int labelCounter = 0;

	public int getNextLabel() {
		return labelCounter++;
	}

	public void addLabel(int label) {
		labelPositions.put(label, instructions.size());
	}

	@Override
	public void emit(BpfInstruction instruction) {
		instructions.add(instruction);
	}

	public void emitAccept() {
		emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0xFFFFFFFF));
	}

	public void emitReject() {
		emit(BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0));
	}

	public void emitJump(int label) {
		// JMP_JA uses immediate value as jump offset
		// Offset will be resolved during label resolution
		emit(BpfInstruction.create(BpfOpcode.JMP_JA, label, 0, 0));
	}

	public void emitJumpIfFalse(int label) {
		// For JMP_JEQ_K, we need to set jt (jump if true) and jf (jump if false)
		// Since we want to jump if false (A == 0), we set jf to the label offset
		emit(BpfInstruction.create(BpfOpcode.JMP_JEQ_K, 0, label, 0));
	}

	public void emitJumpIfTrue(int label) {
		// For JMP_JEQ_K, we set the condition A == 0
		// If A != 0, we jump to label (jt)
		emit(BpfInstruction.create(BpfOpcode.JMP_JEQ_K, 0, label, 0));
	}

	@Override
	public List<BpfInstruction> getInstructions() throws CompilerException {
		// Before returning instructions, resolve label positions
		resolveLabels();
		return instructions;
	}

	private void resolveLabels() throws CompilerException {
		for (int i = 0; i < instructions.size(); i++) {
			BpfInstruction instr = instructions.get(i);
			BpfOpcode opcode = instr.getOpcodeEnum();

			if (opcode == BpfOpcode.JMP_JEQ_K || opcode == BpfOpcode.JMP_JGT_K ||
					opcode == BpfOpcode.JMP_JGE_K || opcode == BpfOpcode.JMP_JSET_K) {

				int jt = instr.getDst();
				int jf = instr.getSrc();

				if (labelPositions.containsKey(jt)) {
					int jtOffset = labelPositions.get(jt) - (i + 1);
					jt = jtOffset;
				} else if (jt != 0) {
					throw new CompilerException("Undefined label: " + jt, null);
				}

				if (labelPositions.containsKey(jf)) {
					int jfOffset = labelPositions.get(jf) - (i + 1);
					jf = jfOffset;
				} else if (jf != 0) {
					throw new CompilerException("Undefined label: " + jf, null);
				}

				instructions.set(i, BpfInstruction.create(opcode, jt, jf, instr.getImmediate()));
			} else if (opcode == BpfOpcode.JMP_JA) {
				int label = instr.getDst();
				if (labelPositions.containsKey(label)) {
					int offset = labelPositions.get(label) - (i + 1);
					instructions.set(i, BpfInstruction.create(opcode, offset, instr.getSrc(), instr.getImmediate()));
				} else {
					throw new CompilerException("Undefined label: " + label, null);
				}
			}
		}
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.bpf.compiler.ir.BpfIR#optimize()
	 */
	@Override
	public void optimize() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.bpf.compiler.ir.BpfIR#validate()
	 */
	@Override
	public void validate() throws CompilerException {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
