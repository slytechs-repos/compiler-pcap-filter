package com.slytechs.jnet.jnetruntime.bpf.compiler.ir;

import java.util.List;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.vm.core.BpfInstruction; // Import existing BpfInstruction

/**
 * Represents the intermediate representation operations.
 */
public interface BpfIR {

	/**
	 * Emits the given BPF instruction into the intermediate representation.
	 *
	 * @param instruction the BPF instruction to emit
	 */
	void emit(BpfInstruction instruction);

	/**
	 * Performs optimization on the intermediate representation.
	 */
	void optimize();

	/**
	 * Validates the intermediate representation for correctness.
	 *
	 * @throws CompilerException if validation fails
	 */
	void validate() throws CompilerException;

	List<BpfInstruction> getInstructions() throws CompilerException;

}
