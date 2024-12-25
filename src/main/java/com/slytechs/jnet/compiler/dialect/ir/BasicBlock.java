package com.slytechs.jnet.compiler.dialect.ir;

import java.util.ArrayList;
import java.util.List;

import com.slytechs.jnet.platform.jnpl.vm.core.BpfInstruction;

/**
 * Represents a basic block in the intermediate representation.
 */
public class BasicBlock {

    private final List<BpfInstruction> instructions = new ArrayList<>();

    /**
     * Adds an instruction to the basic block.
     *
     * @param instruction the instruction to add
     */
    public void addInstruction(BpfInstruction instruction) {
        instructions.add(instruction);
    }

    /**
     * Gets the list of instructions in the basic block.
     *
     * @return the list of instructions
     */
    public List<BpfInstruction> getInstructions() {
        return instructions;
    }
}
