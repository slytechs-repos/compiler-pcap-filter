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
package com.slytechs.jnet.compiler.dialect.ir;

import java.util.List;

import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.ir.IRNode;
import com.slytechs.jnet.platform.jnpl.vm.core.BpfInstruction;

/**
 * Represents the intermediate representation operations.
 */
public interface BpfIR extends IRNode {

	/**
	 * Emits the given BPF instruction into the intermediate representation.
	 *
	 * @param instruction the BPF instruction to emit
	 */
	void emit(BpfInstruction instruction);

	/**
	 * @see com.slytechs.jnet.compiler.ir.IRNode#optimize()
	 */
	@Override
	void optimize();

	/**
	 * @see com.slytechs.jnet.compiler.ir.IRNode#validate()
	 */
	@Override
	void validate() throws CompilerException;

	List<BpfInstruction> getInstructions() throws CompilerException;

}
