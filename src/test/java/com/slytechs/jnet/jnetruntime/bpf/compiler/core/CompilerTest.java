// File: src/test/java/com/slytechs/jnet/jnetruntime/bpf/compiler/core/CompilerTest.java

package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.dialect.dialect.pcap.PcapCompiler;
import com.slytechs.jnet.compiler.dialect.dialect.pcap.PcapLexer;
import com.slytechs.jnet.compiler.dialect.dialect.pcap.PcapParser;
import com.slytechs.jnet.compiler.dialect.dialect.pcap.ProtocolNode;
import com.slytechs.jnet.compiler.frontend.ASTNode;

public class CompilerTest {

	/**
	 * Test compiling the expression "A == 0x800" using the Pcap compilerFrontend
	 * compiler.
	 */
	@Test
	public void testPcapCompilerAEquals0x800() throws CompilerException {
		// Step 1: Define the expression
		String expression = "172.16.0.0/16";
//		String expression = "src host 192.168.1.1 and dst port 80";
//		String expression = "2001:db8::/32";

		// Step 2: Initialize the Pcap Compiler
		PcapCompiler compiler = new PcapCompiler();

		PcapLexer lexer = new PcapLexer(expression);
		PcapParser parser = new PcapParser(lexer);

		// Step 3: Parse the expression into AST
		ASTNode ast = parser.parse();

		// Define the expected AST
		ASTNode expectedAst = new ProtocolNode("ip");

//		// Step 4: Verify the AST structure
		assertEquals(expectedAst, ast, "The AST should match the expected structure for 'A == 0x800'.");

//		// Step 5: Compile AST into IR
//		IR ir = compiler.compileToIR(ast);
//
//		// Define the expected IR
//		IR expectedIR = new IR();
//		expectedIR.add(new IRLoadRegister("A", 0x800));
//		expectedIR.add(new IRCmpLiteral("==", "A", 0x800));
//		expectedIR.add(new IRJumpIfTrue(1)); // Jump ahead by 1 if condition is true
//		expectedIR.add(new IRReturnFalse()); // If condition is false, return false
//		expectedIR.add(new IRReturnTrue()); // If condition is true, return true
//
//		// Step 6: Verify the IR structure
//		assertEquals(expectedIR, ir, "The IR should match the expected structure.");
//
//		// Step 7: Compile IR into BPF Opcodes
//		BpfProgram program = compiler.compileToBpf(ir);
//
//		// Define the expected BPF Opcodes
//		BpfInstruction[] expectedInstructions = new BpfInstruction[] {
//				// Load immediate value 0x800 into A
//				BpfInstruction.create(BpfOpcode.LD_IMM, 0, 0, 0x800),
//				// Compare A to 0x800 and jump ahead by 1 if equal
//				BpfInstruction.create(BpfOpcode.JMP_JEQ_K, 1, 0, 0x800),
//				// If not equal, return false (0)
//				BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 0),
//				// If equal, return true (65535)
//				BpfInstruction.create(BpfOpcode.RET_K, 0, 0, 65535)
//		};
//
//		// Step 8: Verify the BPF Opcodes
//		assertArrayEquals(expectedInstructions, program.getInstructions(),
//				"The BPF Program should contain the expected instructions for 'A == 0x800'.");
	}

}
