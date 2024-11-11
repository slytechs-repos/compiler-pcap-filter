package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.BpfCompiler;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.ASTNode;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Parser;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.TokenType;
import com.slytechs.jnet.jnetruntime.bpf.compiler.ir.BpfIR;
import com.slytechs.jnet.jnetruntime.bpf.vm.core.BpfProgram;

/**
 * Base implementation of the BpfCompiler interface.
 */
public abstract class AbstractBpfCompiler<T extends TokenType, N extends ASTNode>
		implements BpfCompiler<T, N> {

	protected CompilerDialect<T, N> dialect;
	protected CompilerOptions options;

	@Override
	public BpfProgram compile(String source) throws CompilerException {
		return compile(source, new CompilerOptions());
	}

	@Override
	public BpfProgram compile(String source, CompilerOptions options) throws CompilerException {
		this.options = options;
		Lexer<T> lexer = createLexer(source);
		Parser<T, N> parser = createParser(lexer);

		// Parse the source code into an AST
		N ast = parser.parse();

		// Generate IR from AST
		BpfIR ir = generateIR(ast);

		// Optimize IR if needed
		if (options.getOptimizationLevel() > 0) {
			ir.optimize();
		}

		// Validate IR
		ir.validate();

		// Generate BPF program from IR
		BpfProgram program = generateProgram(ir);

		return program;
	}

	@Override
	public CompilerDialect<T, N> getDialect() {
		return dialect;
	}

	protected abstract Lexer<T> createLexer(String source) throws CompilerException;

	protected abstract Parser<T, N> createParser(Lexer<T> lexer)
			throws CompilerException;

	protected abstract BpfIR generateIR(N ast) throws CompilerException;

	protected abstract BpfProgram generateProgram(BpfIR ir) throws CompilerException;

	@Override
	public void setOptions(CompilerOptions options) {
		this.options = options;
	}

	@Override
	public CompilerOptions getOptions() {
		return options;
	}
}
