package com.slytechs.jnet.jnetruntime.bpf.compiler.frontend;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;

/**
 * Interface for the parser.
 *
 * @param <T> the token type enum that implements TokenType
 * @param <N> the AST node type specific to the dialect
 */
public interface Parser<T extends TokenType, N extends ASTNode> {

	/**
	 * Parses the input and returns the root of the abstract syntax tree.
	 *
	 * @return the root AST node
	 * @throws CompilerException if a parsing error occurs
	 */
	N parse() throws CompilerException;
}
