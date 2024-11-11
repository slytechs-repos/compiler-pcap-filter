package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.ASTNode;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Parser;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.TokenType;

/**
 * Defines the contract for dialect-specific components.
 */
public interface CompilerDialect<T extends TokenType, N extends ASTNode> {

	/**
	 * Returns the name of the dialect.
	 *
	 * @return the dialect name
	 */
	String getName();

	/**
	 * Creates a lexer for the given source code.
	 *
	 * @param source the source code to lex
	 * @return a lexer instance
	 */
	Lexer<T> createLexer(String source) throws CompilerException;

	/**
	 * Creates a parser using the given lexer.
	 *
	 * @param lexer the lexer to use
	 * @return a parser instance
	 */
	Parser<T, N> createParser(Lexer<T> lexer) throws CompilerException;
}
