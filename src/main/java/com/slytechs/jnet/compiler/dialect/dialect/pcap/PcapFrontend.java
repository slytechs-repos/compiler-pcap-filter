package com.slytechs.jnet.compiler.dialect.dialect.pcap;

import com.slytechs.jnet.compiler.CompilerDialect;
import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.CompilerFrontend;
import com.slytechs.jnet.compiler.frontend.Lexer;
import com.slytechs.jnet.compiler.frontend.Parser;

/**
 * Concrete implementation of PcapFrontend.
 */
public class PcapFrontend implements CompilerFrontend {

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "PcapFrontend ["
				+ "name=" + getName()
				+ "]";
	}

	@Override
	public String getName() {
		return "Pcap";
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#createLexer(java.lang.String)
	 */
	@Override
	public Lexer createLexer(String source) throws CompilerException {
		return new PcapLexer(source);
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#createParser(com.slytechs.jnet.compiler.frontend.Lexer)
	 */
	@Override
	public Parser createParser(Lexer lexer) throws CompilerException {
		return new PcapParser(lexer);
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#compilerDialect()
	 */
	@Override
	public CompilerDialect compilerDialect() {
		return CompilerDialect.PCAP;
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#compilerDialectId()
	 */
	@Override
	public int compilerDialectId() {
		return CompilerDialect.PCAP_DIALECT_ID;
	}
}
