package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Parser;

/**
 * Concrete implementation of PcapDialect.
 */
public class PcapDialectImpl implements PcapDialect {

	@Override
	public String getName() {
		return "Pcap";
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect#createLexer(java.lang.String)
	 */
	@Override
	public Lexer<PcapTokenType> createLexer(String source) throws CompilerException {
		return new PcapLexer(source);
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect#createParser(com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer)
	 */
	@Override
	public Parser<PcapTokenType, PcapASTNode> createParser(Lexer<PcapTokenType> lexer) throws CompilerException {
		return new PcapParser(lexer);
	}
}
