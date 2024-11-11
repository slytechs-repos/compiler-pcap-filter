package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.ntpl.NtplCompiler;
import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.ntpl.NtplDialect;
import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.ntpl.NtplDialectImpl;
import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap.PcapCompiler;
import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap.PcapDialect;
import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap.PcapDialectImpl;
import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark.WiresharkCompiler;
import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark.WiresharkDialect;
import com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark.WiresharkDialectImpl;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.ASTNode;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Parser;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.TokenType;

/**
 * Defines the contract for dialect-specific components.
 */
public interface CompilerDialect<T extends TokenType, N extends ASTNode> {

	public static final PcapDialect PCAP = new PcapDialectImpl();
	public static final WiresharkDialect WIRESHARK = new WiresharkDialectImpl();
	public static final NtplDialect NTPL = new NtplDialectImpl();

	static <T extends TokenType, N extends ASTNode> BpfCompiler forDialect(CompilerDialect<T, N> dialect) {
		return (BpfCompiler) switch (dialect) {
		case PcapDialect d -> new PcapCompiler();
		case WiresharkDialect d -> new WiresharkCompiler();
		case NtplDialect d -> new NtplCompiler();

		default -> throw new IllegalArgumentException("Unexpected value: " + dialect);
		};
	}

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
