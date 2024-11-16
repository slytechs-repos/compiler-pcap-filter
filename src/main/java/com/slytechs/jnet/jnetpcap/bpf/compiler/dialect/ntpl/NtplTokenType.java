package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.ntpl;

import com.slytechs.jnet.compiler.frontend.TokenType;

/**
 * Enumeration of token types specific to the NTPL compilerFrontend.
 */
public enum NtplTokenType implements TokenType {
	IDENTIFIER,
	NUMBER,
	OPERATOR,
	KEYWORD,
	STRING,
	EOF,
	// NTPL-specific tokens
	FILTER_EXPRESSION, // e.g., "IF 1", "MAC_ADDR"
}
