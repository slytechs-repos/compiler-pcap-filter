package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.wireshark;

import com.slytechs.jnet.compiler.frontend.TokenType;

/**
 * Enumeration of token types specific to the Wireshark compilerFrontend.
 */
public enum WiresharkTokenType implements TokenType {
	IDENTIFIER,
	NUMBER,
	OPERATOR,
	KEYWORD,
	STRING,
	EOF,
	// Wireshark-specific tokens
	FIELD_NAME, // e.g., "ip.src", "tcp.port"
	RELATIONAL_OP, // e.g., "==", "!=", ">", "<"
}
