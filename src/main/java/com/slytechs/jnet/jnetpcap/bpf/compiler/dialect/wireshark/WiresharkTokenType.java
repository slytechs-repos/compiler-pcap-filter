package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark;

import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.TokenType;

/**
 * Enumeration of token types specific to the Wireshark dialect.
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
