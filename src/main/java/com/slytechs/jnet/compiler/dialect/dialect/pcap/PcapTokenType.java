package com.slytechs.jnet.compiler.dialect.dialect.pcap;

import com.slytechs.jnet.compiler.frontend.TokenType;

/**
 * Enumeration of token types specific to the Pcap compilerFrontend.
 */
public enum PcapTokenType implements TokenType {
	IDENTIFIER,
	NUMBER,
	IPv4, // byte[4]
	IPv4_NETMASK, // byte[8]
	IPv6, // byte[16]
	IPv6_CIDR, // byte[17] - last byte is CDIR bit count
	MAC, // byte[12]
	OPERATOR,
	KEYWORD,
	STRING,
	EOF,
	PROTOCOL, // e.g., "tcp", "udp"
	TCP_FLAG, // e.g., "tcp-fin", "tcp-syn"
	ICMP_TYPE, // e.g., "icmp-echoreply", "icmp-unreach"
	PORT, // e.g., "port"
	LEFT_PAREN, // '('
	RIGHT_PAREN, // ')'
	LEFT_SQUARE, // '['
	RIGHT_SQUARE, // ']'
	COLON, // ':'
	UNKNOWN // For any unknown or invalid tokens
	// Add additional Pcap-specific token types as needed
}
