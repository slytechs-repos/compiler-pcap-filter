package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap;

import static com.slytechs.jnet.jnetruntime.bpf.compiler.core.AddressParser.*;
import static java.lang.Character.*;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.Position;
import com.slytechs.jnet.jnetruntime.bpf.compiler.core.AddressParser;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.AbstractLexer;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Token;

/**
 * Concrete lexer for the Pcap dialect.
 */
public class PcapLexer extends AbstractLexer<PcapTokenType> {

	private static final Set<String> KEYWORDS = new HashSet<>();
	private static final Set<String> PROTOCOLS = new HashSet<>();
	private static final Map<String, Integer> TCP_FLAGS = new HashMap<>();
	private static final Map<String, Integer> ICMP_TYPES = new HashMap<>();

	static {

		// Initialize Pcap-specific keywords
		KEYWORDS.add("port");
		KEYWORDS.add("src");
		KEYWORDS.add("dst");
		KEYWORDS.add("host");
		KEYWORDS.add("net");
		KEYWORDS.add("mask");
		KEYWORDS.add("gateway");
		KEYWORDS.add("broadcast");
		KEYWORDS.add("multicast");
		KEYWORDS.add("less");
		KEYWORDS.add("greater");
		KEYWORDS.add("type");
		KEYWORDS.add("vlan");
		KEYWORDS.add("mpls");
		KEYWORDS.add("pppoes");
		KEYWORDS.add("outbound");
		KEYWORDS.add("inbound");
		KEYWORDS.add("tcpflags");

		// TCP Flags
		TCP_FLAGS.put("tcp-fin", 0x01);
		TCP_FLAGS.put("tcp-syn", 0x02);
		TCP_FLAGS.put("tcp-rst", 0x04);
		TCP_FLAGS.put("tcp-push", 0x08);
		TCP_FLAGS.put("tcp-ack", 0x10);
		TCP_FLAGS.put("tcp-urg", 0x20);

		// ICMP Types
		ICMP_TYPES.put("icmp-echoreply", 0);
		ICMP_TYPES.put("icmp-unreach", 3);
		ICMP_TYPES.put("icmp-sourcequench", 4);
		ICMP_TYPES.put("icmp-redirect", 5);
		ICMP_TYPES.put("icmp-echo", 8);
		ICMP_TYPES.put("icmp-routeradvert", 9);
		ICMP_TYPES.put("icmp-routersolicit", 10);
		ICMP_TYPES.put("icmp-timxceed", 11);
		ICMP_TYPES.put("icmp-paramprob", 12);
		ICMP_TYPES.put("icmp-tstamp", 13);
		ICMP_TYPES.put("icmp-tstampreply", 14);
		ICMP_TYPES.put("icmp-ireq", 15);
		ICMP_TYPES.put("icmp-ireqreply", 16);
		ICMP_TYPES.put("icmp-maskreq", 17);
		ICMP_TYPES.put("icmp-maskreply", 18);

		// Initialize Protocol Qualifiers
		PROTOCOLS.add("tr");
		PROTOCOLS.add("wlan");
		PROTOCOLS.add("ether");
		PROTOCOLS.add("fddi");
		PROTOCOLS.add("ip");
		PROTOCOLS.add("ip6");
		PROTOCOLS.add("arp");
		PROTOCOLS.add("rarp");
		PROTOCOLS.add("icmp");
		PROTOCOLS.add("tcp");
		PROTOCOLS.add("udp");
	}

	public PcapLexer(String input) {
		super(input);
	}

	@Override
	public Token<PcapTokenType> nextToken() throws CompilerException {
		var token = nextToken0();

		System.out.println("::nextToken token=" + token);

		return token;
	}

	public Token<PcapTokenType> nextToken0() throws CompilerException {
		skipWhitespace();

		if (isEOF()) {
			return new Token<>(PcapTokenType.EOF, "", new Position(lineNumber, columnNumber));
		}

		char ch = peekChar();

		if (isOperatorStart(ch)) {
			return readOperator();

		} else if (Character.isLetter(ch)) {
			return readIdentifierOrKeyword();

		} else if (isDigit(ch)) {
			return readNumberOrAddress();

		} else if (ch == '"') {
			return readString();

		} else {
			reportLexicalError("Invalid character", String.valueOf(ch));

			return null; // Unreachable
		}
	}

	private void skipWhitespace() {
		while (!isEOF() && Character.isWhitespace(peekChar())) {
			nextChar();
		}
	}

	private Token<PcapTokenType> readIdentifierOrKeyword() {
		StringBuilder sb = new StringBuilder();
		Position start = new Position(lineNumber, columnNumber);

		while (!isEOF()
				&& (false

						|| isLetterOrDigit(peekChar())
						|| peekChar() == '_'
						|| peekChar() == '.'
						|| peekChar() == '-' // eg. 'icmp-echo'

				)) {
			sb.append(nextChar());
		}

		String value = sb.toString().toLowerCase(); // Pcap is case-insensitive

		if (KEYWORDS.contains(value)) {
			return new Token<>(PcapTokenType.KEYWORD, value, start);

		} else if (PROTOCOLS.contains(value)) {
			return new Token<>(PcapTokenType.PROTOCOL, value, start);

		} else if (TCP_FLAGS.containsKey(value)) {
			return new Token<>(PcapTokenType.TCP_FLAG, value, TCP_FLAGS.get(value), start);

		} else if (ICMP_TYPES.containsKey(value)) {
			return new Token<>(PcapTokenType.ICMP_TYPE, value, ICMP_TYPES.get(value), start);

		} else {
			return new Token<>(PcapTokenType.IDENTIFIER, value, start);
		}
	}

	private Token<PcapTokenType> readAddress() {
		StringBuilder sb = new StringBuilder();
		Position start = new Position(lineNumber, columnNumber);

		int i = 0;
		var dist = new HashMap<Character, AtomicInteger>();
		dist.put(':', new AtomicInteger());
		dist.put('.', new AtomicInteger());
		dist.put('-', new AtomicInteger());
		dist.put('/', new AtomicInteger());

		// Collect address characters in the buffer and the run tests for a specific
		// address type match
		char ch = peekCharAt(i);
		while (!isEOF(i)
				&& (false

						|| isHexDigit(ch)
						|| isAddressChar(ch)

				)) {

			ch = peekCharAt(i++);

			if (isAddressChar(ch)) {
				var counter = dist.get(ch);
				counter.incrementAndGet();
			}

			sb.append(ch);
		}

		// IPV4_CIDR (Matches: "192.168.1.0/24")
		if (dist.get('.').get() == 3 && dist.get('/').get() == 1) {
			return scanForAddressType(
					PcapTokenType.IPv4_NETMASK,
					sb.toString(),
					start,
					AddressParser::parseIPv4CIDR);
		}

		// IPV4_DOTTED_DECIMAL (Matches: "192.168.1.1")
		if (dist.get('.').get() == 3) {
			return scanForAddressType(
					PcapTokenType.IPv4,
					sb.toString(),
					start,
					AddressParser::parseIPv4DottedDecimal);
		}

		// IPV4_OCTAL (Matches: "030052000401" (octal for 192.168.1.1))
		if (dist.get('.').get() == 0 && sb.charAt(0) == '0') {
			return scanForAddressType(
					PcapTokenType.IPv4,
					sb.toString(),
					start,
					AddressParser::parseIPv4Octal);
		}

		// IPV6_FULL (Matches: "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
		if (dist.get(':').get() == 7 && sb.length() == 39) {
			return scanForAddressType(
					PcapTokenType.IPv6,
					sb.toString(),
					start,
					AddressParser::parseIPv6Full);
		}

		// IPV6_MIXED (Matches: "::ffff:192.168.1.1")
		if (dist.get(':').get() > 2 && dist.get('.').get() == 4) {
			return scanForAddressType(
					PcapTokenType.IPv6,
					sb.toString(),
					start,
					AddressParser::parseIPv6Mixed);
		}

		// IPV6_CIDR (Matches: "2001:db8::/32")
		if (dist.get(':').get() > 2 && dist.get('/').get() == 1) {
			return scanForAddressType(
					PcapTokenType.IPv6_CIDR,
					sb.toString(),
					start,
					AddressParser::parseIPv6CIDR);
		}

		// IPV6_COMPRESSED (Matches: "2001:db8:85a3::8a2e:370:7334")
		if (dist.get(':').get() > 2) {
			return scanForAddressType(
					PcapTokenType.IPv6,
					sb.toString(),
					start,
					AddressParser::parseIPv6Compressed);
		}

		// MAC_COLON (Matches: "00:11:22:33:44:55")
		if (dist.get(':').get() == 5) {
			return scanForAddressType(
					PcapTokenType.MAC,
					sb.toString(),
					start,
					AddressParser::parseMACColon);
		}

		// MAC_HYPHEN (Matches: "00-11-22-33-44-55")
		if (dist.get('-').get() == 5) {
			return scanForAddressType(
					PcapTokenType.MAC,
					sb.toString(),
					start,
					AddressParser::parseMACHyphen);
		}

		// MAC_DOT (Matches: "0011.2233.4455")
		if (dist.get('.').get() == 2 && sb.length() == 14) {
			return scanForAddressType(
					PcapTokenType.MAC,
					sb.toString(),
					start,
					AddressParser::parseMACDot);
		}

		// Not an address
		return null;
	}

	private Token<PcapTokenType> scanForAddressType(
			PcapTokenType type,
			String value,
			Position start,
			Function<String, Optional<byte[]>> matcher) {

		Optional<byte[]> address = matcher.apply(value);
		if (address.isEmpty())
			return null;

		skip(value.length());

		return new Token<>(type, value, address.get(), start);
	}

	private Token<PcapTokenType> readNumberOrAddress() {

		// Check for an address token
		var tkn = readAddress();
		if (tkn != null)
			return tkn;

		StringBuilder sb = new StringBuilder();
		Position start = new Position(lineNumber, columnNumber);

		if (!isEOF() && !isHexDigit(peekChar()))
			return new Token<>(PcapTokenType.NUMBER, "" + nextChar(), start);

		while (!isEOF() && (isHexDigit(peekChar()) || peekChar() == 'x' || peekChar() == '_')) {
			sb.append(nextChar());
		}

		String value = sb.toString();
		return Token.ofInt(PcapTokenType.NUMBER, value, start);
	}

	private Token<PcapTokenType> readString() throws CompilerException {
		Position start = new Position(lineNumber, columnNumber);
		nextChar(); // Consume the opening quote

		StringBuilder sb = new StringBuilder();

		while (!isEOF() && peekChar() != '"') {
			sb.append(nextChar());
		}

		if (isEOF()) {
			reportLexicalError("Unterminated string literal", sb.toString());
		}

		nextChar(); // Consume the closing quote
		String value = sb.toString();

		return new Token<>(PcapTokenType.STRING, value, start);
	}

	private boolean isOperatorStart(char ch) {
		return false

				|| ch == '&'
				|| ch == '|'
				|| ch == '!'
				|| ch == ':'
				|| ch == '['
				|| ch == ']'
				|| ch == '('
				|| ch == ')'
				|| ch == '='
				|| ch == '>'
				|| ch == '*'
				|| ch == '^'
				|| ch == 'a'
				|| ch == 'o'
				|| ch == 'n'

		;
	}

	private Token<PcapTokenType> readOperator() throws CompilerException {
		Position start = new Position(lineNumber, columnNumber);
		char ch = nextChar();
		String value = String.valueOf(ch);

		PcapTokenType type;

		switch (ch) {
		case 'a': {
			if (!isEOF() && peekChar() == 'n')
				value += nextChar();

			if (!isEOF() && peekChar() == 'd') {
				nextChar();
				value = "&&";
			}

			type = PcapTokenType.OPERATOR;
			break;
		}

		case 'o': {
			if (!isEOF() && peekChar() == 'r') {
				nextChar();
				value = "||";
			}

			type = PcapTokenType.OPERATOR;
			break;
		}

		case 'n': {
			if (!isEOF() && peekChar() == 'o') {
				value += nextChar();
			}

			if (!isEOF() && peekChar() == 't') {
				nextChar();
				value = "!";
			}

			type = PcapTokenType.OPERATOR;
			break;
		}

		case '&':
			if (!isEOF() && peekChar() == '&') {
				nextChar();
				value = "&&";

			}

			type = PcapTokenType.OPERATOR;
			break;

		case '|':
			if (!isEOF() && peekChar() == '|') {
				nextChar();
				value = "||";

			}

			type = PcapTokenType.OPERATOR;
			break;

		case '!':
			if (!isEOF() && peekChar() == '=') {
				nextChar();
				value = "!=";
			}

			type = PcapTokenType.OPERATOR;
			break;

		case ':':
			type = PcapTokenType.COLON;
			break;

		case '[':
			type = PcapTokenType.LEFT_SQUARE;
			break;

		case ']':
			type = PcapTokenType.LEFT_SQUARE;
			break;

		case '(':
			type = PcapTokenType.LEFT_PAREN;
			break;

		case ')':
			type = PcapTokenType.RIGHT_PAREN;
			break;

		case '=':
			if (!isEOF() && peekChar() == '=') {
				nextChar();
			}

			value = "==";
			type = PcapTokenType.OPERATOR;
			break;

		case '>':
			if (!isEOF() && peekChar() == '=') {
				value += nextChar();

			} else if (!isEOF() && peekChar() == '>') {
				value += nextChar();
			}

			type = PcapTokenType.OPERATOR;
			break;

		case '<':
			if (!isEOF() && peekChar() == '=') {
				value += nextChar();
			}

			type = PcapTokenType.OPERATOR;
			break;

		default:
			reportLexicalError("Invalid operator", String.valueOf(ch));
			type = PcapTokenType.UNKNOWN;
			break;
		}

		return new Token<>(type, value, start);
	}
}
