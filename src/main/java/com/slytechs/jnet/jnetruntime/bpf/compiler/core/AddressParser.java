package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Pattern;

public class AddressParser {

	// IPv4 Patterns
	// Matches: "192.168.1.1"
	private static final Pattern IPV4_DOTTED_DECIMAL = Pattern.compile(
			"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

	// Matches: "192.168.1.0/24"
	private static final Pattern IPV4_CIDR = Pattern.compile(
			"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[1-2]?[0-9])$");

	// Matches: "192.168.1.0 mask 255.255.255.0"
	private static final Pattern IPV4_NETMASK = Pattern.compile(
			"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\s+mask\\s+(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

	// Matches: "3232235777" (decimal for 192.168.1.1)
	private static final Pattern IPV4_DECIMAL = Pattern.compile(
			"^\\d{1,10}$");

	// Matches: "0xC0A80101" (hex for 192.168.1.1)
	private static final Pattern IPV4_HEXADECIMAL = Pattern.compile(
			"^0x[0-9a-fA-F]{8}$");

	// Matches: "030052000401" (octal for 192.168.1.1)
	private static final Pattern IPV4_OCTAL = Pattern.compile(
			"^0[0-7]{11}$");

	// IPv6 Patterns
	// Matches: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	private static final Pattern IPV6_FULL = Pattern.compile(
			"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");

	// Matches: "2001:db8:85a3::8a2e:370:7334"
	private static final Pattern IPV6_COMPRESSED = Pattern.compile(
			"^(?:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?):(?:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)$");

	// Matches: "::ffff:192.168.1.1"
	private static final Pattern IPV6_MIXED = Pattern.compile(
			"^::ffff:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

	// Matches: "2001:db8::/32"
	private static final Pattern IPV6_CIDR = Pattern.compile(
			"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/(?:12[0-8]|1[0-1][0-9]|[1-9]?[0-9])$");

	// MAC Address Patterns
	// Matches: "00:11:22:33:44:55"
	private static final Pattern MAC_COLON = Pattern.compile(
			"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$");

	// Matches: "00-11-22-33-44-55"
	private static final Pattern MAC_HYPHEN = Pattern.compile(
			"^([0-9A-Fa-f]{2}[-]){5}([0-9A-Fa-f]{2})$");

	// Matches: "0011.2233.4455"
	private static final Pattern MAC_DOT = Pattern.compile(
			"^([0-9A-Fa-f]{4}[.]){2}([0-9A-Fa-f]{4})$");

	// Matches: "001122334455"
	private static final Pattern MAC_RAW = Pattern.compile(
			"^[0-9A-Fa-f]{12}$");

	// DNS and Special Patterns
	// Matches: "host.example.com"
	private static final Pattern HOSTNAME = Pattern.compile(
			"^(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$");

	// Matches: "cisco" or "intel-corp"
	private static final Pattern OUI_VENDOR = Pattern.compile(
			"^[a-zA-Z][a-zA-Z0-9\\-_]{2,}$");

	// IPv4 Parsing Methods
	public static Optional<byte[]> parseIPv4DottedDecimal(String address) {
		if (!IPV4_DOTTED_DECIMAL.matcher(address).matches()) {
			return Optional.empty();
		}

		byte[] result = new byte[4];
		String[] parts = address.split("\\.");
		for (int i = 0; i < 4; i++) {
			result[i] = (byte) Integer.parseInt(parts[i]);
		}
		return Optional.of(result);
	}

	public static Optional<byte[]> parseIPv4CIDR(String address) {
		if (!IPV4_CIDR.matcher(address).matches()) {
			return Optional.empty();
		}

		String[] parts = address.split("/");
		byte[] ipBytes = parseIPv4DottedDecimal(parts[0]).orElse(null);
		if (ipBytes == null) {
			return Optional.empty();
		}

		// Parse CIDR prefix length
		int prefixLength = Integer.parseInt(parts[1]);
		if (prefixLength < 0 || prefixLength > 32) {
			return Optional.empty();
		}

		// Calculate netmask bytes from prefix length
		// Example: prefix 24 becomes 255.255.255.0
		int shiftBits = 32 - prefixLength;
		long maskValue = shiftBits == 32 ? 0 : ~((1L << shiftBits) - 1);

		byte[] result = new byte[8]; // 4 bytes IP + 4 bytes netmask

		// Copy IP address to first 4 bytes
		System.arraycopy(ipBytes, 0, result, 0, 4);

		// Fill in netmask in last 4 bytes
		result[4] = (byte) (maskValue >> 24);
		result[5] = (byte) (maskValue >> 16);
		result[6] = (byte) (maskValue >> 8);
		result[7] = (byte) maskValue;

		return Optional.of(result);
	}

	public static Optional<byte[]> parseIPv4Netmask(String address) {
		if (!IPV4_NETMASK.matcher(address).matches()) {
			return Optional.empty();
		}

		String[] parts = address.split("\\s+mask\\s+");
		byte[] ipBytes = parseIPv4DottedDecimal(parts[0]).orElse(null);
		byte[] maskBytes = parseIPv4DottedDecimal(parts[1]).orElse(null);

		if (ipBytes == null || maskBytes == null) {
			return Optional.empty();
		}

		byte[] result = new byte[8];
		System.arraycopy(ipBytes, 0, result, 0, 4);
		System.arraycopy(maskBytes, 0, result, 4, 4);
		return Optional.of(result);
	}

	public static Optional<byte[]> parseIPv4Decimal(String address) {
		if (!IPV4_DECIMAL.matcher(address).matches()) {
			return Optional.empty();
		}

		long value = Long.parseLong(address);
		if (value > 4294967295L) { // Max value for IPv4
			return Optional.empty();
		}

		return Optional.of(new byte[] {
				(byte) (value >> 24),
				(byte) (value >> 16),
				(byte) (value >> 8),
				(byte) value
		});
	}

	public static Optional<byte[]> parseIPv4Hexadecimal(String address) {
		if (!IPV4_HEXADECIMAL.matcher(address).matches()) {
			return Optional.empty();
		}

		long value = Long.parseLong(address.substring(2), 16);
		return Optional.of(new byte[] {
				(byte) (value >> 24),
				(byte) (value >> 16),
				(byte) (value >> 8),
				(byte) value
		});
	}

	public static Optional<byte[]> parseIPv4Octal(String address) {
		if (!IPV4_OCTAL.matcher(address).matches()) {
			return Optional.empty();
		}

		long value = Long.parseLong(address.substring(1), 8);
		return Optional.of(new byte[] {
				(byte) (value >> 24),
				(byte) (value >> 16),
				(byte) (value >> 8),
				(byte) value
		});
	}

	// IPv6 Parsing Methods
	public static Optional<byte[]> parseIPv6Full(String address) {
		if (!IPV6_FULL.matcher(address).matches()) {
			return Optional.empty();
		}

		byte[] result = new byte[16];
		String[] parts = address.split(":");
		for (int i = 0; i < 8; i++) {
			int value = Integer.parseInt(parts[i], 16);
			result[i * 2] = (byte) (value >> 8);
			result[i * 2 + 1] = (byte) value;
		}
		return Optional.of(result);
	}

	public static Optional<byte[]> parseIPv6Compressed(String address) {
		if (!IPV6_COMPRESSED.matcher(address).matches()) {
			return Optional.empty();
		}

		// Expand compressed notation
		String expanded = expandIPv6(address);
		return parseIPv6Full(expanded);
	}

	public static Optional<byte[]> parseIPv6Mixed(String address) {
		if (!IPV6_MIXED.matcher(address).matches()) {
			return Optional.empty();
		}

		String ipv4Part = address.substring(7); // Remove ::ffff:
		byte[] ipv4Bytes = parseIPv4DottedDecimal(ipv4Part).orElse(null);
		if (ipv4Bytes == null) {
			return Optional.empty();
		}

		byte[] result = new byte[16];
		Arrays.fill(result, 0, 10, (byte) 0);
		result[10] = (byte) 0xff;
		result[11] = (byte) 0xff;
		System.arraycopy(ipv4Bytes, 0, result, 12, 4);
		return Optional.of(result);
	}

	public static Optional<byte[]> parseIPv6CIDR(String address) {
		if (!IPV6_CIDR.matcher(address).matches()) {
			return Optional.empty();
		}

		String[] parts = address.split("/");
		byte[] ipv6Bytes = parseIPv6Full(parts[0]).orElse(null);
		if (ipv6Bytes == null) {
			return Optional.empty();
		}

		byte[] result = new byte[17]; // 16 bytes IPv6 + 1 byte prefix
		System.arraycopy(ipv6Bytes, 0, result, 0, 16);
		result[16] = (byte) Integer.parseInt(parts[1]);
		return Optional.of(result);
	}

	// MAC Address Parsing Methods
	public static Optional<byte[]> parseMACColon(String address) {
		if (!MAC_COLON.matcher(address).matches()) {
			return Optional.empty();
		}

		return Optional.of(parseMACAddress(address.split(":")));
	}

	public static Optional<byte[]> parseMACHyphen(String address) {
		if (!MAC_HYPHEN.matcher(address).matches()) {
			return Optional.empty();
		}

		return Optional.of(parseMACAddress(address.split("-")));
	}

	public static Optional<byte[]> parseMACDot(String address) {
		if (!MAC_DOT.matcher(address).matches()) {
			return Optional.empty();
		}

		String[] parts = address.split("\\.");
		byte[] result = new byte[6];
		for (int i = 0; i < 3; i++) {
			int value = Integer.parseInt(parts[i], 16);
			result[i * 2] = (byte) (value >> 8);
			result[i * 2 + 1] = (byte) value;
		}
		return Optional.of(result);
	}

	public static Optional<byte[]> parseMACRaw(String address) {
		if (!MAC_RAW.matcher(address).matches()) {
			return Optional.empty();
		}

		byte[] result = new byte[6];
		for (int i = 0; i < 6; i++) {
			result[i] = (byte) Integer.parseInt(address.substring(i * 2, (i + 1) * 2), 16);
		}
		return Optional.of(result);
	}

	// String-based patterns that return Optional<String>
	public static Optional<String> parseHostname(String address) {
		return HOSTNAME.matcher(address).matches() ? Optional.of(address) : Optional.empty();
	}

	public static Optional<String> parseOUIVendor(String vendor) {
		return OUI_VENDOR.matcher(vendor).matches() ? Optional.of(vendor) : Optional.empty();
	}

	// Helper methods
	private static byte[] parseMACAddress(String[] parts) {
		byte[] result = new byte[6];
		for (int i = 0; i < 6; i++) {
			result[i] = (byte) Integer.parseInt(parts[i], 16);
		}
		return result;
	}

	private static String expandIPv6(String compressed) {
		// Count number of groups present
		String[] parts = compressed.split(":");
		int presentGroups = parts.length;
		int missingGroups = 8 - (presentGroups - 1);

		StringBuilder expanded = new StringBuilder();
		boolean seenEmpty = false;

		for (String part : parts) {
			if (part.isEmpty()) {
				if (!seenEmpty) {
					for (int i = 0; i < missingGroups; i++) {
						expanded.append("0000:");
					}
					seenEmpty = true;
				}
			} else {
				expanded.append(String.format("%4s:", part).replace(' ', '0'));
			}
		}

		// Remove trailing colon
		return expanded.substring(0, expanded.length() - 1);
	}

	public static boolean isAddressChar(char ch) {
		return false

				|| ch == ':' // Used as IPv6 separators
				|| ch == '.' // Used as IPv6, IPv4 and MAC separators
				|| ch == '-' // Used as MAC separator
				|| ch == ':' // Used as MAC separator
				|| ch == '/' // Used as IPv6, IPv4 CIDR separator

		;

	}

	public static boolean isHexDigit(char ch) {
		return false

				|| ch == '0'
				|| ch == '1'
				|| ch == '2'
				|| ch == '3'
				|| ch == '4'
				|| ch == '5'
				|| ch == '6'
				|| ch == '7'
				|| ch == '8'
				|| ch == '9'
				|| ch == 'a'
				|| ch == 'b'
				|| ch == 'c'
				|| ch == 'd'
				|| ch == 'e'
				|| ch == 'f'
				|| ch == 'A'
				|| ch == 'B'
				|| ch == 'C'
				|| ch == 'D'
				|| ch == 'E'
				|| ch == 'F';
	}
}