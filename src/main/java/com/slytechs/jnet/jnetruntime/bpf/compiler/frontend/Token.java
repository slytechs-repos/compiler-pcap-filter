package com.slytechs.jnet.jnetruntime.bpf.compiler.frontend;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.Position;

/**
 * Represents a lexical token.
 *
 * @param <T> the token type enum that implements TokenType
 */
public class Token<T extends TokenType> {

	public static <T extends TokenType> Token<T> ofInt(T type, String value, Position position) {
		String normalized = value.trim().replaceAll("_", "");

		long intValue; // use long to be able to store full 32-bits unsigned integer
		if (normalized.startsWith("0x"))
			intValue = Long.parseLong(normalized.substring(2), 16);

		else if (normalized.startsWith("0") && Character.isDigit(normalized.charAt(1)))
			intValue = Long.parseLong(normalized.substring(1), 8);

		else if (normalized.startsWith("0b"))
			intValue = Long.parseLong(normalized.substring(2), 2);

		else
			intValue = Long.parseLong(normalized);

		return new Token<T>(type, value, intValue, position);
	}

	private final T type;
	private final String value;
	private final Long intValue;
	private final byte[] address;
	private final Position position;

	/**
	 * Constructs a new Token with the specified type, value, and position.
	 *
	 * @param type     the token type
	 * @param value    the token value
	 * @param position the position in the source code
	 */
	public Token(T type, String value, Position position) {
		this.type = type;
		this.value = value;
		this.intValue = null;
		this.position = position;
		this.address = null;
	}

	public Token(T type, String value, long intValue, Position position) {
		this.type = type;
		this.value = value;
		this.intValue = intValue;
		this.position = position;
		this.address = null;
	}

	public Token(T type, String value, byte[] address, Position position) {
		this.type = type;
		this.value = value;
		this.address = address;
		this.intValue = null;
		this.position = position;
	}

	public byte[] addressValue() {
		return address;
	}

	/**
	 * Gets the token type.
	 *
	 * @return the token type
	 */
	public T getType() {
		return type;
	}

	/**
	 * Gets the token value.
	 *
	 * @return the token value
	 */
	public String getValue() {
		return value;
	}

	public long intValue() {
		return intValue == null ? 0 : intValue;
	}

	/**
	 * Gets the position of the token in the source code.
	 *
	 * @return the position
	 */
	public Position getPosition() {
		return position;
	}

	@Override
	public String toString() {
		return "Token{" +
				"type=" + type +
				", value='" + value + '\'' +
				(intValue == null ? "" : " (0x" + Long.toHexString(intValue) + ")") +
				", position=" + position +
				'}';
	}
}
