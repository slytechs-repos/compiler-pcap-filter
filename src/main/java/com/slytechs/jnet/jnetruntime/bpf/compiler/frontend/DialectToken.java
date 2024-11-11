package com.slytechs.jnet.jnetruntime.bpf.compiler.frontend;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.Position;

/**
 * Represents a token with a dialect-specific token type.
 *
 * @param <T> the enum type representing the token type
 */
public class DialectToken<T extends Enum<T> & TokenType> extends Token<T> {

	private final T dialectTokenType;

	/**
	 * Constructs a new DialectToken.
	 *
	 * @param type     the token type
	 * @param value    the token value
	 * @param position the position in the source code
	 */
	public DialectToken(T type, String value, Position position) {
		super(type, value, position);
		this.dialectTokenType = type;
	}

	@Override
	public T getType() {
		return dialectTokenType;
	}
}
