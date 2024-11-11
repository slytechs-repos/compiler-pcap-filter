package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

/**
 * Base class for compiler-related exceptions.
 */
public class CompilerException extends Exception {

	private static final long serialVersionUID = 3573538346993208757L;
	private final Position position;

	/**
	 * Constructs a new CompilerException with the specified detail message.
	 *
	 * @param message  the detail message
	 * @param position the position in the source code where the error occurred
	 */
	public CompilerException(String message, Position position) {
		super(message);
		this.position = position;
	}

	/**
	 * Constructs a new CompilerException with the specified detail message and
	 * cause.
	 *
	 * @param message  the detail message
	 * @param position the position in the source code where the error occurred
	 * @param cause    the cause of the exception
	 */
	public CompilerException(String message, Position position, Throwable cause) {
		super(message, cause);
		this.position = position;
	}

	/**
	 * Gets the position in the source code where the error occurred.
	 *
	 * @return the position
	 */
	public Position getPosition() {
		return position;
	}
}
