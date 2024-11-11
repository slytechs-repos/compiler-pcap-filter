package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

/**
 * Exception thrown during the code generation phase.
 */
public class CodeGenerationException extends CompilerException {

	private static final long serialVersionUID = 3396274229292334208L;

	/**
	 * Constructs a new CodeGenerationException with the specified detail message.
	 *
	 * @param message  the detail message
	 * @param position the position in the source code where the error occurred
	 */
	public CodeGenerationException(String message, Position position) {
		super(message, position);
	}

	/**
	 * Constructs a new CodeGenerationException with the specified detail message
	 * and cause.
	 *
	 * @param message  the detail message
	 * @param position the position in the source code where the error occurred
	 * @param cause    the cause of the exception
	 */
	public CodeGenerationException(String message, Position position, Throwable cause) {
		super(message, position, cause);
	}
}
