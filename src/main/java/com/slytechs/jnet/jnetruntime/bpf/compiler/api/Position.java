package com.slytechs.jnet.jnetruntime.bpf.compiler.api;

/**
 * Represents a position in the source code.
 */
public class Position {

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "Position [line=" + line + ", column=" + column + "]";
	}

	private final int line;
	private final int column;

	/**
	 * Constructs a new Position with the specified line and column.
	 *
	 * @param line   the line number
	 * @param column the column number
	 */
	public Position(int line, int column) {
		this.line = line;
		this.column = column;
	}

	/**
	 * Gets the line number.
	 *
	 * @return the line number
	 */
	public int getLine() {
		return line;
	}

	/**
	 * Gets the column number.
	 *
	 * @return the column number
	 */
	public int getColumn() {
		return column;
	}
}
