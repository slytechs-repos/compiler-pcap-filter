package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.wireshark;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect;

/**
 * Represents the Wireshark compiler dialect.
 */
public interface WiresharkDialect extends CompilerDialect<WiresharkTokenType, WiresharkASTNode> {

	/**
	 * Returns the name of the dialect.
	 *
	 * @return the dialect name "Wireshark"
	 */
	@Override
	default String getName() {
		return "Wireshark";
	}

	// Add any Wireshark-specific methods if needed
}
