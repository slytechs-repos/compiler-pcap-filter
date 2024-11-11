package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.ntpl;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect;

/**
 * Represents the NTPL compiler dialect.
 */
public interface NtplDialect extends CompilerDialect<NtplTokenType, NtplASTNode> {

	/**
	 * Returns the name of the dialect.
	 *
	 * @return the dialect name "NTPL"
	 */
	@Override
	default String getName() {
		return "NTPL";
	}

	// Add any NTPL-specific methods if needed
}
