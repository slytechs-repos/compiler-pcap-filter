package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect;

/**
 * Represents the Pcap compiler dialect.
 */
public interface PcapDialect extends CompilerDialect<PcapTokenType, PcapASTNode> {

	/**
	 * Returns the name of the dialect.
	 *
	 * @return the dialect name "Pcap"
	 */
	@Override
	default String getName() {
		return "Pcap";
	}

	// Add any Pcap-specific methods if needed
}
