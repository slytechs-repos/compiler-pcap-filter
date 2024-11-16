package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.pcap;

import com.slytechs.jnet.compiler.frontend.ASTNode;

/**
 * Represents a port node in the Pcap AST.
 */
public class PortNode extends ASTNode {

	private final String port;

	public PortNode(String port) {
		this.port = port;
	}

	public String getPort() {
		return port;
	}
}
