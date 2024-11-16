package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.pcap;

/**
 * Represents a port node in the Pcap AST.
 */
public class PortNode extends PcapASTNode {

	private final String port;

	public PortNode(String port) {
		this.port = port;
	}

	public String getPort() {
		return port;
	}
}
