package com.slytechs.jnet.compiler.dialect.dialect.pcap;

import java.util.Objects;

import com.slytechs.jnet.compiler.frontend.ASTNode;

/**
 * Represents a protocol node in the Pcap AST.
 */
public class ProtocolNode extends ASTNode {

    /**
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return Objects.hash(protocol);
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ProtocolNode other = (ProtocolNode) obj;
		return Objects.equals(protocol, other.protocol);
	}

	private final String protocol;

    public ProtocolNode(String protocol) {
        this.protocol = protocol;
    }

    public String getProtocol() {
        return protocol;
    }

    // Implement visitor pattern methods if needed
}
