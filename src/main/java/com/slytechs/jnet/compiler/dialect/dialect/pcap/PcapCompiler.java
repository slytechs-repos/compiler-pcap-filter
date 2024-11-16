package com.slytechs.jnet.compiler.dialect.dialect.pcap;

import com.slytechs.jnet.compiler.core.AbstractCompiler;
import com.slytechs.jnet.compiler.core.CompilerOptions;
import com.slytechs.jnet.compiler.dialect.ir.BpfIR;
import com.slytechs.jnet.jnetruntime.jnpl.vm.core.BpfProgram;

public class PcapCompiler extends AbstractCompiler<BpfIR, BpfProgram> {

	public PcapCompiler() {
		super(new PcapFrontend(), new BpfBackend());
	}

	public PcapCompiler(CompilerOptions options) {
		super(new PcapFrontend(), new BpfBackend(), options);
	}
}
