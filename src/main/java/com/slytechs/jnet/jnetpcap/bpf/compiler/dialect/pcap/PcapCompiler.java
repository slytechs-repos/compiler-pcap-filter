package com.slytechs.jnet.jnetpcap.bpf.compiler.dialect.pcap;

import com.slytechs.jnet.compiler.core.AbstractCompiler;
import com.slytechs.jnet.compiler.core.CompilerOptions;
import com.slytechs.jnet.jnetpcap.bpf.compiler.ir.BpfIR;
import com.slytechs.jnet.jnetpcap.bpf.vm.core.BpfProgram;

public class PcapCompiler extends AbstractCompiler<BpfIR, BpfProgram> {

	public PcapCompiler() {
		super(new PcapFrontend(), new BpfBackend());
	}

	public PcapCompiler(CompilerOptions options) {
		super(new PcapFrontend(), new BpfBackend(), options);
	}
}
