/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

import com.slytechs.jnet.compiler.CompilerBackend;
import com.slytechs.jnet.compiler.CompilerFrontend;
import com.slytechs.jnet.compiler.dialect.dialect.ntpl.NtplFrontend;
import com.slytechs.jnet.compiler.dialect.dialect.pcap.BpfBackend;
import com.slytechs.jnet.compiler.dialect.dialect.pcap.PcapFrontend;
import com.slytechs.jnet.compiler.dialect.dialect.wireshark.WiresharkFrontend;

@SuppressWarnings("rawtypes")
/**
 * BPF compiler module providing multiple filter dialect implementations. This
 * module implements a compiler framework for Berkeley Packet Filter (BPF)
 * programs with settingsSupport for multiple front-end dialects and back-end code
 * generation.
 * 
 * <p>
 * The module provides three distinct compiler front-ends:
 * <ul>
 * <li>Pcap - Classic libpcap filter syntax</li>
 * <li>Wireshark - Extended Wireshark display filter syntax</li>
 * <li>NTPL - Intel's Network Time Protocol Language filter syntax</li>
 * </ul>
 * </p>
 * 
 * <p>
 * For code generation, the module includes:
 * <ul>
 * <li>BPF Backend - Generates classic BPF bytecode</li>
 * </ul>
 * </p>
 * 
 * <h2>Service Providers</h2>
 * <p>
 * This module provides implementations for the following service interfaces:
 * <ul>
 * <li>{@link CompilerBackend} - Implemented by {@link BpfBackend}</li>
 * <li>{@link CompilerFrontend} - Implemented by {@link PcapFrontend},
 * {@link WiresharkFrontend}, and {@link NtplFrontend}</li>
 * </ul>
 * </p>
 * 
 * <h2>Module Dependencies</h2>
 * <p>
 * Required modules:
 * <ul>
 * <li>com.slytechs.jnet.platform.jnpl.vm - BPF virtual machine
 * implementation</li>
 * <li>com.slytechs.jnet.compiler - Core compiler framework</li>
 * <li>com.slytechs.jnet.platform - Runtime settingsSupport libraries</li>
 * </ul>
 * </p>
 * 
 * @provides CompilerBackend Provides BPF bytecode generation backend
 * @provides CompilerFrontend Provides Pcap, Wireshark and NTPL filter syntax
 *           frontends
 * 
 * @uses com.slytechs.jnet.compiler.CompilerBackend
 * @uses com.slytechs.jnet.compiler.CompilerFrontend
 * 
 * @version 1.0
 * @author Sly Technologies Inc
 */
module com.slytechs.jnet.compiler.dialect.pcap {

	exports com.slytechs.jnet.compiler.dialect.dialect.pcap;
	exports com.slytechs.jnet.compiler.dialect.dialect.wireshark;
	exports com.slytechs.jnet.compiler.dialect.dialect.ntpl;
	exports com.slytechs.jnet.compiler.dialect.ir;

	requires transitive com.slytechs.jnet.platform.api;
	requires transitive com.slytechs.jnet.platform.jnpl;
	requires transitive com.slytechs.jnet.compiler;

	/**
	 * Provides the BPF backend implementation for code generation.
	 */
	provides CompilerBackend with BpfBackend;

	/**
	 * Provides multiple front-end implementations for different filter dialects:
	 * PCap, Wireshark, and NTPL.
	 */
	provides CompilerFrontend with
			PcapFrontend,
			WiresharkFrontend,
			NtplFrontend;
}