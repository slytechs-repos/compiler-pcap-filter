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
package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.ntpl;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Parser;

/**
 * @author Mark Bednarczyk
 *
 */
public class NtplDialectImpl implements NtplDialect {

	/**
	 * @see com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect#getName()
	 */
	@Override
	public String getName() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect#createLexer(java.lang.String)
	 */
	@Override
	public Lexer<NtplTokenType> createLexer(String source) throws CompilerException {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerDialect#createParser(com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer)
	 */
	@Override
	public Parser<NtplTokenType, NtplASTNode> createParser(Lexer<NtplTokenType> lexer) throws CompilerException {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
