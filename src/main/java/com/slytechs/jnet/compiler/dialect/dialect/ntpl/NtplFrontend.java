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
package com.slytechs.jnet.compiler.dialect.dialect.ntpl;

import com.slytechs.jnet.compiler.CompilerDialect;
import com.slytechs.jnet.compiler.CompilerException;
import com.slytechs.jnet.compiler.CompilerFrontend;
import com.slytechs.jnet.compiler.frontend.Lexer;
import com.slytechs.jnet.compiler.frontend.Parser;

/**
 * @author Mark Bednarczyk
 *
 */
public class NtplFrontend implements CompilerFrontend {
	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "NtplFrontend ["
				+ "name=" + getName()
				+ "]";
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#getName()
	 */
	@Override
	public String getName() {
		return "Ntpl";
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#createLexer(java.lang.String)
	 */
	@Override
	public Lexer createLexer(String source) throws CompilerException {
		return new NtplLexer(source);
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#createParser(com.slytechs.jnet.compiler.frontend.Lexer)
	 */
	@Override
	public Parser createParser(Lexer lexer) throws CompilerException {
		return new NtplParser(lexer);
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#compilerDialect()
	 */
	@Override
	public CompilerDialect compilerDialect() {
		return CompilerDialect.NTPL;
	}

	/**
	 * @see com.slytechs.jnet.compiler.CompilerFrontend#compilerDialectId()
	 */
	@Override
	public int compilerDialectId() {
		return CompilerDialect.NTPL_DIALECT_ID;
	}
}