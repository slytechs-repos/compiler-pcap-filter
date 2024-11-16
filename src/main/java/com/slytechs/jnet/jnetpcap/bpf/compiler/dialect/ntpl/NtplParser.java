package com.slytechs.jnet.jnetruntime.bpf.compiler.dialect.ntpl;

import com.slytechs.jnet.jnetruntime.bpf.compiler.api.CompilerException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.api.ParserException;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.AbstractParser;
import com.slytechs.jnet.jnetruntime.bpf.compiler.frontend.Lexer;

/**
 * Concrete parser for the NTPL dialect.
 */
public class NtplParser extends AbstractParser<NtplTokenType, NtplASTNode> {

    public NtplParser(Lexer<NtplTokenType> lexer) throws CompilerException {
        super(lexer);
    }

    @Override
    public NtplASTNode parse() throws CompilerException {
        NtplASTNode node = parseStatement();
        if (currentToken.getType() != NtplTokenType.EOF) {
            throw new ParserException("Unexpected token after end of statement", currentToken.getPosition(), null, currentToken);
        }
        return node;
    }

    private NtplASTNode parseStatement() throws CompilerException {
        if (currentToken.getType() == NtplTokenType.KEYWORD && currentToken.getValue().equals("IF")) {
            match(NtplTokenType.KEYWORD);
            String condition = currentToken.getValue();
            match(NtplTokenType.NUMBER);
            // Parse the rest of the filter expression
            // Placeholder implementation
            return new FilterExpressionNode(condition);
        } else {
            throw new ParserException("Expected 'IF' keyword", currentToken.getPosition(), null, currentToken);
        }
    }
}
