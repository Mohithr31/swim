import pytest
from src.lexer import Lexer, TokenType, LexerError


def test_lexer_valid_tokens():
    source = """
    # Sample comment
    module test_mod {
        collect system
        collect processes
    }
    """
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    
    types = [t.type for t in tokens]
    assert types == [
        TokenType.MODULE,
        TokenType.IDENTIFIER,
        TokenType.LBRACE,
        TokenType.COLLECT,
        TokenType.IDENTIFIER,
        TokenType.COLLECT,
        TokenType.IDENTIFIER,
        TokenType.RBRACE,
        TokenType.EOF
    ]
    assert tokens[1].value == "test_mod"
    assert tokens[4].value == "system"
    assert tokens[6].value == "processes"


def test_lexer_invalid_character():
    source = "module test { collect system $ }"
    lexer = Lexer(source)
    with pytest.raises(LexerError):
        lexer.tokenize()
