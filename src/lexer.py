"""
JOCKY Language — Lexer (Authoritative)
Tokenizes JOCKY source (.jky) files using the module/collect grammar.

Grammar summary:
    module <name> {
        collect <operation>
        ...
    }

Comments: # to end of line
"""

import re
from enum import Enum, auto
from dataclasses import dataclass
from typing import List


class TokenType(Enum):
    MODULE     = auto()
    COLLECT    = auto()
    IDENTIFIER = auto()
    LBRACE     = auto()
    RBRACE     = auto()
    EOF        = auto()


@dataclass
class Token:
    type: TokenType
    value: str
    line: int


class LexerError(Exception):
    """Raised on an unrecognised character or illegal token."""
    pass


_KEYWORDS = {
    "module": TokenType.MODULE,
    "collect": TokenType.COLLECT,
}

_TOKEN_RE = re.compile(
    r"(?P<COMMENT>#[^\n]*)"
    r"|(?P<WS>[ \t\r]+)"
    r"|(?P<NEWLINE>\n)"
    r"|(?P<LBRACE>\{)"
    r"|(?P<RBRACE>\})"
    r"|(?P<IDENT>[A-Za-z_][A-Za-z0-9_]*)"
)


class Lexer:
    """Tokenises JOCKY source into a list of Token objects."""

    def __init__(self, source: str) -> None:
        self._source = source

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        line = 1
        pos = 0
        src = self._source
        length = len(src)

        while pos < length:
            m = _TOKEN_RE.match(src, pos)
            if not m:
                snippet = src[pos:pos + 20].splitlines()[0]
                raise LexerError(
                    f"Unexpected character at line {line}: {snippet!r}"
                )

            kind = m.lastgroup
            value = m.group()
            pos = m.end()

            if kind in ("COMMENT", "WS"):
                continue
            if kind == "NEWLINE":
                line += 1
                continue
            if kind == "LBRACE":
                tokens.append(Token(TokenType.LBRACE, value, line))
            elif kind == "RBRACE":
                tokens.append(Token(TokenType.RBRACE, value, line))
            elif kind == "IDENT":
                ttype = _KEYWORDS.get(value, TokenType.IDENTIFIER)
                tokens.append(Token(ttype, value, line))

        tokens.append(Token(TokenType.EOF, "", line))
        return tokens
