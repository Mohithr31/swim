"""
JOCKY Language — Parser (Authoritative)

Parses the module/collect grammar and returns a Module AST.
Enforces a strict allowlist of forensic operations at parse time.

Public API:
    parse_jocky_source(source: str) -> Module
    ParserError
    ALLOWLISTED_OPERATIONS  (frozenset)
"""

from src.lexer import Lexer, Token, TokenType, LexerError
from src.ast_nodes import Module, CollectionOperation
from typing import List

# ---------------------------------------------------------------------------
# Allowlisted forensic operations — extend here as capabilities grow.
# Any 'collect <op>' where <op> is not in this set raises ParserError.
# ---------------------------------------------------------------------------
ALLOWLISTED_OPERATIONS: frozenset = frozenset({
    "system",
    "processes",
    "network",
    "users",
    "logs",
    "filesystem",
    "services",
    "software",
    "scheduled_tasks",
    "environment",
    "mounts",
    "disk_usage",
    "network_config",
    "drivers",
    "browser",
    "email",
    "memory",
    "registry",
    "live_events",
    "security_telemetry",
    "location",
    "recovery",
    "offline",
    "removable_media",
})


class ParserError(Exception):
    """Raised on a syntax or semantic error in JOCKY source."""
    pass


class _Parser:
    def __init__(self, tokens: List[Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, ttype: TokenType) -> Token:
        tok = self._peek()
        if tok.type != ttype:
            raise ParserError(
                f"Line {tok.line}: expected {ttype.name}, got "
                f"{tok.type.name} ({tok.value!r})"
            )
        return self._advance()

    # ------------------------------------------------------------------
    # Grammar rules
    # ------------------------------------------------------------------

    def parse(self) -> Module:
        self._expect(TokenType.MODULE)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.LBRACE)

        operations: List[CollectionOperation] = []
        while self._peek().type != TokenType.RBRACE:
            if self._peek().type == TokenType.EOF:
                raise ParserError(
                    f"Line {self._peek().line}: unexpected EOF — missing closing '}}'"
                )
            operations.append(self._parse_collect())

        self._expect(TokenType.RBRACE)
        self._expect(TokenType.EOF)

        return Module(name=name_tok.value, operations=operations)

    def _parse_collect(self) -> CollectionOperation:
        collect_tok = self._peek()
        if collect_tok.type != TokenType.COLLECT:
            raise ParserError(
                f"Line {collect_tok.line}: expected 'collect', got "
                f"{collect_tok.type.name} ({collect_tok.value!r})"
            )
        self._advance()  # consume 'collect'

        op_tok = self._peek()
        if op_tok.type not in (TokenType.IDENTIFIER, TokenType.MODULE, TokenType.COLLECT):
            raise ParserError(
                f"Line {op_tok.line}: expected operation name after 'collect', "
                f"got {op_tok.type.name} ({op_tok.value!r})"
            )
        self._advance()  # consume operation name

        op_name = op_tok.value
        if op_name not in ALLOWLISTED_OPERATIONS:
            raise ParserError(
                f"Line {op_tok.line}: Forbidden or unrecognized forensic "
                f"operation '{op_name}'. Allowed: {sorted(ALLOWLISTED_OPERATIONS)}"
            )

        return CollectionOperation(op_type=op_name, line=op_tok.line)


def parse_jocky_source(source: str) -> Module:
    """
    Lex and parse a JOCKY source string.

    Args:
        source: JOCKY DSL text.

    Returns:
        A Module AST node.

    Raises:
        LexerError: on unrecognised characters.
        ParserError: on syntax or semantic errors.
    """
    try:
        lexer = Lexer(source)
        tokens = lexer.tokenize()
    except LexerError as exc:
        raise ParserError(f"Lexer error: {exc}") from exc

    return _Parser(tokens).parse()
