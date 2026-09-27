"""
JOCKY Language — AST Node Definitions (Authoritative)

The module/collect grammar produces:
    Module
        .name        str
        .operations  List[CollectionOperation]

    CollectionOperation
        .op_type     str   (e.g. "system", "processes", "network")
        .line        int
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class CollectionOperation:
    op_type: str
    line: int


@dataclass
class Module:
    name: str
    operations: List[CollectionOperation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "operations": [{"op_type": op.op_type, "line": op.line} for op in self.operations],
        }


# ---------------------------------------------------------------------------
# Legacy op/call grammar nodes kept for backward-compat with codegen/plan
# ---------------------------------------------------------------------------

@dataclass
class PrintStmt:
    text: str
    line: int


@dataclass
class CallStmt:
    name: str
    args: list
    line: int


@dataclass
class OpDecl:
    name: str
    body: list
    line: int


@dataclass
class Program:
    ops: List[OpDecl] = field(default_factory=list)
