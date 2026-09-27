"""
JOCKY Language — Plan Compiler (Authoritative)

Compiles a Module AST into a signed JSON collection plan.
The plan carries a SHA-256 hash of its operations so any
tampering (adding/removing/reordering) is detectable at runtime.

Public API:
    compile_plan_from_ast(module: Module) -> dict
    validate_forensic_plan(plan: dict) -> bool
    PlanCompilerError
"""

import json
import hashlib
from src.ast_nodes import Module, CollectionOperation
from src.parser import ALLOWLISTED_OPERATIONS
from typing import Dict, Any


class PlanCompilerError(Exception):
    """Raised when a plan cannot be compiled from the given AST."""
    pass


def _hash_operations(operations: list) -> str:
    """Return SHA-256 of the canonical JSON of the operations list."""
    canonical = json.dumps(operations, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def compile_plan_from_ast(module: Module) -> Dict[str, Any]:
    """
    Compile a Module AST into a forensic collection plan dict.

    Plan schema:
        {
          "version": 1,
          "module": "<name>",
          "operations": [{"type": "<op>"}, ...],
          "plan_hash": "<sha256>"
        }

    Raises:
        PlanCompilerError: if any operation is forbidden.
    """
    ops_out = []
    for op in module.operations:
        if op.op_type not in ALLOWLISTED_OPERATIONS:
            raise PlanCompilerError(
                f"Forbidden operation '{op.op_type}' at line {op.line}. "
                f"Allowed: {sorted(ALLOWLISTED_OPERATIONS)}"
            )
        ops_out.append({"type": op.op_type})

    plan_hash = _hash_operations(ops_out)

    return {
        "version": 1,
        "module": module.name,
        "operations": ops_out,
        "plan_hash": plan_hash,
    }


def validate_forensic_plan(plan: Dict[str, Any]) -> bool:
    """
    Re-derive the plan hash and compare to the stored value.

    Returns True if the plan is unmodified, False if tampered.
    """
    try:
        ops = plan.get("operations", [])
        expected_hash = _hash_operations(ops)
        return plan.get("plan_hash") == expected_hash
    except Exception:
        return False
