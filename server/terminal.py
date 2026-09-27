"""
JOCKY Terminal Engine — server/terminal.py

Provides the JockyTerminalEngine: a server-side component that
accepts JOCKY DSL source, compiles it, and returns the resulting
plan and optional C/LLVM output.  Also maintains a per-session
execution history for the dashboard's DSL editor terminal widget.
"""

import os
import sys
import json
import hashlib
import datetime
from typing import Dict, Any, List, Optional

# Ensure project root is on sys.path
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _root not in sys.path:
    sys.path.insert(0, _root)

from src.parser import parse_jocky_source, ParserError, ALLOWLISTED_OPERATIONS
from src.plan import compile_plan_from_ast, validate_forensic_plan, PlanCompilerError
from src.codegen import generate_c_code, CodeGeneratorError
from src.lexer import LexerError


class TerminalError(Exception):
    """Raised when the terminal engine encounters an unrecoverable error."""
    pass


class TerminalSession:
    """Tracks the history of DSL compilations for one dashboard session."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.history: List[Dict[str, Any]] = []
        self.created_at = datetime.datetime.utcnow().isoformat()

    def record(self, entry: Dict[str, Any]) -> None:
        self.history.append({
            **entry,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "history": self.history,
        }


class JockyTerminalEngine:
    """
    Central compile-and-execute engine for the JOCKY DSL terminal.

    Responsibilities:
        - Compile DSL source → Module AST → plan dict
        - Optionally emit C source
        - Validate plan integrity
        - Manage per-dashboard-session history
        - Provide introspection (allowlist, syntax hints)
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, TerminalSession] = {}

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def get_or_create_session(self, session_id: str) -> TerminalSession:
        if session_id not in self._sessions:
            self._sessions[session_id] = TerminalSession(session_id)
        return self._sessions[session_id]

    def get_session(self, session_id: str) -> Optional[TerminalSession]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._sessions.values()]

    # ------------------------------------------------------------------
    # Compilation
    # ------------------------------------------------------------------

    def compile(
        self,
        source: str,
        session_id: Optional[str] = None,
        emit_c: bool = False,
    ) -> Dict[str, Any]:
        """
        Compile JOCKY DSL source.

        Args:
            source:     JOCKY DSL text.
            session_id: If provided, record this compilation in the session history.
            emit_c:     Also generate C source code.

        Returns:
            {
              "status": "success" | "error",
              "plan":   <plan dict>  (on success),
              "c_code": <str>        (on success if emit_c=True),
              "error":  <str>        (on error),
            }
        """
        result: Dict[str, Any] = {}

        try:
            module = parse_jocky_source(source)
            plan = compile_plan_from_ast(module)
            result["status"] = "success"
            result["plan"] = plan
            if emit_c:
                result["c_code"] = generate_c_code(module)
        except (LexerError, ParserError) as exc:
            result["status"] = "error"
            result["error"] = f"Parse error: {exc}"
        except PlanCompilerError as exc:
            result["status"] = "error"
            result["error"] = f"Plan compiler error: {exc}"
        except CodeGeneratorError as exc:
            result["status"] = "error"
            result["error"] = f"Code generator error: {exc}"
        except Exception as exc:  # pragma: no cover
            result["status"] = "error"
            result["error"] = f"Internal compiler error: {exc}"

        if session_id:
            sess = self.get_or_create_session(session_id)
            sess.record({
                "source_preview": source[:120],
                "result_status": result["status"],
                "plan_hash": result.get("plan", {}).get("plan_hash"),
                "error": result.get("error"),
            })

        return result

    def validate_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a previously compiled plan's integrity hash."""
        valid = validate_forensic_plan(plan)
        return {"valid": valid, "plan_hash": plan.get("plan_hash")}

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_allowlist(self) -> Dict[str, Any]:
        """Return the sorted list of allowed forensic operations."""
        return {"operations": sorted(ALLOWLISTED_OPERATIONS)}

    # ------------------------------------------------------------------
    # Class-level command dispatcher (used by /api/terminal/execute)
    # ------------------------------------------------------------------

    @classmethod
    def execute_command(
        cls,
        cmd_str: str,
        case_id: str,
        agent_id: str,
    ) -> dict:
        """
        Stateless class-level command dispatcher for the dashboard terminal.

        Supported commands:
            help                      — list available commands
            device                    — current device info
            processes                 — running processes (psutil)
            recover <path>            — mock recovery record for <path>
            compile <dsl_source>      — compile a DSL snippet
            allowlist                 — show allowed forensic operations
        """
        import platform, datetime, os

        cmd_str = cmd_str.strip()
        cmd_parts = cmd_str.split(None, 1)
        cmd = cmd_parts[0].lower() if cmd_parts else ""
        arg = cmd_parts[1] if len(cmd_parts) > 1 else ""

        if cmd == "help":
            return {
                "status": "SUCCESS",
                "output": (
                    "JOCKY Forensic Terminal Engine\n"
                    "Commands:\n"
                    "  help                  — this message\n"
                    "  device                — device information\n"
                    "  processes             — running processes\n"
                    "  recover <path>        — create recovery record for path\n"
                    "  compile <dsl>         — compile DSL snippet\n"
                    "  allowlist             — show permitted forensic operations\n"
                ),
                "command": cmd_str,
                "case_id": case_id,
            }

        if cmd == "device":
            import socket, platform as pf
            return {
                "status": "SUCCESS",
                "output": {
                    "hostname": socket.gethostname(),
                    "operating_system": pf.system(),
                    "release": pf.release(),
                    "architecture": pf.architecture()[0],
                    "python_version": pf.python_version(),
                },
                "command": cmd_str,
                "case_id": case_id,
            }

        if cmd == "processes":
            procs = []
            try:
                import psutil
                for p in psutil.process_iter(["pid", "name", "status"]):
                    try:
                        procs.append({"pid": p.info["pid"], "name": p.info["name"], "status": p.info["status"]})
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except ImportError:
                procs = [{"pid": os.getpid(), "name": "jocky_server", "status": "running"}]
            return {"status": "SUCCESS", "output": procs, "command": cmd_str, "case_id": case_id}

        if cmd == "recover":
            import uuid
            evid = f"EVID-REC-{uuid.uuid4().hex[:8].upper()}"
            return {
                "status": "SUCCESS",
                "output": f"Recovery record created for: {arg or 'unspecified path'}",
                "evidence_id": evid,
                "command": cmd_str,
                "case_id": case_id,
            }

        if cmd == "compile":
            engine = cls()
            result = engine.compile(arg or "", session_id=None)
            result["command"] = cmd_str
            result["case_id"] = case_id
            return result

        if cmd == "allowlist":
            return {
                "status": "SUCCESS",
                "output": sorted(ALLOWLISTED_OPERATIONS),
                "command": cmd_str,
                "case_id": case_id,
            }

        return {
            "status": "ERROR",
            "output": f"Unknown command: {cmd!r}. Type 'help' for available commands.",
            "command": cmd_str,
            "case_id": case_id,
        }

    def syntax_hint(self) -> str:
        ops = "\n    collect ".join(sorted(ALLOWLISTED_OPERATIONS))
        return (
            "# JOCKY DSL syntax:\n"
            "module <name> {\n"
            f"    collect {ops}\n"
            "}"
        )
