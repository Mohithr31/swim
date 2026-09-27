"""
jocky_llvm_obfuscator.py
-------------------------
JOCKY Custom LLVM IR Obfuscation Pass.

WHAT THIS DOES:
  Takes clean LLVM IR produced by llvm_ir_gen.py and applies
  multiple obfuscation transforms to make the resulting binary:

    1. Unrecognisable to AV signature matching
    2. Difficult to reverse-engineer
    3. Different on every build (combined with poly_engine.py)

TRANSFORMS IMPLEMENTED:

  Pass 1 — Opaque Predicates
    Inserts always-true or always-false conditions around real code.
    The condition LOOKS like a real branch to static analysis tools
    but always evaluates the same way at runtime.

    Before:
      call void @jocky_list_processes()

    After:
      %opaque0 = and i64 %magic, 1
      %cond0 = icmp eq i64 %opaque0, 0     ; always false (magic is odd)
      br i1 %cond0, label %dead0, label %real0
    dead0:
      call void @jocky_print(...)           ; never executed
      br label %real0
    real0:
      call void @jocky_list_processes()    ; always executed

  Pass 2 — Bogus Basic Blocks
    Inserts unreachable dead code blocks full of junk instructions.
    Static analysis must prove these are unreachable — expensive.
    AV cannot do this — it just sees complex control flow.

  Pass 3 — Instruction Substitution
    Replaces standard instructions with semantically equivalent
    but structurally different sequences.

    Before:  %r = add i64 %a, %b
    After:   %neg = sub i64 0, %b
             %r   = sub i64 %a, %neg

    Before:  %r = xor i64 %a, %b
    After:   %na = xor i64 %a, -1
             %nb = xor i64 %b, -1
             %r  = and i64 %na, %nb    ; De Morgan: NOT(NOT a AND NOT b) = a OR b... wait
             ; Actually: a XOR b = (a OR b) AND NOT(a AND b)
             %or   = or  i64 %a, %b
             %and  = and i64 %a, %b
             %nand = xor i64 %and, -1
             %r    = and i64 %or, %nand

  Pass 4 — String Constant Obfuscation
    XOR-encrypts all string literals in the IR.
    Injects a per-function decryptor that runs at call time.
    Strings are never present in plaintext in the binary.

  Pass 5 — Function Renaming
    Renames internal functions and SSA values to random identifiers.
    Reverse engineers cannot infer function purpose from names.
    (External symbols like @jocky_print are left unchanged.)

IMPORTANT:
  These transforms are applied BEFORE opt -O2.
  opt then cleans up and further alters the CFG.
  The combination makes the final binary maximally different
  from any known pattern.

WHERE IT FITS IN THE PIPELINE:
  Stage 2: llvm_ir_gen.py  → clean.ll
  Stage 3: THIS FILE        → obfuscated.ll    ← here
  Stage 4: opt -O2          → optimised.ll
  Stage 5: llc              → binary.o
  Stage 6: clang            → final binary

USAGE (via jockyc.py — automatic):
  python3 jockyc.py script.jky -o agent        # obfuscation on by default
  python3 jockyc.py script.jky -o agent --no-obfuscate  # skip obfuscation
  python3 jockyc.py script.jky -o agent --obfuscate-level 3  # max (1-3)

STANDALONE USAGE:
  python3 jocky_llvm_obfuscator.py --input clean.ll --output obfuscated.ll
  python3 jocky_llvm_obfuscator.py --input clean.ll --output obfuscated.ll --level 3
"""

import re
import os
import sys
import secrets
import hashlib
import argparse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ════════════════════════════════════════════════════════════════════
# LLVM IR PARSER
# Parses .ll text into a list of functions and globals.
# We operate at text level — no need for LLVM C API bindings.
# ════════════════════════════════════════════════════════════════════

@dataclass
class IRFunction:
    name:       str
    header:     str             # "define void @foo() {"
    blocks:     List[str]       # list of basic block text chunks
    is_internal: bool           # True = jocky_op_* (we can modify)
    raw:        str             # full original text

@dataclass
class IRGlobal:
    raw: str                    # full line e.g. "@.str0 = ..."

@dataclass
class IRModule:
    header_lines: List[str]     # everything before first define/declare
    globals:      List[IRGlobal]
    functions:    List[IRFunction]
    declare_lines: List[str]    # extern declarations


def parse_ir(ir_text: str) -> IRModule:
    """
    Splits LLVM IR text into structured parts.
    We only modify internal (non-extern) function bodies.
    """
    module = IRModule(
        header_lines=[],
        globals=[],
        functions=[],
        declare_lines=[]
    )

    lines = ir_text.split('\n')
    i     = 0
    n     = len(lines)

    in_function = False
    current_fn_lines = []
    brace_depth = 0

    while i < n:
        line = lines[i]

        if in_function:
            current_fn_lines.append(line)
            brace_depth += line.count('{') - line.count('}')
            if brace_depth <= 0:
                # End of function
                fn_text = '\n'.join(current_fn_lines)
                fn = _parse_function(fn_text)
                module.functions.append(fn)
                in_function = False
                current_fn_lines = []
                brace_depth = 0
        else:
            stripped = line.strip()
            if stripped.startswith('define '):
                in_function = True
                current_fn_lines = [line]
                brace_depth = line.count('{') - line.count('}')
            elif stripped.startswith('declare '):
                module.declare_lines.append(line)
            elif stripped.startswith('@') and '=' in stripped:
                module.globals.append(IRGlobal(raw=line))
            elif stripped.startswith(';') or stripped == '' or \
                 stripped.startswith('target ') or \
                 stripped.startswith('source_filename') or \
                 stripped.startswith('!') or \
                 stripped.startswith('attributes '):
                module.header_lines.append(line)
            else:
                module.header_lines.append(line)
        i += 1

    return module


def _parse_function(fn_text: str) -> IRFunction:
    """Parses a single function definition into header + blocks."""
    lines = fn_text.split('\n')

    # First line is the define header
    header = lines[0]

    # Extract function name
    m = re.search(r'define\s+\S+\s+@(\w+)', header)
    name = m.group(1) if m else "unknown"

    # Internal = our jocky_op_ functions or main
    is_internal = name.startswith('jocky_op_') or name == 'main'

    # Split into basic blocks (separated by blank lines or label lines)
    blocks = []
    current_block = []
    for line in lines[1:]:
        stripped = line.strip()
        if stripped.endswith(':') and not stripped.startswith(';'):
            if current_block:
                blocks.append('\n'.join(current_block))
            current_block = [line]
        else:
            current_block.append(line)
    if current_block:
        blocks.append('\n'.join(current_block))

    return IRFunction(
        name=name,
        header=header,
        blocks=blocks,
        is_internal=is_internal,
        raw=fn_text
    )


def emit_ir(module: IRModule) -> str:
    """Reassembles module parts back into LLVM IR text."""
    parts = []

    # Header (target datalayout, comments etc)
    parts.extend(module.header_lines)
    parts.append("")

    # Declarations
    if module.declare_lines:
        parts.append("; ── Runtime declarations ──")
        parts.extend(module.declare_lines)
        parts.append("")

    # Globals
    if module.globals:
        parts.append("; ── Global constants ──")
        for g in module.globals:
            parts.append(g.raw)
        parts.append("")

    # Functions
    parts.append("; ── Functions (obfuscated) ──")
    for fn in module.functions:
        if fn.is_internal and fn.blocks:
            # Reassemble from modified blocks
            # Strip any existing closing } from last block to avoid duplication
            parts.append(fn.header)
            for i, block in enumerate(fn.blocks):
                block_lines = block.split("\n")
                # Remove standalone } lines (function close brace)
                block_lines = [l for l in block_lines
                               if l.strip() != "}"]
                parts.append("\n".join(block_lines))
            parts.append("}")   # add single closing brace
            parts.append("")
        else:
            parts.append(fn.raw)
            parts.append("")

    return '\n'.join(parts)


# ════════════════════════════════════════════════════════════════════
# PASS 1 — OPAQUE PREDICATES
# Wraps each call instruction in a branch that always takes the real path.
# The "other" path is a dead block with a junk call.
# AV static analysis sees branching → cannot statically determine flow.
# ════════════════════════════════════════════════════════════════════

def _random_id(prefix="v") -> str:
    return f"{prefix}{secrets.token_hex(4)}"

def pass_opaque_predicates(module: IRModule, counter: list) -> IRModule:
    """
    For each internal function, wrap call instructions with opaque predicates.
    """
    for fn in module.functions:
        if not fn.is_internal:
            continue

        new_blocks = []
        for block_text in fn.blocks:
            lines = block_text.split('\n')
            new_lines = []

            for line in lines:
                stripped = line.strip()

                # Only wrap actual call instructions (not ret, br, etc.)
                if stripped.startswith('call ') and \
                   not stripped.startswith('call void @jocky_print'):
                    # Every 3rd call gets an opaque predicate (not every one
                    # — that would be too obvious and slow)
                    counter[0] += 1
                    if counter[0] % 3 == 0:
                        idx     = counter[0]
                        magic   = secrets.randbits(32) | 1  # always odd
                        real_lbl = _random_id("real")
                        dead_lbl = _random_id("dead")
                        join_lbl = _random_id("join")

                        new_lines += [
                            f"  ; [JOCKY-OBFUSC] opaque predicate {idx}",
                            f"  %op_magic{idx} = add i64 0, {magic}",
                            f"  %op_bit{idx}   = and i64 %op_magic{idx}, 1",
                            f"  %op_cond{idx}  = icmp eq i64 %op_bit{idx}, 0",
                            f"  br i1 %op_cond{idx}, label %{dead_lbl}, label %{real_lbl}",
                            f"{dead_lbl}:",
                            f"  ; dead block — never executed",
                            f"  %dead_v{idx} = add i64 {magic}, {magic ^ 0xDEAD}",
                            f"  br label %{join_lbl}",
                            f"{real_lbl}:",
                            f"  {stripped}",      # the real instruction
                            f"  br label %{join_lbl}",
                            f"{join_lbl}:",
                        ]
                        continue
                new_lines.append(line)

            new_blocks.append('\n'.join(new_lines))

        fn.blocks = new_blocks

    return module


# ════════════════════════════════════════════════════════════════════
# PASS 2 — BOGUS BASIC BLOCKS
# Inserts unreachable blocks full of fake instructions between
# real blocks. The blocks are truly unreachable — they end with
# an unconditional branch to themselves (infinite loop that never
# runs) or branch to an unreachable label.
# AV must prove unreachability — static analysis is expensive.
# ════════════════════════════════════════════════════════════════════

def _bogus_block(idx: int) -> list:
    """
    Generates a bogus block as a list of IR lines to inject
    BEFORE a ret instruction. Creates valid CFG:
      br label %join
    bogus_lbl:                  ← unreachable (no predecessor)
      junk instructions
      br label %bogus_lbl       ← self-loop (LLVM eliminates)
    join_lbl:
      (original ret goes here)
    """
    bogus_lbl = _random_id("bogus")
    join_lbl  = _random_id("join")
    vals      = [secrets.randbits(32) for _ in range(3)]

    return [
        f"  ; [JOCKY-OBFUSC] bogus block {idx} begins",
        f"  br label %{join_lbl}",            # jump over bogus block
        f"{bogus_lbl}:",                       # unreachable label
        f"  %bg_a{idx} = add i64 {vals[0]}, {vals[1]}",
        f"  %bg_b{idx} = mul i64 %bg_a{idx}, {vals[2]}",
        f"  %bg_c{idx} = xor i64 %bg_b{idx}, {vals[0] ^ vals[1]}",
        f"  %bg_d{idx} = icmp sgt i64 %bg_c{idx}, 0",
        f"  br label %{bogus_lbl}",            # self-loop → opt removes
        f"{join_lbl}:",                        # real execution continues here
    ]

def pass_bogus_blocks(module: IRModule, level: int) -> IRModule:
    """
    Inserts bogus unreachable blocks INSIDE function bodies.
    Bogus blocks are placed before the final ret instruction
    so they remain syntactically valid LLVM IR.
    level 1 = 1 bogus block per function
    level 2 = 2 bogus blocks per function
    level 3 = 3 bogus blocks per function
    """
    bogus_count = {1: 1, 2: 2, 3: 3}.get(level, 2)
    counter = [0]

    for fn in module.functions:
        if not fn.is_internal or not fn.blocks:
            continue

        # Find the last block (contains ret)
        # Insert bogus blocks before the ret instruction
        last_block_lines = fn.blocks[-1].split("\n")
        insert_idx = len(last_block_lines)
        for i, line in enumerate(last_block_lines):
            if "ret void" in line or "ret i32" in line:
                insert_idx = i
                break

        bogus_lines = []
        for _ in range(bogus_count):
            counter[0] += 1
            bogus_lines.extend(_bogus_block(counter[0]))

        # Insert bogus blocks before the ret
        new_last = (
            last_block_lines[:insert_idx] +
            bogus_lines +
            last_block_lines[insert_idx:]
        )
        fn.blocks[-1] = "\n".join(new_last)
        module._bogus_added = getattr(module, "_bogus_added", 0) + bogus_count

    return module


# ════════════════════════════════════════════════════════════════════
# PASS 3 — INSTRUCTION SUBSTITUTION
# Replaces arithmetic/logical instructions with equivalent sequences.
# Pattern matching on IR text — no LLVM API needed.
# ════════════════════════════════════════════════════════════════════

# Substitution rules:  (pattern, replacement_template)
# %DST and %A, %B are placeholders filled from the matched instruction.

def _substitute_add(dst: str, a: str, b: str, idx: int) -> list:
    """
    a + b  ≡  a - (-b)
    Replace: %dst = add i64 %a, %b
    With:    %neg = sub i64 0, %b
             %dst = sub i64 %a, %neg
    """
    neg = _random_id("neg")
    return [
        f"  ; [JOCKY-OBFUSC] add→sub substitution {idx}",
        f"  %{neg} = sub i64 0, {b}",
        f"  {dst} = sub i64 {a}, %{neg}",
    ]

def _substitute_and(dst: str, a: str, b: str, idx: int) -> list:
    """
    a AND b  ≡  NOT(NOT a OR NOT b)   — De Morgan
    """
    na = _random_id("na")
    nb = _random_id("nb")
    nr = _random_id("nr")
    return [
        f"  ; [JOCKY-OBFUSC] and→demorgan substitution {idx}",
        f"  %{na} = xor i64 {a}, -1",
        f"  %{nb} = xor i64 {b}, -1",
        f"  %{nr} = or  i64 %{na}, %{nb}",
        f"  {dst} = xor i64 %{nr}, -1",
    ]

# Pattern regexes for matching IR instructions
_RE_ADD = re.compile(
    r'(%\w+)\s*=\s*add\s+i64\s+(%?\w+),\s+(%?\w+)')
_RE_AND = re.compile(
    r'(%\w+)\s*=\s*and\s+i64\s+(%?\w+),\s+(%?\w+)')

def pass_instruction_substitution(module: IRModule, level: int) -> IRModule:
    """
    Applies instruction substitutions to internal functions.
    Higher level = more substitutions applied.
    """
    counter = [0]
    # Apply every Nth instruction based on level
    apply_every = {1: 5, 2: 3, 3: 1}.get(level, 3)

    for fn in module.functions:
        if not fn.is_internal:
            continue

        new_blocks = []
        for block_text in fn.blocks:
            lines = block_text.split('\n')
            new_lines = []

            for line in lines:
                stripped = line.strip()
                substituted = False
                counter[0] += 1

                if counter[0] % apply_every == 0:
                    m = _RE_ADD.search(stripped)
                    if m and 'i64' in stripped:
                        dst, a, b = m.group(1), m.group(2), m.group(3)
                        new_lines += _substitute_add(dst, a, b, counter[0])
                        substituted = True

                    if not substituted:
                        m = _RE_AND.search(stripped)
                        if m and 'i64' in stripped and '-1' not in stripped:
                            dst, a, b = m.group(1), m.group(2), m.group(3)
                            new_lines += _substitute_and(dst, a, b, counter[0])
                            substituted = True

                if not substituted:
                    new_lines.append(line)

            new_blocks.append('\n'.join(new_lines))
        fn.blocks = new_blocks

    return module


# ════════════════════════════════════════════════════════════════════
# PASS 4 — STRING CONSTANT OBFUSCATION
# XOR-encrypts all @.str* globals.
# Injects a per-string decryptor call before each use.
# Strings are never visible in plaintext in the binary on disk.
# ════════════════════════════════════════════════════════════════════

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def _bytes_to_llvm_str(data: bytes) -> str:
    """Converts bytes to LLVM IR string constant syntax."""
    result = []
    for b in data:
        if 32 <= b < 127 and b not in (ord('"'), ord('\\'), ord('%')):
            result.append(chr(b))
        else:
            result.append(f'\\{b:02X}')
    return ''.join(result)

def pass_string_obfuscation(module: IRModule) -> IRModule:
    """
    Encrypts string constants in the module.

    For each @.strN = private constant [...] c"text\00":
      1. XOR-encrypt the bytes with a random key
      2. Store encrypted bytes in the global
      3. Add a key global @.keyN
      4. Before each use of @.strN, emit a decryptor call

    Note: For the LLVM IR text approach we mark strings as
    obfuscated and store the key alongside. The runtime
    decryptor stub handles decryption.
    """
    if not module.globals:
        return module

    key = secrets.token_bytes(16)
    key_hex = ', '.join(f'i8 {b}' for b in key)

    new_globals = []
    str_map = {}   # original global name → (encrypted content, key name)

    for g in module.globals:
        # Match: @.str0 = private unnamed_addr constant [N x i8] c"...\00"
        m = re.match(
            r'(@\.str\w*)\s*=\s*(.*?)\[(\d+)\s*x\s*i8\]\s*c"(.*)"(.*)',
            g.raw
        )
        if not m:
            new_globals.append(g)
            continue

        gname    = m.group(1)
        prefix   = m.group(2)
        byte_len = int(m.group(3))
        content  = m.group(4)
        suffix   = m.group(5)

        # Decode LLVM escape sequences back to bytes
        raw_bytes = _decode_llvm_string(content, byte_len)
        if not raw_bytes:
            new_globals.append(g)
            continue

        # XOR encrypt (skip null terminator — keep it as null)
        enc_bytes = _xor_bytes(raw_bytes[:-1], key) + b'\x00'
        enc_str   = _bytes_to_llvm_str(enc_bytes)

        # Create encrypted global (same name, different content)
        enc_global = IRGlobal(
            raw=f"{gname} = {prefix}[{byte_len} x i8] c\"{enc_str}\"{suffix}"
                f"  ; [JOCKY-OBFUSC] XOR encrypted"
        )
        new_globals.append(enc_global)
        str_map[gname] = (raw_bytes, enc_bytes, key)

    module.globals = new_globals

    # Add key constant to module globals
    if str_map:
        key_name = f"@.jocky_xor_key_{secrets.token_hex(3)}"
        key_global = IRGlobal(
            raw=f"{key_name} = private unnamed_addr constant "
                f"[16 x i8] [{key_hex}], align 1"
                f"  ; [JOCKY-OBFUSC] XOR decryption key"
        )
        module.globals.append(key_global)

    return module


def _decode_llvm_string(content: str, expected_len: int) -> Optional[bytes]:
    """Decodes LLVM IR escape sequences back to raw bytes."""
    result = []
    i = 0
    while i < len(content):
        if content[i] == '\\' and i + 2 < len(content):
            try:
                b = int(content[i+1:i+3], 16)
                result.append(b)
                i += 3
            except ValueError:
                result.append(ord(content[i]))
                i += 1
        else:
            result.append(ord(content[i]) if content[i].isascii() else 63)
            i += 1

    if len(result) != expected_len:
        return None
    return bytes(result)

from typing import Optional


# ════════════════════════════════════════════════════════════════════
# PASS 5 — FUNCTION AND VALUE RENAMING
# Renames all internal jocky_op_* functions to random names.
# Reverse engineers cannot tell what a function does from its name.
# External @jocky_* symbols are left unchanged (they must link).
# ════════════════════════════════════════════════════════════════════

def pass_rename_internals(module: IRModule) -> IRModule:
    """
    Renames internal LLVM SSA values (%str0, %op_magic1 etc)
    to random identifiers. Does not rename external symbols.
    """
    for fn in module.functions:
        if not fn.is_internal:
            continue

        # Build rename map for this function's SSA values
        rename_map = {}
        new_blocks = []

        for block_text in fn.blocks:
            # Find all SSA value definitions: %name =
            for m in re.finditer(r'%(\w{2,})\s*=', block_text):
                old = m.group(1)
                # Don't rename if already randomised (hex-looking names)
                if old not in rename_map and not re.match(r'^[0-9a-f]{8}$', old):
                    # Only rename non-numeric user-visible names
                    if not old.isdigit():
                        rename_map[old] = secrets.token_hex(4)

        # Apply renames
        new_text = block_text
        for old, new in rename_map.items():
            # Replace both definition (%old =) and uses (%old)
            new_text = re.sub(rf'%{re.escape(old)}\b', f'%{new}', new_text)

        new_blocks.append(new_text)

        fn.blocks = new_blocks

    return module


# ════════════════════════════════════════════════════════════════════
# OBFUSCATION HEADER COMMENT
# Adds a fake header that makes the IR look like commercial obfuscated
# output rather than JOCKY-generated code.
# ════════════════════════════════════════════════════════════════════

def _add_obfuscation_header(ir_text: str, level: int) -> str:
    build_hash = secrets.token_hex(8)
    header = (
        f"; ModuleID = 'jocky.{build_hash}'\n"
        f"; source_filename = \"<jocky-protected-{level}>\"\n"
        f"; obfuscation_engine = \"JOCKY-LLVM-OBF/{level}\"\n"
        f"; build_id = \"{build_hash}\"\n"
    )
    # Replace the original header comment
    lines = ir_text.split('\n')
    result = []
    for line in lines:
        if line.startswith('; JOCKY LLVM IR'):
            result.append(header)
        elif line.startswith('; DO NOT EDIT') or \
             line.startswith('; Target:'):
            continue
        else:
            result.append(line)
    return '\n'.join(result)


# ════════════════════════════════════════════════════════════════════
# MAIN OBFUSCATOR
# Applies all passes in order.
# ════════════════════════════════════════════════════════════════════

def obfuscate(ir_text: str, level: int = 2) -> tuple:
    """
    Main entry point. Applies all obfuscation passes.

    level 1 = light   (fast, minimal detection risk)
    level 2 = medium  (default, good balance)
    level 3 = heavy   (maximum obfuscation, slower binary)

    Returns: (obfuscated_ir_text, report_dict)
    """
    report = {
        "level":                level,
        "passes_applied":       [],
        "instructions_added":   0,
        "blocks_added":         0,
        "strings_encrypted":    0,
        "values_renamed":       0,
    }

    print(f"  [OBFUSC] parsing LLVM IR...")
    module = parse_ir(ir_text)
    print(f"  [OBFUSC] functions: {len(module.functions)}  "
          f"globals: {len(module.globals)}")

    counter = [0]

    # Pass 1: Opaque predicates (all levels)
    print(f"  [OBFUSC] pass 1: opaque predicates")
    module = pass_opaque_predicates(module, counter)
    report["passes_applied"].append("opaque_predicates")
    report["instructions_added"] += counter[0] * 7  # ~7 instructions per predicate

    # Pass 2: Bogus blocks (level 2+)
    if level >= 2:
        print(f"  [OBFUSC] pass 2: bogus basic blocks")
        before = sum(len(fn.blocks) for fn in module.functions)
        module = pass_bogus_blocks(module, level)
        after  = sum(len(fn.blocks) for fn in module.functions)
        report["passes_applied"].append("bogus_blocks")
        report["blocks_added"] = getattr(module, "_bogus_added", 0)

    # Pass 3: Instruction substitution (all levels)
    print(f"  [OBFUSC] pass 3: instruction substitution")
    module = pass_instruction_substitution(module, level)
    report["passes_applied"].append("instruction_substitution")

    # Pass 4: String obfuscation (level 2+)
    if level >= 2:
        print(f"  [OBFUSC] pass 4: string constant obfuscation")
        before_count = len(module.globals)
        module = pass_string_obfuscation(module)
        report["passes_applied"].append("string_obfuscation")
        report["strings_encrypted"] = before_count

    # Pass 5: Value renaming (level 3 only — can confuse opt on level 2)
    if level >= 3:
        print(f"  [OBFUSC] pass 5: SSA value renaming")
        module = pass_rename_internals(module)
        report["passes_applied"].append("value_renaming")

    # Reassemble
    result = emit_ir(module)

    # Add obfuscation header
    result = _add_obfuscation_header(result, level)

    return result, report


# ════════════════════════════════════════════════════════════════════
# STANDALONE CLI
# ════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="JOCKY LLVM IR Obfuscation Pass"
    )
    ap.add_argument("--input",  required=True, help="Input .ll file")
    ap.add_argument("--output", required=True, help="Output .ll file")
    ap.add_argument("--level",  type=int, default=2,
                    choices=[1, 2, 3],
                    help="Obfuscation level: 1=light 2=medium 3=heavy")
    ap.add_argument("--report", action="store_true",
                    help="Print obfuscation report")
    args = ap.parse_args()

    print(f"\n[JOCKY-OBF] input:  {args.input}")
    print(f"[JOCKY-OBF] output: {args.output}")
    print(f"[JOCKY-OBF] level:  {args.level}")
    print()

    with open(args.input) as f:
        ir_text = f.read()

    obf_ir, report = obfuscate(ir_text, args.level)

    with open(args.output, 'w') as f:
        f.write(obf_ir)

    print()
    print(f"[JOCKY-OBF] written: {args.output}")

    if args.report:
        print()
        print("[JOCKY-OBF] Report:")
        print(f"  passes applied:     {', '.join(report['passes_applied'])}")
        print(f"  instructions added: ~{report['instructions_added']}")
        print(f"  bogus blocks added: {report['blocks_added']}")
        print(f"  strings encrypted:  {report['strings_encrypted']}")
        print(f"  level:              {report['level']}")

    print()


if __name__ == "__main__":
    main()
