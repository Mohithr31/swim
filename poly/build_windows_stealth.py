#!/usr/bin/env python3
"""
build_windows_stealth.py
-------------------------
Builds the JOCKY Windows stealth runtime.

Supports two modes:
  1. Native Windows  — uses MinGW or MSVC detected automatically
  2. Cross-compile   — uses x86_64-w64-mingw32-gcc from Linux

Usage:
  python3 build_windows_stealth.py               # auto-detect
  python3 build_windows_stealth.py --cross       # force cross-compile
  python3 build_windows_stealth.py --check       # just check tools
"""

import os
import sys
import shutil
import subprocess
import argparse
import platform

# ── Colour output ─────────────────────────────────────────────────
def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

def log(tag, msg): print(f"  [{cyan(tag)}] {msg}")
def ok(msg):       print(f"  [{green('OK')}] {msg}")
def fail(msg):     print(f"  [{red('FAIL')}] {msg}"); sys.exit(1)
def warn(msg):     print(f"  [{yellow('WARN')}] {msg}")


# ── Source files ──────────────────────────────────────────────────
SOURCES = [
    "test_stealth_windows.c",
    "jocky_runtime_windows_stealth.c",
]
OUTPUT  = "test_stealth_windows.exe"
DEFINES = ["-DJOCKY_STEALTH", "-D_WIN32", "-DWIN32"]
FLAGS   = ["-O2", "-Wall", "-Wno-unused-function"]
LINKS   = ["-lntdll", "-liphlpapi", "-lws2_32"]


# ── Compiler detection ────────────────────────────────────────────

def find_compiler(force_cross: bool) -> tuple:
    """
    Returns (compiler_path, mode)
    mode: "native_mingw" | "cross_mingw" | "msvc" | None
    """
    if platform.system() == "Windows" and not force_cross:
        # Try MinGW on Windows
        for name in ["gcc", "x86_64-w64-mingw32-gcc"]:
            path = shutil.which(name)
            if path:
                log("DETECT", f"Found MinGW on Windows: {path}")
                return path, "native_mingw"

        # Try MSVC (cl.exe)
        cl = shutil.which("cl")
        if cl:
            log("DETECT", f"Found MSVC: {cl}")
            return cl, "msvc"

        return None, None

    else:
        # Linux / Mac — cross-compile
        for name in ["x86_64-w64-mingw32-gcc",
                     "x86_64-w64-mingw32-gcc-posix"]:
            path = shutil.which(name)
            if path:
                log("DETECT", f"Found cross-compiler: {path}")
                return path, "cross_mingw"

        return None, None


def check_mingw_cross_available():
    """Check if MinGW cross-compiler is installable"""
    if platform.system() == "Linux":
        result = subprocess.run(
            ["dpkg", "-l", "mingw-w64"],
            capture_output=True, text=True
        )
        if "ii" in result.stdout:
            return True
    return False


# ── Build functions ───────────────────────────────────────────────

def build_mingw(compiler: str, src_dir: str, out_dir: str):
    """Build using MinGW (native or cross)"""
    os.makedirs(out_dir, exist_ok=True)

    sources  = [os.path.join(src_dir, s) for s in SOURCES]
    out_file = os.path.join(out_dir, OUTPUT)

    cmd = [compiler] + FLAGS + DEFINES + sources + ["-o", out_file] + LINKS + ["-I", src_dir]

    log("COMPILE", " ".join(cmd[:6]) + " ...")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=src_dir)

    if result.returncode != 0:
        print(result.stderr)
        fail("Compilation failed")

    size = os.path.getsize(out_file)
    ok(f"Binary: {out_file}  ({size:,} bytes)")
    return out_file


def build_msvc(compiler: str, src_dir: str, out_dir: str):
    """Build using MSVC cl.exe"""
    os.makedirs(out_dir, exist_ok=True)

    sources  = [os.path.join(src_dir, s) for s in SOURCES]
    out_file = os.path.join(out_dir, OUTPUT)

    msvc_defines = [f"/D{d.lstrip('-D')}" for d in DEFINES]
    cmd = [compiler, "/O2", "/W3"] + msvc_defines + sources + [
        f"/Fe:{out_file}",
        "/link", "ntdll.lib", "iphlpapi.lib"
    ]

    log("COMPILE", " ".join(cmd[:4]) + " ...")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=src_dir)

    if result.returncode != 0:
        print(result.stderr)
        fail("MSVC compilation failed")

    ok(f"Binary: {out_file}")
    return out_file


# ── Main ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="JOCKY Windows Stealth Runtime Builder"
    )
    ap.add_argument("--cross",  action="store_true",
                    help="Force cross-compile mode (Linux → Windows)")
    ap.add_argument("--check",  action="store_true",
                    help="Check build tools only, don't compile")
    ap.add_argument("--src",    default=".",
                    help="Source directory (default: current)")
    ap.add_argument("--out",    default="./build_windows",
                    help="Output directory")
    args = ap.parse_args()

    print()
    print(bold("╔══════════════════════════════════════════════════════╗"))
    print(bold("║   JOCKY Windows Stealth Runtime Builder              ║"))
    print(bold("╚══════════════════════════════════════════════════════╝"))
    print()

    src_dir = os.path.abspath(args.src)
    out_dir = os.path.abspath(args.out)

    # ── Detect compiler ───────────────────────────────────────────
    print(bold("[ Step 1 ] Detect compiler"))
    compiler, mode = find_compiler(args.cross)

    if not compiler:
        warn("No compiler found.")
        print()
        print("  To install MinGW cross-compiler on Kali/Ubuntu:")
        print(f"    {yellow('sudo apt install mingw-w64')}")
        print()
        print("  Then run:")
        print(f"    {cyan('python3 build_windows_stealth.py --cross')}")
        print()
        if args.check:
            sys.exit(1)
        fail("No compiler available")

    log("MODE", mode)
    print()

    if args.check:
        ok("All tools available")
        print()
        print("  Compile with:")
        print(f"    {cyan('python3 build_windows_stealth.py --src ../runtime --out ./build_windows')}")
        return

    # ── Verify sources exist ──────────────────────────────────────
    print(bold("[ Step 2 ] Verify sources"))
    for s in SOURCES:
        path = os.path.join(src_dir, s)
        if not os.path.exists(path):
            fail(f"Source not found: {path}")
        ok(s)
    print()

    # ── Compile ───────────────────────────────────────────────────
    print(bold("[ Step 3 ] Compile"))
    if mode == "msvc":
        binary = build_msvc(compiler, src_dir, out_dir)
    else:
        binary = build_mingw(compiler, src_dir, out_dir)
    print()

    # ── Usage instructions ────────────────────────────────────────
    print(bold("[ Step 4 ] How to run"))
    print()
    print(f"  Copy {cyan(binary)} to your Windows machine.")
    print()
    print("  Run as Administrator (for full process access):")
    print(f"    {cyan('test_stealth_windows.exe')}")
    print()
    print("  Expected output:")
    print(f"    {cyan('[jocky] ssn NtQuerySystemInformation = 0x36 (54)')}")
    print(f"    {cyan('[jocky] proc pid=4      ppid=0      ... name=(System)')}")
    print(f"    {cyan('[jocky] proc pid=1234   ppid=4      ... name=svchost.exe')}")
    print(f"    {cyan('[jocky] ANOMALY=possible_hidden_processes')}")
    print(f"    {cyan('[jocky] driver idx=0 base=0x... name=ntoskrnl.exe')}")
    print()
    print(bold("╔══════════════════════════════════════════════════════╗"))
    print(bold("║   Build complete.                                    ║"))
    print(bold("╚══════════════════════════════════════════════════════╝"))
    print()


if __name__ == "__main__":
    main()
