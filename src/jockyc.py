"""JOCKY compiler CLI.

Authoritative pipeline:
  .jky -> lexer/parser -> forensic plan -> LLVM IR -> transformations ->
  native executable (when clang is available).

The compiler is intentionally limited to the allow-listed forensic DSL and
never exposes primitives for security-control disabling or kernel subversion.
"""
import argparse, json, os, shutil, subprocess, sys
from pathlib import Path


def _parse_args():
    p = argparse.ArgumentParser(prog="jockyc", description="JOCKY DFIR DSL Compiler")
    p.add_argument("source", help="Path to .jky source")
    p.add_argument("--plan", action="store_true", help="Print compiled forensic plan")
    p.add_argument("--c-output", metavar="PATH", help="Write generated C source")
    p.add_argument("--emit-llvm", metavar="PATH", help="Write transformed LLVM IR")
    p.add_argument("--obfuscate-level", type=int, choices=(0,1,2,3), default=3)
    p.add_argument("-o", "--output", metavar="BINARY", help="Build native binary")
    p.add_argument("--backend", choices=("llvm", "c"), default="llvm")
    return p.parse_args()


def _write(path, text):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")


def main():
    args = _parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from src.parser import parse_jocky_source
    from src.plan import compile_plan_from_ast
    from src.codegen import generate_c_code
    from src.llvm_ir_gen import emit_llvm_ir
    
    source_path = Path(args.source).resolve()
    module = parse_jocky_source(source_path.read_text(encoding="utf-8"))
    plan = compile_plan_from_ast(module)

    if args.plan or not (args.c_output or args.emit_llvm or args.output):
        print(json.dumps(plan, indent=2))

    if args.c_output:
        _write(args.c_output, generate_c_code(module))
        print(f"[jockyc] C source: {args.c_output}", file=sys.stderr)

    ir = None
    if args.emit_llvm or args.output:
        # The compiler emits standards-compliant LLVM IR. Existing experimental
        # obfuscation passes remain separately testable but are not automatically
        # wired into production artifacts because that would turn the compiler
        # into a security-control evasion mechanism.
        ir = emit_llvm_ir(module, source_file=str(source_path))
        if args.emit_llvm:
            _write(args.emit_llvm, ir)
            print(f"[jockyc] LLVM IR: {args.emit_llvm}", file=sys.stderr)

    if args.output:
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        clang = shutil.which("clang")
        if not clang:
            print("[jockyc] clang is required for native LLVM builds", file=sys.stderr)
            return 2
        import tempfile
        with tempfile.TemporaryDirectory(prefix="jockyc-") as td:
            ll = Path(td) / "module.ll"
            ll.write_text(ir, encoding="utf-8")
            runtime = root / "runtime" / ("jocky_runtime_windows.c" if os.name == "nt" else "jocky_runtime.c")
            obj = Path(td) / "module.o"
            runtime_obj = Path(td) / "runtime.o"
            result = subprocess.run([clang, "-O2", "-x", "ir", str(ll), "-c", "-o", str(obj)], text=True, capture_output=True)
            if result.returncode:
                print(result.stderr, file=sys.stderr); return result.returncode
            result = subprocess.run([clang, "-O2", "-std=c11", "-I", str(root / "runtime"), "-c", str(runtime), "-o", str(runtime_obj)], text=True, capture_output=True)
            if result.returncode:
                print(result.stderr, file=sys.stderr); return result.returncode
            result = subprocess.run([clang, str(obj), str(runtime_obj), "-lcrypto", "-o", str(output)], text=True, capture_output=True)
            if result.returncode:
                print(result.stderr, file=sys.stderr); return result.returncode
        print(f"[jockyc] native binary: {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
