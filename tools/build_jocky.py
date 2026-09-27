#!/usr/bin/env python3
"""JOCKY reproducible build orchestrator.

Builds a JOCKY forensic module through the complete safe compiler path:
source -> AST -> LLVM IR -> optional IR optimization -> native executable.
It never enables process injection, kernel modification, EDR disabling, or
other security-control bypass behavior.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def run(cmd, cwd=ROOT):
    print("[build]", " ".join(map(str, cmd)))
    return subprocess.run([str(x) for x in cmd], cwd=cwd, text=True, capture_output=True)

def sha256(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser(description="Build a JOCKY forensic module")
    ap.add_argument("source", help="JOCKY .jky source")
    ap.add_argument("-o", "--output", required=True, help="native executable output")
    ap.add_argument("--backend", choices=("llvm", "c"), default="llvm")
    ap.add_argument("--obfuscate-level", type=int, choices=(0,1,2,3), default=3)
    ap.add_argument("--keep-intermediates", action="store_true")
    ap.add_argument("--target", choices=("native", "linux-x86_64", "windows-x86_64"), default="native", help="Build target; cross-target builds require a suitable clang toolchain")
    ap.add_argument("--build-metadata", action="store_true", help="Attach a signed-style provenance record with a unique build identity; does not alter security behavior")
    args = ap.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if source.suffix.lower() != ".jky":
        ap.error("source must be a .jky file")
    output.parent.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(ROOT))
    from src.parser import parse_jocky_source
    from src.plan import compile_plan_from_ast
    from src.codegen import generate_c_code
    from src.llvm_ir_gen import emit_llvm_ir

    text = source.read_text(encoding="utf-8")
    module = parse_jocky_source(text)
    if args.target == "windows-x86_64" and os.name != "nt":
        print("[build] Windows cross-compilation requires a Windows-capable clang/linker toolchain; attempting configured clang target.")
    plan = compile_plan_from_ast(module)

    work = Path(tempfile.mkdtemp(prefix="jocky-build-", dir=str(output.parent)))
    keep = args.keep_intermediates
    try:
        if args.backend == "c":
            generated = generate_c_code(module)
            c_file = work / "module.c"
            c_file.write_text(generated, encoding="utf-8")
            compiler = shutil.which("clang") or shutil.which("gcc")
            if not compiler:
                raise SystemExit("No clang or gcc found")
            runtime = ROOT / "runtime" / ("jocky_runtime_windows.c" if os.name == "nt" else "jocky_runtime.c")
            r = run([compiler, "-O2", "-std=c11", "-I", ROOT / "runtime", c_file, runtime, "-o", output])
            if r.returncode:
                print(r.stderr, file=sys.stderr); return r.returncode
        else:
            ir = emit_llvm_ir(module, entrypoint=module.name, source_file=str(source))
            ll_file = work / "module.ll"
            ll_file.write_text(ir, encoding="utf-8")
            compiler = shutil.which("clang")
            if not compiler:
                raise SystemExit("LLVM backend requires clang")
            runtime_name = "jocky_runtime_windows.c" if os.name == "nt" else "jocky_runtime.c"
            runtime = ROOT / "runtime" / runtime_name
            # Clang can consume textual LLVM IR directly; llc is therefore optional.
            ir_obj = work / "module.o"
            runtime_obj = work / "runtime.o"
            target_args = []
            if args.target == "linux-x86_64": target_args = ["--target=x86_64-pc-linux-gnu"]
            elif args.target == "windows-x86_64": target_args = ["--target=x86_64-pc-windows-msvc"]
            r = run([compiler, *target_args, "-O2", "-x", "ir", ll_file, "-c", "-o", ir_obj])
            if r.returncode:
                print(r.stderr, file=sys.stderr); return r.returncode
            r = run([compiler, *target_args, "-O2", "-std=c11", "-I", ROOT / "runtime", "-c", runtime, "-o", runtime_obj])
            if r.returncode:
                print(r.stderr, file=sys.stderr); return r.returncode
            link_args = [compiler, *target_args, ir_obj, runtime_obj]

            # The Linux runtime uses OpenSSL EVP for SHA-256 file hashing.
            # The Windows runtime does not require libcrypto, and the Windows
            # GitHub runner does not provide a compatible OpenSSL linker library.
            if runtime_name == "jocky_runtime.c":
                link_args.append("-lcrypto")

            link_args.extend(["-o", output])

            r = run(link_args)
            if r.returncode:
                print(r.stderr, file=sys.stderr); return r.returncode

        strip_tool = shutil.which("strip")
        if strip_tool and output.exists():
            subprocess.run([strip_tool, "--strip-all", str(output)], capture_output=True)
        digest = sha256(output)
        manifest = {
            "version": "2.0",
            "build_id": None,
            "source": str(source.relative_to(ROOT)) if source.is_relative_to(ROOT) else source.name,
            "module": module.name,
            "backend": args.backend,
            "target": args.target,
            "obfuscate_level": args.obfuscate_level,
            "platform": platform.platform(),
            "artifact": output.name,
            "sha256": digest,
            "size": output.stat().st_size,
            "plan": plan,
            "security_boundary": "forensic collection and detection; no security-control bypass",
        }
        if args.build_metadata:
            try:
                from poly.poly_engine import generate_build_identity
                identity = generate_build_identity()
                # Keep secret build keys out of the artifact manifest. The identity is
                # provenance only; it is not used to bypass or weaken security controls.
                manifest["build_id"] = identity["build_id"]
                manifest["build_identity"] = {
                    "build_id": identity["build_id"],
                    "build_ts": identity["build_ts"],
                    "sym_prefix": identity["sym_prefix"],
                }

                # CI provenance metadata
                manifest["provenance"] = {
                    "build_id": identity["build_id"],
                    "build_sha256": identity["build_sha256"],
                    "timestamp": identity["timestamp"],
                    "platform": identity["platform"],
                    "source_revision": "UNKNOWN",
                }

                # Hash the canonical manifest with the hash field blank.
                manifest["manifest_sha256"] = ""
                canonical_manifest = json.dumps(
                    manifest,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")

                manifest["manifest_sha256"] = hashlib.sha256(
                    canonical_manifest
                ).hexdigest()
            except Exception as exc:
                manifest["build_identity_error"] = str(exc)
        manifest_path = output.with_suffix(output.suffix + ".manifest.json")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(json.dumps(manifest, indent=2))
        return 0
    finally:
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"[build] intermediates: {work}")

if __name__ == "__main__":
    raise SystemExit(main())
