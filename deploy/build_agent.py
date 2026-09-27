#!/usr/bin/env python3
"""Unified safe JOCKY native-agent build orchestrator.

Coordinates native single-file packaging, build provenance, artifact validation,
and manifest verification. Linux ELF is built on Linux; Windows PE is built on
Windows. It intentionally does not enable security-control bypass behavior.
"""
from __future__ import annotations
import argparse, hashlib, json, platform, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def validate(path: Path, expected: str) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"Artifact missing or empty: {path}")
    head=path.read_bytes()[:4]
    if expected == "linux" and head != b"\x7fELF":
        raise RuntimeError("Linux artifact is not an ELF executable")
    if expected == "windows" and head[:2] != b"MZ":
        raise RuntimeError("Windows artifact is not a PE executable")

def main() -> int:
    ap=argparse.ArgumentParser(description="Build and verify a JOCKY native single-file agent")
    ap.add_argument("--platform", choices=("native","linux","windows"), default="native")
    ap.add_argument("--skip-build", action="store_true")
    args=ap.parse_args()
    host=platform.system().lower()
    target=host if args.platform=="native" else args.platform
    if target not in ("linux","windows"):
        raise SystemExit("Native builds are supported on Linux and Windows only")
    if target != host:
        raise SystemExit(f"A {target} native agent must be built on a {target} runner/host")
    name="jocky-agent-linux" if target=="linux" else "jocky-agent-windows.exe"
    artifact=DIST/name
    if not args.skip_build:
        r=subprocess.run([sys.executable, str(ROOT/"deploy"/"build_standalone.py")], cwd=ROOT)
        if r.returncode: return r.returncode
    validate(artifact,target)
    manifest=artifact.with_name(artifact.name+".manifest.json")
    if not manifest.is_file(): raise SystemExit(f"Manifest missing: {manifest}")
    data=json.loads(manifest.read_text())
    actual=sha256(artifact)
    if data.get("sha256") != actual:
        raise SystemExit("Artifact SHA-256 does not match manifest")
    data["verification"]={"artifact_sha256_verified":True,"header_verified":True}
    manifest.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":"verified","artifact":str(artifact),"manifest":str(manifest),"sha256":actual},indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
