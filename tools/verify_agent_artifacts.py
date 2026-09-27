#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, sys

root = Path(__file__).resolve().parents[1]
artifact = root / "dist" / "jocky-agent-windows.exe"
manifest = root / "dist" / "jocky-agent-windows.exe.manifest.json"

if not artifact.exists():
    print(f"MISSING: {artifact}")
    print("Build/import the Windows native artifact before using the dashboard download.")
    sys.exit(1)

sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
print(f"Windows artifact: {artifact}")
print(f"Size: {artifact.stat().st_size} bytes")
print(f"SHA-256: {sha}")

if manifest.exists():
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        print("Manifest: present")
        print(f"Build ID: {data.get('build_id', '<not specified>')}")
    except Exception:
        print("Manifest: present but could not be parsed")
else:
    print("Manifest: missing (artifact is still present)")
