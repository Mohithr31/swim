
#!/usr/bin/env python3
"""
deploy/build_wine_windows.py
─────────────────────────────────────────────────────────────
Cross-build the JOCKY Windows agent (.exe) from Linux using Wine.

What this script does:
  1. Checks Wine is installed (apt install wine)
  2. Checks / installs a Windows Python 3.11 inside Wine (~/.wine)
  3. Installs PyInstaller + agent deps inside Wine Python
  4. Writes a fresh build identity (unique UUID + timestamp)
  5. Runs PyInstaller via Wine → produces jocky-agent-windows.exe
  6. Patches the JNONCE: placeholder so per-download hashes work
  7. Writes the manifest JSON (sha256, size, build_id …)
  8. Copies artifact to dist/ so the dashboard serves it immediately

Run:
    python3 deploy/build_wine_windows.py

Options:
    --check       Only check tools, don't build
    --no-install  Skip automatic Wine Python / pip install steps
    --out DIR     Output directory (default: <repo>/dist)
"""
from __future__ import annotations

import os
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
IDENTITY_MODULE = ROOT / "agent" / "build_identity.py"
ARTIFACT_NAME = "jocky-agent-windows.exe"
MANIFEST_NAME = ARTIFACT_NAME + ".manifest.json"
JNONCE_MARKER  = b"JNONCE:"
JNONCE_PAYLOAD = 57
VERSION = "5.0"

# Windows Python 3.11 standalone installer (no admin required)
WIN_PYTHON_URL = (
    "https://www.python.org/ftp/python/3.11.9/"
    "python-3.11.9-amd64.exe"
)
WIN_PYTHON_INSTALLER = Path.home() / ".cache" / "jocky" / "python-3.11.9-amd64.exe"

# Wine prefix selection.
# The dashboard server may be started without WINEPREFIX even though the
# operator has a working dedicated JOCKY prefix (for example ~/.jocky-wine).
# Prefer an explicitly supplied prefix, then an existing JOCKY prefix, then
# the normal Wine default. This prevents the dashboard build from silently
# using a different/broken prefix and producing kernel32.dll errors.
def _select_wine_prefix() -> Path:
    explicit = os.environ.get("WINEPREFIX")
    if explicit:
        return Path(explicit).expanduser()

    candidates = [
        Path.home() / ".jocky-wine",
        Path.home() / ".wine",
    ]
    for candidate in candidates:
        if (candidate / "drive_c").exists():
            return candidate

    # Default for a first-time setup.
    return candidates[0]

WINE_PREFIX = _select_wine_prefix()
os.environ["WINEPREFIX"] = str(WINE_PREFIX)

# Where Wine installs Windows Python
WINE_PYTHON_PATHS = [
    WINE_PREFIX / "drive_c" / "Python311" / "python.exe",
    WINE_PREFIX / "drive_c" / "Program Files" / "Python311" / "python.exe",
    WINE_PREFIX / "drive_c" / "users" / os.environ.get("USER", "user") / "AppData" / "Local" / "Programs" / "Python" / "Python311" / "python.exe",
]

# ── Colour helpers ────────────────────────────────────────────────────────────
def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m"

ok   = lambda s: print(f"  [\033[92m OK \033[0m] {s}")
fail = lambda s: (print(f"  [\033[91mFAIL\033[0m] {s}"), sys.exit(1))
info = lambda s: print(f"  [\033[96mINFO\033[0m] {s}")
warn = lambda s: print(f"  [\033[93mWARN\033[0m] {s}")
step = lambda n, s: print(f"\n\033[1m[ Step {n} ] {s}\033[0m")


# ── Tool checks ───────────────────────────────────────────────────────────────
def require_linux() -> None:
    if platform.system() != "Linux":
        fail("build_wine_windows.py must be run on Linux (Kali, Ubuntu, Debian …)")

def find_wine() -> str | None:
    return shutil.which("wine") or shutil.which("wine64")

def ensure_wine_prefix(wine: str) -> None:
    # Initialize an existing/new prefix before invoking Windows programs.
    # A valid prefix should contain drive_c; wineboot repairs/initializes the
    # prefix without changing the project code.
    WINE_PREFIX.mkdir(parents=True, exist_ok=True)
    drive_c = WINE_PREFIX / "drive_c"
    if not drive_c.exists():
        info(f"Initializing Wine prefix: {WINE_PREFIX}")
    try:
        result = subprocess.run(
            [wine, "wineboot", "-u"],
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=180,
        )
    except Exception as exc:
        fail(f"Wine prefix initialization failed: {exc}")
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        fail(
            f"Wine prefix is not usable: {WINE_PREFIX}. "
            f"Wine returned {result.returncode}. {details[-1200:]}"
        )
    ok(f"Wine prefix: {WINE_PREFIX}")

def find_wine_python() -> Path | None:
    for p in WINE_PYTHON_PATHS:
        if p.exists():
            return p
    # Also search dynamically
    base = WINE_PREFIX / "drive_c"
    if base.exists():
        for hit in base.rglob("python.exe"):
            if "Python3" in str(hit) or "python3" in str(hit).lower():
                return hit
    return None

def wine_python_to_windows_path(p: Path) -> str:
    """Convert a host ~/.wine/drive_c/... path to Wine C:\\... path."""
    rel = str(p).replace(str(WINE_PREFIX / "drive_c"), "")
    return "C:" + rel.replace("/", "\\")


# ── Wine Python install ───────────────────────────────────────────────────────
def download_win_python() -> Path:
    WIN_PYTHON_INSTALLER.parent.mkdir(parents=True, exist_ok=True)
    if WIN_PYTHON_INSTALLER.exists():
        info(f"Installer already cached: {WIN_PYTHON_INSTALLER}")
        return WIN_PYTHON_INSTALLER
    info(f"Downloading Windows Python 3.11 installer (~25 MB)…")
    info(f"  URL: {WIN_PYTHON_URL}")
    urllib.request.urlretrieve(WIN_PYTHON_URL, WIN_PYTHON_INSTALLER)
    ok("Download complete")
    return WIN_PYTHON_INSTALLER


def install_wine_python(wine: str) -> Path:
    installer = download_win_python()
    info("Installing Python 3.11 into Wine (silent install — takes ~60s)…")
    win_installer = "Z:" + str(installer).replace("/", "\\")
    cmd = [
        wine, win_installer,
        "/quiet",
        "InstallAllUsers=0",
        "PrependPath=1",
        "Include_test=0",
        "TargetDir=C:\\Python311",
    ]
    result = subprocess.run(cmd, timeout=300)
    if result.returncode not in (0, 1):  # 1 = reboot required, fine for us
        fail(f"Python installer exited {result.returncode}")
    py = find_wine_python()
    if not py:
        fail(f"Python was not found in Wine after install. Check {WINE_PREFIX / 'drive_c' / 'Python311'}")
    ok(f"Wine Python installed: {py}")
    return py


def ensure_wine_python(wine: str, no_install: bool) -> Path:
    py = find_wine_python()
    if py:
        ok(f"Wine Python found: {py}")
        return py
    if no_install:
        fail("Wine Python not found and --no-install is set. Run without --no-install first.")
    warn("Wine Python not found — installing now…")
    return install_wine_python(wine)


# ── pip inside Wine ───────────────────────────────────────────────────────────
def wine_pip_install(wine: str, win_py: str, *packages: str) -> None:
    """Install packages into the Wine Python environment."""
    cmd = [wine, win_py, "-m", "pip", "install", "--quiet", "--upgrade", *packages]
    info(f"pip install {' '.join(packages)}")
    result = subprocess.run(cmd, timeout=300)
    if result.returncode != 0:
        fail(f"pip install failed for: {packages}")
    ok(f"Installed: {' '.join(packages)}")


def check_wine_package(wine: str, win_py: str, package: str) -> bool:
    result = subprocess.run(
        [wine, win_py, "-c", f"import {package}"],
        capture_output=True, timeout=30
    )
    return result.returncode == 0


# ── Build identity ────────────────────────────────────────────────────────────
def make_identity() -> dict:
    return {
        "build_id":          str(uuid.uuid4()),
        "built_at":          datetime.now(timezone.utc).isoformat(),
        "version":           VERSION,
        "platform":          "windows",
        "machine":           "x86_64",
        "python":            "3.11",
        "builder":           "deploy/build_wine_windows.py (Wine cross-build from Linux)",
        "security_boundary": "forensic collection and detection; no security-control bypass",
    }


def write_identity(identity: dict) -> None:
    source = (
        "# AUTO-GENERATED by deploy/build_wine_windows.py\n"
        "# Build provenance only; do not edit manually.\n"
        f"BUILD_IDENTITY = {identity!r}\n"
        "BUILD_ID = BUILD_IDENTITY['build_id']\n"
    )
    IDENTITY_MODULE.write_text(source, encoding="utf-8")
    ok(f"Build identity written (build_id={identity['build_id'][:8]}…)")


# ── JNONCE patch ──────────────────────────────────────────────────────────────
def patch_jnonce(artifact: Path) -> None:
    """Overwrite the JNONCE placeholder with random bytes so the server's
    per-download patch has something to locate.  The server replaces these
    bytes again on every download — this just ensures the marker exists."""
    data = bytearray(artifact.read_bytes())
    idx  = data.find(JNONCE_MARKER)
    if idx == -1:
        warn("JNONCE: placeholder not found in binary — per-download unique hash will not work.")
        warn("Ensure _DELIVERY_NONCE = b'JNONCE:' + b'\\x00'*57 is in agent/jocky_agent.py")
        return
    nonce_start = idx + len(JNONCE_MARKER)
    data[nonce_start : nonce_start + JNONCE_PAYLOAD] = os.urandom(JNONCE_PAYLOAD)
    artifact.write_bytes(bytes(data))
    ok("JNONCE placeholder verified and seeded with initial random bytes")


# ── Manifest ──────────────────────────────────────────────────────────────────
def write_manifest(artifact: Path, identity: dict) -> Path:
    sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = {
        **identity,
        "artifact":       artifact.name,
        "sha256":         sha256,
        "size_bytes":     artifact.stat().st_size,
        "artifact_type":  "PE",
        "cross_built":    True,
        "cross_build_tool": "Wine (build_wine_windows.py)",
    }
    manifest_path = artifact.parent / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Self-hash the manifest
    m_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    manifest["manifest_sha256"] = m_sha
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ok(f"Manifest written: {manifest_path.name}")
    ok(f"SHA-256: {sha256}")
    return manifest_path


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(description="Cross-build JOCKY Windows agent via Wine")
    ap.add_argument("--check",       action="store_true", help="Check tools only, don't build")
    ap.add_argument("--no-install",  action="store_true", help="Skip automatic dep installation")
    ap.add_argument("--out",         default=str(DIST),   help="Output directory (default: dist/)")
    args = ap.parse_args()

    print()
    print("\033[1m╔══════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[1m║   JOCKY Windows Agent — Wine Cross-Build (Linux → .exe)      ║\033[0m")
    print("\033[1m╚══════════════════════════════════════════════════════════════╝\033[0m")

    # ── Step 1: OS check ──────────────────────────────────────────────────────
    step(1, "Platform check")
    require_linux()
    ok(f"Running on Linux ({platform.release()})")

    # ── Step 2: Wine ──────────────────────────────────────────────────────────
    step(2, "Locate Wine")
    wine = find_wine()
    if not wine:
        print()
        print("  Wine is not installed. Install it with:")
        print("    \033[96msudo apt update && sudo apt install -y wine wine64\033[0m")
        print()
        if not args.check:
            fail("Wine not found")
        else:
            warn("Wine not found — install it before building")
            return 1
    ok(f"Wine: {wine}")
    ensure_wine_prefix(wine)

    # ── Step 3: Wine Python ───────────────────────────────────────────────────
    step(3, "Locate / install Windows Python 3.11 in Wine")
    if args.check:
        py_path = find_wine_python()
        if py_path:
            ok(f"Wine Python: {py_path}")
        else:
            warn("Wine Python not found — run without --check to install")
        print()
        print("  All tools present. Build with:")
        print(f"    \033[96mpython3 deploy/build_wine_windows.py\033[0m")
        return 0

    wine_py_host = ensure_wine_python(wine, args.no_install)
    win_py = wine_python_to_windows_path(wine_py_host)  # C:\Python311\python.exe
    info(f"Wine Python (Windows path): {win_py}")

    # ── Step 4: PyInstaller + deps in Wine ───────────────────────────────────
    step(4, "Ensure PyInstaller + requests inside Wine Python")
    if not args.no_install:
        wine_pip_install(wine, win_py, "pyinstaller>=6.0", "requests", "psutil", "cryptography", "python-dotenv")
    else:
        if not check_wine_package(wine, win_py, "PyInstaller"):
            fail("PyInstaller not found in Wine Python. Run without --no-install.")
        ok("PyInstaller already present in Wine Python")

    # ── Step 5: Build identity ────────────────────────────────────────────────
    step(5, "Write unique build identity")
    identity = make_identity()
    write_identity(identity)

    # ── Step 6: PyInstaller build via Wine ───────────────────────────────────
    step(6, "Compile Windows .exe via Wine + PyInstaller")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    agent_script_host = ROOT / "agent" / "jocky_agent.py"
    # PyInstaller runs inside Wine, so paths must be Windows-style
    agent_script_win  = "Z:" + str(agent_script_host).replace("/", "\\")
    root_win          = "Z:" + str(ROOT).replace("/", "\\")
    dist_win          = "Z:" + str(out_dir).replace("/", "\\")

    pyinstaller_cmd = [
        wine, win_py,
        "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        "--onefile",
        "--name",   "jocky-agent-windows",
        "--paths",  root_win,
        "--distpath", dist_win,
        "--workpath", "Z:" + str(ROOT / "build_wine_tmp").replace("/", "\\"),
        "--specpath", "Z:" + str(ROOT / "build_wine_tmp").replace("/", "\\"),
        agent_script_win,
    ]

    info(f"Running: wine python -m PyInstaller --onefile jocky_agent.py …")
    result = subprocess.run(pyinstaller_cmd, cwd=ROOT, timeout=900)
    if result.returncode != 0:
        fail(f"PyInstaller (Wine) exited with code {result.returncode}")

    artifact = out_dir / ARTIFACT_NAME
    if not artifact.exists():
        fail(f"Build completed but artifact not found at: {artifact}")
    ok(f"Artifact: {artifact} ({artifact.stat().st_size:,} bytes)")

    # ── Step 7: JNONCE patch ──────────────────────────────────────────────────
    step(7, "Verify / seed JNONCE placeholder for per-download unique hash")
    patch_jnonce(artifact)

    # ── Step 8: Manifest ──────────────────────────────────────────────────────
    step(8, "Write SHA-256 manifest")
    manifest_path = write_manifest(artifact, identity)

    # ── Step 9: Cleanup build tmp ─────────────────────────────────────────────
    step(9, "Clean up Wine build temporaries")
    tmp = ROOT / "build_wine_tmp"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
        ok("Cleaned build_wine_tmp/")

    # ── Done ──────────────────────────────────────────────────────────────────
    print()
    print("\033[1m╔══════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[1m║   BUILD COMPLETE                                              ║\033[0m")
    print("\033[1m╚══════════════════════════════════════════════════════════════╝\033[0m")
    print()
    print(f"  Artifact : {artifact}")
    print(f"  Manifest : {manifest_path}")
    print(f"  Build ID : {identity['build_id']}")
    print(f"  SHA-256  : {hashlib.sha256(artifact.read_bytes()).hexdigest()}")
    print()
    print("  The dashboard will now serve this .exe with a unique hash per download.")
    print("  Each download patches the JNONCE: bytes → different SHA-256 every time.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
