# -*- mode: python ; coding: utf-8 -*-
"""Portable PyInstaller spec for the JOCKY single-file agent.

Prefer deploy/build_standalone.py because it creates a fresh build identity
and selects the correct Linux/Windows artifact name automatically.
"""
from pathlib import Path

ROOT = Path(SPECPATH).resolve()


a = Analysis(
    [str(ROOT / "agent" / "jocky_agent.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="jocky-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
