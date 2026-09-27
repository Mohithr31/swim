# JOCKY V5 — Single-File Agent Deployment

JOCKY V5 can be deployed as exactly one native executable per target OS:

| Target | Artifact | Built on |
|---|---|---|
| Linux | `dist/jocky-agent-linux` (ELF) | Linux |
| Windows | `dist/jocky-agent-windows.exe` (PE) | Windows |

The artifact is a PyInstaller `--onefile` executable. Python and the Python
modules required by the agent are bundled inside it, so the target machine
does not need a Python installation.

## Build Linux ELF

Run on the Linux build machine:

```bash
python3 -m pip install -r requirements.txt
python3 -m pip install pyinstaller
python3 deploy/build_standalone.py
```

Output:

```text
dist/jocky-agent-linux
dist/jocky-agent-linux.manifest.json
```

## Build Windows EXE

Run on the Windows build machine:

```powershell
py -m pip install -r requirements.txt
py -m pip install pyinstaller
py deploy\build_standalone.py
```

Output:

```text
dist\jocky-agent-windows.exe
dist\jocky-agent-windows.exe.manifest.json
```

## Why two native builds?

PyInstaller bundles the interpreter and native bootloader for the OS on which
it is run. Therefore one build cannot natively produce both a Windows PE
executable and a Linux ELF executable. Build each artifact on its matching OS
(or use a properly isolated CI runner for that OS).

## Different binary on every build

Every build generates a fresh UUID and UTC build timestamp in
`agent/build_identity.py`. The identity is included in the packaged agent and
reported as build provenance. The final artifact's SHA-256 is written to the
manifest, so two independently built artifacts will normally have different
bytes and hashes.

This mechanism is for **build provenance and artifact traceability**. It does
not disable, bypass, or attempt to evade antivirus/EDR controls.

## Dashboard

The dashboard exposes two compact platform-specific buttons:

- `⊞ Windows agent` → `/downloads/agent/windows`
- `🐧 Linux agent` → `/downloads/agent/linux`

The old separate `Windows EXE` dashboard button is removed. The two buttons
serve the single-file artifacts directly.

## Deployment

Copy only the appropriate artifact to the target machine. For example:

```bash
./jocky-agent-linux --help
```

or on Windows:

```powershell
.\jocky-agent-windows.exe --help
```

Use the normal JOCKY server URL/API configuration supported by the agent and
run it only on endpoints where forensic collection is authorized.
