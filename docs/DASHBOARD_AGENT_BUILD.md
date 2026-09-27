# JOCKY V5 — Dashboard Agent Artifacts

The JOCKY dashboard is the deployment surface for the two native single-file agents.
There is no separate `Windows EXE` button and no requirement for the investigator to
run a packaging command for a native build performed by the dashboard server.

## Dashboard workflow

1. Start the JOCKY server normally.
2. Open the dashboard.
3. Click either `⊞ Windows agent` or `🐧 Linux agent`.
4. The dashboard opens **JOCKY SINGLE-FILE AGENTS** and checks `dist/`.
5. If the requested native artifact already exists, choose **Download**.
6. If the requested artifact is missing but matches the server's OS, choose
   **Generate & Download**. The dashboard invokes `deploy/build_standalone.py`;
   the build script bootstraps PyInstaller when it is missing, then downloads the
   resulting one-file artifact.
7. If the requested artifact belongs to the other OS, choose **Import Native Build**
   after obtaining that native binary from a Windows/Linux native build machine or CI
   runner. The dashboard validates the PE/ELF file header before storing it in `dist/`.

## Native-build rule

PyInstaller cannot use a Linux host to produce a native Windows PE executable, or
use a Windows host to produce a native Linux ELF executable. Therefore:

- Linux dashboard server: can generate the Linux ELF directly.
- Windows dashboard server: can generate the Windows EXE directly.
- To have **both** artifacts available from one dashboard instance, build the
  other artifact on its native OS (or a native CI runner) once and place it in
  the server's `dist/` directory. The dashboard then serves both files directly.

This is a limitation of native packaging, not a limitation of the dashboard UI.

## Artifacts

```text
dist/
├── jocky-agent-linux
├── jocky-agent-linux.manifest.json
├── jocky-agent-windows.exe
└── jocky-agent-windows.exe.manifest.json
```

The executable is the deployment unit. Python source is not required on the
endpoint when the PyInstaller artifact is used.

## Build identity

Each build receives a fresh UUID and UTC timestamp. The SHA-256 of the final
artifact is recorded in the manifest. This is for artifact provenance and
traceability; it is not an antivirus/EDR bypass mechanism.
