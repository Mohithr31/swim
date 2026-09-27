# Browser Forensics: Read-Only Acquisition Layer

## Architecture

Browser artifacts are collected on the assigned endpoint by the JOCKY agent. The central server only receives authenticated telemetry; it does not inspect the server host's browser profile.

Linux:

`browser profile -> raw_acquisition.py -> Linux syscall ABI (openat/read/close/getdents64/lseek) -> parser -> browser_forensics telemetry -> authenticated agent transport -> server -> dashboard`

Windows:

`browser profile -> raw_acquisition.py -> kernel32 CreateFileW/ReadFile/GetFileSizeEx/CloseHandle -> parser -> browser_forensics telemetry -> authenticated agent transport -> server -> dashboard`

The acquisition layer is read-only. It is not intended to bypass AV/EDR or kernel auditing. Security monitoring can still observe the resulting file access.

## Why the parser remains separate

Syscalls provide bytes and directory entries; they do not understand Chrome/Edge/Firefox schemas. SQLite, JSON and LevelDB parsing therefore remains above the acquisition layer.

## Real-data rule

`synthetic_data` remains `false`. If a browser profile or artifact is absent, the dashboard reports no telemetry rather than generating sample rows.
