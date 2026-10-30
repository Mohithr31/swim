# Tiny Monitor — Windows + Linux Integration Fix

## What was fixed

The newer feature-rich build had a platform-bound server/dashboard path: several case APIs directly called the Windows collector from the server process, while the overview read normalized rows that could belong to an older case/device. The dashboard also contained presentation fallbacks for a Windows host and an artifact count, which could make an empty Linux case appear populated.

This build keeps the newer B1–B12 feature set and restores the working endpoint-first behavior from the earlier cross-platform implementation.

### 1. Endpoint-first telemetry
- The server no longer substitutes its own Windows/Linux host for the assigned endpoint.
- Case views resolve the endpoint assigned to the selected case.
- System, process, network, filesystem, service, task, user, login, browser and timeline views can consume endpoint telemetry on both OS families.
- If the endpoint has not supplied evidence, the UI reports `NO_EVIDENCE_FOUND` / `NO DATA RECEIVED` instead of inventing values.

### 2. Rich B1–B8 endpoint collection
After a case is assigned, the agent performs a case-scoped rich snapshot using the target operating system:
- B1 Browser Forensics
- B2 Application Forensics
- B3 Messaging Forensics
- B4 Email Forensics
- B6 Device Forensics
- B7 System Forensics
- B8 Filesystem Forensics
- Network/user/service/log compatibility telemetry

The existing Linux and Windows native collectors remain in place.

### 3. Case binding
Telemetry submissions now carry the case ID and are rejected when the supplied case does not match the endpoint's active case. The dashboard resolves data from the case's assigned endpoint rather than from the server OS.

### 4. Removed fabricated dashboard fallbacks
The overview no longer contains fallback values for a Windows hostname, Windows build, RAM, CPU, collection run ID, or a fixed artifact count.

### 5. Clean deployment package
The source distribution does not include:
- a runtime SQLite database
- collected evidence
- a committed `.env`
- Windows virtual-environment files
- Python bytecode/cache files

Runtime data is created on the machine where the server is deployed.

## Linux validation performed

- Python syntax validation: all source Python files parsed successfully.
- Linux B1–B10 collection smoke test completed successfully with real local collectors.
- Rich Linux telemetry snapshot completed and produced real Linux system/application/device/network data.
- A full Linux forensic collection completed and produced a SHA-256 packaged evidence archive.

The test environment did not contain Flask, so the Flask integration test suite could not be executed in this build environment. Install `requirements.txt` on the deployment machine before running the server tests.

## Start

Linux:
```bash
./setup_linux.sh
./run_server.sh
./run_agent.sh --server http://SERVER_IP:5000
```

Windows:
```powershell
.\setup_windows.ps1
.\run_server.ps1
.\agent\run_agent.ps1
```

For a real deployment, copy `.env.example` to `.env` and set deployment-specific credentials/API keys.
