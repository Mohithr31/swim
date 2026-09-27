# HOW TO RUN — JOCKY Combined Framework

## Prerequisites

- Python 3.11+ (3.13 tested)
- `pip` / `venv`
- Optional for LLVM build: `clang`, `opt`, `llc` (LLVM toolchain)
- Optional for PDF reports: `weasyprint` or `wkhtmltopdf`

---

## 1. Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate          # Linux/macOS
# OR
.\venv\Scripts\activate           # Windows PowerShell

pip install -r requirements.txt
```

---

## 2. Start the Central Server

```bash
python3 -m server.server
```

Default: `http://127.0.0.1:5000`

Set environment variables in `.env` (copy from `.env.example`):
```
JOCKY_API_KEY=your-secret-key
JOCKY_DB=jocky_forensics.db
JOCKY_EVIDENCE_DIR=evidence
PORT=5000
```

---

## 3. Launch the Forensic Agent

### Linux
```bash
python3 -m agent.jocky_agent --server http://127.0.0.1:5000
```

### Windows (PowerShell)
```powershell
.\agent\run_agent.ps1
```

### Generate a Launcher Script
```bash
python3 deploy/generate_agent.py --os linux --server http://SERVER:5000 -o ./launch_agent.sh
python3 deploy/generate_agent.py --os windows --server http://SERVER:5000 -o ./launch_agent.ps1
```

---

## 4. Compile a JOCKY Script

### Basic Plan Compilation (Python path — no LLVM required)
```bash
python3 -m src.jockyc examples/full_forensic.jky --plan
python3 -m src.jockyc examples/full_forensic.jky --c-output /tmp/jocky_agent.c
```

### LLVM IR + Obfuscation Pipeline (requires LLVM toolchain)
```bash
python3 -m src.jockyc examples/full_forensic.jky -o agent_binary --emit-llvm
python3 -m src.jockyc examples/full_forensic.jky -o agent_binary --obfuscate-level 3
```

### Polymorphic Build (unique hash every run)
```bash
python3 poly/poly_engine.py --src runtime --out poly/build
```

### .text Section Encryption
```bash
python3 poly/jocky_text_encrypt.py --input poly/build/jocky_agent --output poly/build/jocky_agent_enc --verify
```

---

## 5. Domain Fronting Proxy (optional)

Routes all agent→server traffic through a trusted CDN.

```bash
# Start proxy (alongside server)
python3 server/jocky_domain_front.py --mode proxy --backend http://127.0.0.1:5000

# Test connectivity
python3 server/jocky_domain_front.py --mode test
```

Agents automatically use the proxy when configured.

---

## 6. Live Monitoring

The live monitor runs within the agent automatically when a live job is dispatched. You can also run it standalone:

```bash
python3 -c "
from collector.live_monitor import LiveMonitorEngine
engine = LiveMonitorEngine('test-agent-001', 'http://127.0.0.1:5000')
engine.start()
import time; time.sleep(10)
events = engine.poll_cycle()
print(f'Collected {len(events)} live events')
"
```

---

## 7. Docker Deployment

```bash
cd deploy
cp .env.example .env
# Edit .env with your keys
docker-compose up -d
```

---

## 8. Run Tests

```bash
python -m pytest tests/ -v

# Specific suites
python -m pytest tests/test_live_monitoring.py -v
python -m pytest tests/test_windows_forensics.py -v
python -m pytest tests/test_stage17_18.py -v
python -m pytest tests/test_integration.py -v
```

---

## 9. Encrypt/Decrypt Evidence

```bash
# Encrypt an evidence archive
python3 security/jocky_crypt.py --encrypt evidence/case001.tar.gz --output evidence/case001.jockyenc

# Decrypt for review
python3 security/jocky_crypt.py --decrypt evidence/case001.jockyenc --output evidence/case001_decrypted.tar.gz
```

---

## 10. Investigator Dashboard

Open `http://127.0.0.1:5000` in your browser after starting the server.

Features:
- Real-time device, case, and job management
- JOCKY DSL editor with plan preview
- Evidence chain-of-custody viewer
- Unified forensic timeline
- Correlation findings panel
- HTML/PDF report generation
- Live event stream viewer

---

## Folder Reference

```
src/         — JOCKY DSL compiler + LLVM IR generator + obfuscator
poly/        — Polymorphic build engine + .text encryption
runtime/     — C forensic runtimes (standard + stealth + direct-syscall)
agent/       — Forensic agent (Linux + Windows PowerShell)
collector/   — All forensic data collectors
server/      — Central server, DB, timeline, correlation, dashboard
security/    — AES-256-GCM evidence encryption library
client/      — CLI investigator tool
examples/    — Sample .jky forensic scripts
tests/       — Full test suite
deploy/      — Docker + agent launcher generator
docs/        — Architecture documentation
.github/     — CI/CD workflows
```

## Single-file endpoint agents (recommended deployment)

Build the artifact on the same operating system as the target:

### Linux → one ELF
```bash
python3 -m pip install pyinstaller
python3 deploy/build_standalone.py
```
Produces `dist/jocky-agent-linux` plus its SHA-256 build manifest.

### Windows → one EXE
```powershell
py -m pip install pyinstaller
py deploy\build_standalone.py
```
Produces `dist\jocky-agent-windows.exe` plus its SHA-256 build manifest.

Copy only the resulting executable to the target machine. The target does not
need Python installed. The dashboard's **⊞ Windows agent** and **🐧 Linux agent**
buttons download these single-file artifacts directly from `dist/`.

Each build receives a fresh UUID/timestamp build identity embedded in the
agent, so builds are byte-distinct and their SHA-256 values can be tracked.
This is provenance/traceability and does not disable or bypass security tools.

## Dashboard — Single-File Agent Deployment

The dashboard contains only two platform buttons: `⊞ Windows agent` and `🐧 Linux agent`.
Click either button to open the Single-File Agents panel. Existing native binaries can
be downloaded directly; a missing binary can be generated from the dashboard when the
server is running on the matching native OS. A native Windows PE still requires a
Windows build host and a native Linux ELF requires a Linux build host.

## Default DFIR Gateway Login

- Username: `INV-9042-FED`
- Password: `JOCKY-DFIR-2026`
- MFA/OTP: `000000`

These are development/demo defaults. Change them in `.env` before real deployment.
