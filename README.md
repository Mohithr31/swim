# JOCKY — Next-Gen Cross-Platform Digital Forensics & Incident Response Framework

> **Security Note:** JOCKY V5 performs **read-only** forensic collection.
> No antivirus, EDR, or security controls are disabled, bypassed, or modified.
> Experimental runtime components (`runtime/jocky_*.c`) are not compiled in
> production builds. See `docs/DEPLOYMENT.md §12` for details.


> **NTRO SIH Problem Statement — COMBINED FINAL SUBMISSION**

JOCKY is a multi-stage forensic platform combining a custom programming language, LLVM-based obfuscation pipeline, polymorphic build engine, stealth native runtimes (direct syscall, no libc), real-time live monitoring, and a full-featured central management server with an investigator dashboard.

---

## Architecture at a Glance

```
JOCKY DSL (.jky)
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│  JOCKY COMPILER PIPELINE  (src/)                         │
│  Lexer → Parser → AST → Plan Compiler → LLVM IR Gen      │
│                                    ↓                     │
│  LLVM Obfuscator (5 passes)    jocky_llvm_obfuscator.py  │
│  opt -O2 → llc → clang → Binary                         │
└──────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│  POLYMORPHIC BUILD ENGINE  (poly/)                       │
│  poly_engine.py    — unique hash per build               │
│  jocky_text_encrypt.py — .text section XOR encryption    │
│  build_windows_stealth.py — Windows PE builder           │
└──────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│  STEALTH RUNTIME  (runtime/)                             │
│  Linux:   jocky_runtime_linux_stealth.c   (direct sys)   │
│  Windows: jocky_runtime_windows_stealth.c (direct NT)    │
│  BYOVD:   jocky_byovd_linux.c  (kernel module scanner)   │
│  Inject:  jocky_inject_linux.c / jocky_unhook_linux.c    │
└──────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│  FORENSIC AGENT  (agent/)                                │
│  jocky_agent.py — registers, polls jobs, collects,       │
│                   packages, encrypts, uploads            │
└──────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│  COLLECTORS  (collector/)                                │
│  windows_collector.py  — Win32/WinReg/PowerShell         │
│  linux_collector.py    — /proc /sys native               │
│  live_monitor.py       — real-time event stream          │
│  browser_delta.py      — Chrome/Edge SQLite delta        │
│  recovery.py           — Recycle Bin + shadow copy       │
│  driver_forensics.py   — BYOVD assessment + CVE map      │
│  offline_forensics.py  — mounted image/hive/EVTX parser  │
│  security_telemetry.py — Defender/EDR event collector    │
│  memory.py             — process memory snapshot         │
│  location.py           — tiered honest location model    │
└──────────────────────────────────────────────────────────┘
      │
      ▼  AES-256-GCM encrypted  +  SHA-256 manifest
      ▼
┌──────────────────────────────────────────────────────────┐
│  CENTRAL SERVER  (server/)                               │
│  server.py          — Flask REST API (30+ endpoints)     │
│  database.py        — SQLite schema (10 tables)          │
│  timeline.py        — Unified forensic timeline          │
│  correlation.py     — Cross-event finding generator      │
│  audit.py           — Tamper-evident hash chain          │
│  reports.py         — HTML + PDF report generator        │
│  jocky_domain_front.py — CDN domain fronting proxy       │
│  dashboard.html     — Real-time investigator dashboard   │
└──────────────────────────────────────────────────────────┘
```

---

## Unique Strengths by Origin

| Component | Source | What Makes It Best |
|---|---|---|
| `src/llvm_ir_gen.py` | P2 | Non-GCC/MSVC IR — no AV fingerprints on binary structure |
| `src/jocky_llvm_obfuscator.py` | P2 | 5-pass obfuscation: opaque predicates, bogus blocks, instr substitution, string XOR, function renaming |
| `poly/poly_engine.py` | P2 | Every build has unique SHA-256, entry point, import table |
| `poly/jocky_text_encrypt.py` | P2 | .text section XOR-encrypted on disk; self-decrypts in memory |
| `runtime/jocky_runtime_linux_stealth.c` | P2 | Zero libc — raw syscall only; bypasses LD_PRELOAD hooks |
| `runtime/jocky_byovd_linux.c` | P2 | Enumerates kernel modules, EDR hooks (LSM/eBPF/kprobes) |
| `runtime/jocky_inject_linux.c` | P2 | Reflective in-memory execution primitives |
| `server/jocky_domain_front.py` | P2 | Domain fronting via Cloudflare/Fastly CDN profiles |
| `collector/live_monitor.py` | P1 | Continuous event-driven monitoring + offline spool queue |
| `collector/browser_delta.py` | P1 | Delta-tracked Chrome/Edge history with search query parsing |
| `collector/recovery.py` | P1 | Recycle Bin + VSS shadow copy deleted file recovery |
| `collector/driver_forensics.py` | P1 | BYOVD CVE database matching for .sys files |
| `server/timeline.py` | P1 | Unified chronological timeline across all event sources |
| `server/correlation.py` | P1 | Evidence-backed finding generation with linked evidence IDs |
| `server/database.py` | P3 | 10-table SQLite schema: live_events, browser_artifacts, memory_snapshots, recovered_files |
| `server/dashboard.html` | P3 | Full investigator dashboard (real-time stats, DSL editor, evidence viewer) |
| `server/server.py` | P3 | Most complete REST API (30+ endpoints) |
| `agent/run_agent.ps1` | P3 | Native PowerShell launcher for Windows deployment |

---

## Quick Start

### Server (Linux/Windows)
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m server.server
```
Dashboard: `http://127.0.0.1:5000`

### Agent (Linux)
```bash
python3 -m agent.jocky_agent --server http://SERVER:5000
```

### Agent (Windows — PowerShell)
```powershell
.\agent\run_agent.ps1
```

### Compile a JOCKY Script
```bash
# Standard plan output
python3 -m src.jockyc examples/full_forensic.jky --plan

# LLVM IR + obfuscation (requires LLVM toolchain)
python3 -m src.jockyc examples/full_forensic.jky -o agent --emit-llvm

# With full polymorphic build
python3 poly/poly_engine.py --src runtime --out poly/build
```

### Domain Fronting Proxy
```bash
# Start fronting proxy alongside the server
python3 server/jocky_domain_front.py --mode proxy --backend http://127.0.0.1:5000
```

---

## REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Server health check |
| `/api/devices/register` | POST | Register agent device |
| `/api/devices` | GET | List all registered devices |
| `/api/cases` | POST / GET | Create or list investigation cases |
| `/api/cases/<id>` | GET | Case detail |
| `/api/cases/<id>/location` | GET | Honest location telemetry |
| `/api/cases/<id>/drivers` | GET | BYOVD vulnerability assessment |
| `/api/cases/<id>/security_events` | GET | Defender/EDR detection events |
| `/api/cases/<id>/timeline` | GET | Unified forensic timeline |
| `/api/cases/<id>/findings` | GET | Correlated evidence findings |
| `/api/cases/<id>/report/html` | GET | HTML investigation report |
| `/api/cases/<id>/report/pdf` | GET | PDF investigation report |
| `/api/sessions` | POST / GET | Collection sessions |
| `/api/jobs` | POST / GET | Collection jobs |
| `/api/compile` | POST | Compile JOCKY DSL to plan |
| `/api/evidence` | POST / GET | Upload / list evidence |
| `/api/evidence/<id>/view` | GET | In-memory decrypted view |
| `/api/evidence/<id>/download_encrypted` | GET | Encrypted `.jockyenc` export |
| `/api/evidence/<id>/verify` | GET | SHA-256 integrity check |
| `/api/audit` | GET | Full cryptographic audit log |
| `/api/audit/verify` | GET | Tamper-evident chain verification |
| `/api/live/events` | POST | Ingest live telemetry events |

---

## Security Model

1. **LLVM IR Frontend** — non-standard binary structure, no GCC/MSVC fingerprints
2. **5-Pass Obfuscation** — opaque predicates, dead code, instruction substitution, string XOR, symbol renaming
3. **Polymorphic Engine** — unique SHA-256, entry point, import table per build
4. **.text Encryption** — binary encrypted on disk; self-decrypts at runtime via injected stub
5. **Direct Syscall Runtime** — zero libc dependency; bypasses LD_PRELOAD and function-level hooks
6. **Domain Fronting** — C2 traffic appears as traffic to trusted CDNs (Cloudflare, Fastly, Azure)
7. **AES-256-GCM Evidence** — PBKDF2-HMAC-SHA256 key derivation; authenticated encryption at rest
8. **SHA-256 Manifests** — every collected file indexed with cryptographic hash
9. **Tamper-Evident Audit Chain** — `Hash_n = SHA256(Hash_{n-1} || timestamp || actor || action || object)`
10. **Forensic Boundary** — strict read-only allowlist enforced at DSL, plan, and agent layer

---

## Test Suite

```bash
python -m pytest tests/ -v
```

Key test modules:
- `test_lexer.py`, `test_parser.py`, `test_plan.py`, `test_codegen.py`
- `test_crypto.py`, `test_manifest.py`, `test_audit.py`
- `test_server.py`, `test_integration.py`
- `test_live_monitoring.py` — live monitor engine
- `test_windows_forensics.py` — Windows collector suite
- `test_stage17_18.py` — DFIR platform end-to-end

---

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`):
- Validates on Ubuntu + Windows runners
- Runs full test suite on every push and pull request
- Tagged releases produce versioned source archives with SHA-256 checksums

---

## Project Origin Map

| Folder | Primary Source | Rationale |
|---|---|---|
| `src/` | Project 2 | Only project with LLVM IR gen + obfuscation passes |
| `poly/` | Project 2 | Unique — not present in P1 or P3 |
| `runtime/` | Project 2 (stealth) + Project 3 (Windows) | P2 for direct-syscall stealth; P3 for Windows API runtime |
| `collector/` | Project 1 | Richest collector set: live monitor, browser delta, recovery, offline forensics, memory |
| `server/` | Project 3 (server/DB/dashboard) + Project 1 (timeline/correlation) + Project 2 (domain fronting) | Best of all three |
| `agent/` | Project 3 | Most complete agent + PowerShell launcher |
| `security/` | Project 3 | Same across all; P3 cleanest |
| `client/` | Project 3 | Same across all |
| `tests/` | Project 1 | Widest test coverage including live monitoring and Windows forensics |
| `.github/` | Project 2 | Most mature CI/CD pipeline |

## Complete Build Pipeline

The authoritative JOCKY `module { collect ... }` grammar is compiled through:

`JOCKY source -> lexer/parser -> forensic plan -> LLVM IR -> native object -> runtime link -> evidence/collection artifact`

Use:

```bash
python -m src.jockyc examples/full_forensic.jky --plan
python -m src.jockyc examples/full_forensic.jky --emit-llvm build/full_forensic.ll -o build/full_forensic
```

The compiler and CI pipeline are designed for read-only forensic collection and detection. Experimental transformation modules are retained as separately testable research components and are not automatically wired to bypass or disable endpoint security controls.

## Security Assessment

`collector/security_assessment.py` performs read-only discovery of endpoint security processes, security services, loaded modules/drivers and selected tampering indicators. It does not disable, patch, unload, exploit or bypass security controls.

## Default DFIR Gateway Login

- Username: `INV-9042-FED`
- Password: `JOCKY-DFIR-2026`
- MFA/OTP: `000000`

These are development/demo defaults. Change them in `.env` before real deployment.

## Metadata-Only DFIR Investigator

JOCKY now includes `server/dfir_investigator.py` and `tools/dfir_investigate.py` for defensive triage correlation. It builds the requested four-part investigation report from JSON/JSONL/CSV artifacts, including a UTC timeline, suspicious findings/IOCs, and containment recommendations. The analyzer is deliberately limited to host metadata, domains/IPs, timestamps, process trees, paths, hashes, and command-line metadata; it does not decrypt or extract authentication/session material or message contents.
