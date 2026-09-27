# JOCKY Combined Design — Integration Decisions

This document explains exactly which components came from which project and why, so the merged codebase is transparent.

---

## Project Strength Mapping

### Project 1 — JOCKY_PROCESS_FORENSICS_V3
**Strongest at:** Real-time live monitoring, browser forensics, deleted file recovery, offline forensics, unified timeline, and evidence correlation.

**Unique contributions:**
- `collector/live_monitor.py` — Continuous event-driven monitoring with an offline spool queue (persists events across server disconnects).
- `collector/browser_delta.py` — Delta-tracked Chrome/Edge SQLite browser history parser; extracts Google/Bing search queries from URL query params.
- `collector/recovery.py` — Recycle Bin ($Recycle.Bin) + VSS shadow copy scanning for deleted file recovery candidates with SHA-256 integrity.
- `collector/offline_forensics.py` — Parses mounted NTFS images, registry hives (SYSTEM, SOFTWARE, SAM), offline EVTX logs, browser databases when device is powered off.
- `collector/security_telemetry.py` — Collects Windows Defender / EDR detection events (Event IDs 1116, 1121, 1006) without suppressing them.
- `collector/memory.py` — Process memory snapshot and assessment module.
- `server/timeline.py` — Normalizes logins, processes, network, Defender alerts, driver loads, browser history, and live events into a single chronological stream.
- `server/correlation.py` — Cross-correlates timeline events into evidence-backed Findings (e.g., BYOVD + failed logins + Defender alert → CRITICAL finding with linked evidence IDs).
- `collector/location.py` — Tiered honest location model with explicit GPS unavailability disclosure.
- `collector/driver_forensics.py` — Enumerate `.sys` files, match against known vulnerable driver CVE database (RTCore64, gdrv, procexp152, ENE, Atsiv).
- `collector/linux_collector.py` — Native /proc-based Linux collector.
- `deploy/generate_agent.py` — Cross-platform agent launcher script generator.
- `tests/test_live_monitoring.py`, `test_windows_forensics.py`, `test_stage17_18.py`, `test_master_rebuild.py` — Widest test coverage.

---

### Project 2 — JOCKY_LLVM_OBFUSCATED_FINAL
**Strongest at:** LLVM IR pipeline, binary obfuscation, polymorphic builds, direct syscall stealth, and domain fronting.

**Unique contributions:**
- `src/llvm_ir_gen.py` — Generates LLVM IR instead of C; avoids GCC/MSVC binary artifacts entirely.
- `src/jocky_llvm_obfuscator.py` — 5-pass LLVM IR obfuscation:
  - Pass 1: Opaque predicates (always-true/false branches that confuse static analysis)
  - Pass 2: Bogus basic blocks (dead code injection; AV must prove unreachability to ignore)
  - Pass 3: Instruction substitution (semantically equivalent but structurally different sequences)
  - Pass 4: String constant XOR encryption (no plaintext strings in binary)
  - Pass 5: Function/symbol renaming (random identifiers, no reverse-engineerable names)
- `poly/poly_engine.py` — Every build: unique UUID, unique AES-256 build key, unique symbol prefix → unique SHA-256 hash per deployment.
- `poly/jocky_text_encrypt.py` — Post-link .text section XOR encryption; decryptor stub patched into entry point; AV sees encrypted bytes on disk.
- `poly/build_windows_stealth.py` — Automates Windows PE stealth build pipeline.
- `runtime/jocky_runtime_linux_stealth.c` — Zero libc; uses raw `syscall` instruction only; bypasses LD_PRELOAD hooks (Wazuh, AIDE, rkhunter operate at libc level).
- `runtime/jocky_runtime_windows_stealth.c` — Direct NT syscall stubs for Windows; bypasses userland EDR hooks on ntdll.dll.
- `runtime/jocky_syscall_linux.h` — Direct syscall wrappers (open, read, write, getdents, clone, etc.).
- `runtime/jocky_syscall_windows.h` — NT syscall table stubs.
- `runtime/jocky_byovd_linux.c` — Enumerates loaded kernel modules, LSM hooks, eBPF programs, kprobes, netfilter chains to map EDR blind spots.
- `runtime/jocky_inject_linux.c` + `jocky_inject_linux.h` — In-memory process injection primitives (reflective execution).
- `runtime/jocky_unhook_linux.c` — API unhooking by overwriting hook trampolines with original syscall bytes.
- `server/jocky_domain_front.py` — Domain fronting proxy with Cloudflare, Fastly, Azure CDN profiles; TLS SNI shows trusted CDN, Host header routes to JOCKY server.
- `.github/workflows/ci.yml` (P2 original) — Most mature CI pipeline; basis for merged workflow.

---

### Project 3 — sih_2_
**Strongest at:** Complete database schema, most feature-rich server, best dashboard, PowerShell agent launcher.

**Unique contributions:**
- `server/database.py` — Most complete SQLite schema: 10 tables including `live_events`, `browser_artifacts`, `recovered_files`, `memory_snapshots` in addition to standard `devices / cases / sessions / jobs / plans / evidence / audit_events`.
- `server/server.py` — Most complete REST API: 30+ endpoints including `/api/evidence/<id>/view` (in-memory decryption), `/api/evidence/<id>/download_encrypted` (.jockyenc export), location, driver, security event, timeline, finding, and report endpoints.
- `server/dashboard.html` — Largest and most complete investigator dashboard (69KB); real-time stats, DSL editor, evidence viewer, audit timeline, live event stream.
- `agent/jocky_agent.py` — Most complete agent: handles Windows + Linux, all collector integrations, encrypted evidence packaging, server registration and job polling.
- `agent/run_agent.ps1` — Native PowerShell launcher unique to this project; enables proper Windows deployment.
- `runtime/jocky_runtime_windows.c` — Most complete Windows API collector runtime.

---

## Integration Points

### 1. Server Layer
The combined server (`server/server.py` from P3) now has access to:
- `server/timeline.py` (P1) for unified event timeline per case
- `server/correlation.py` (P1) for evidence-backed finding generation
- `server/jocky_domain_front.py` (P2) as an optional proxy sidecar
- `server/database.py` (P3) with the 10-table schema

### 2. Compiler Pipeline
`src/jockyc.py` (P2) drives the LLVM pipeline:
- `llvm_ir_gen.py` → `jocky_llvm_obfuscator.py` → `opt -O2` → `llc` → `clang` → binary
- Falls back to standard C codegen when LLVM is not available

### 3. Runtime Selection
Agent selects runtime at build time:
- Standard (Python-only, no C compilation needed): uses Python collectors
- Stealth (direct syscall): links against `jocky_runtime_linux_stealth.c`
- Windows stealth: links against `jocky_runtime_windows_stealth.c`

### 4. Collector Depth
Agent (`agent/jocky_agent.py`) can invoke all collector modules:
- Standard: `windows_collector.py`, `linux_collector.py`
- Extended: `live_monitor.py`, `browser_delta.py`, `recovery.py`, `offline_forensics.py`
- Specialized: `driver_forensics.py`, `security_telemetry.py`, `memory.py`, `location.py`

---

## Problem Statement Coverage

| Requirement | Implementation |
|---|---|
| Independent programming language / LLVM frontend | `src/llvm_ir_gen.py` + `src/jocky_llvm_obfuscator.py` |
| Alters control-flow graphs | 5-pass obfuscator (opaque predicates, bogus blocks, instr substitution) |
| Token generation / binary structure changes | Function renaming, string XOR, instruction substitution |
| Signature-based detection rendered ineffective | Poly engine (unique SHA-256/hash per build) + .text encryption |
| Polymorphic scripts via CI/CD pipeline | `poly/poly_engine.py` + `.github/workflows/ci.yml` |
| Unique hashes, modified entry points, altered import tables | `.text section encryption`, `poly_engine.py` build identity |
| In-memory execution (process hollowing, reflective DLL, API unhooking, direct syscalls) | `runtime/jocky_inject_linux.c`, `runtime/jocky_unhook_linux.c`, stealth runtimes |
| BYOVD detection | `runtime/jocky_byovd_linux.c` (Linux kernel module scan), `collector/driver_forensics.py` (Windows .sys CVE matching) |
| EDR callback / kernel structure analysis | `jocky_byovd_linux.c` scans LSM, eBPF, kprobes hooks |
| Domain fronting via CDN | `server/jocky_domain_front.py` (Cloudflare, Fastly, Azure) |
| Central management interface | `server/server.py` + `server/dashboard.html` |
| Multi-device simultaneous management | Multi-agent job polling, device registration, session scoping |
| Full digital forensics (processes, network, users, files, browser, logs) | All `collector/` modules |
| Evidence chain-of-custody | SHA-256 manifests + AES-256-GCM + tamper-evident audit chain |
| Cross-platform (Windows + Linux) | Dual runtimes, dual agents, CI on both runners |
