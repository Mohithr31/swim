# TINY MONITOR — MASTER IMPLEMENTATION CHECKLIST
**Event:** Swim with TinyFish — Presidency University  
**Target Environment:** Windows 11, PowerShell, Python 3.12+

---

## Acceptance Checklist Status (7 of 7 Verified)
- [x] **1. One Application Starts Correctly**
  - Canonical server: `python run.py` (serving Tiny Monitor on `http://127.0.0.1:5000/`)
  - Canonical launchers: `run_server.bat` and `run_server.ps1` with virtual environment detection.
  - Health check endpoint `/api/health` reports application, database, and integration health (`status: "healthy"`).
  - Status endpoint `/api/status` returns operational state and event banner without secret leakage.
- [x] **2. Authorized Agent Completes a Real Job**
  - Device enrollment with token, OS metadata, platform specs, and last seen.
  - Job lifecycle: `PENDING` -> `CLAIMED` -> `RUNNING` -> `COMPLETED`.
  - Authorized read-only collection (process inventory, network, system info, logs).
  - Agent polls `/api/agents/<agent_id>/jobs`, validates allowlisted DSL plan, executes collection, packs archive with `manifest.json`, uploads evidence to `/api/evidence`, and reports `COMPLETED`.
- [x] **3. Evidence Integrity Works & Detects Tampering**
  - Server independently computes SHA-256 upon ingestion and records it in `evidence` and `hashes` tables.
  - Verification endpoint `/api/evidence/<id>/verify` recalculates SHA-256 strictly from disk bytes.
  - Tamper detection verified live: 1 byte altered on disk triggers immediate hash mismatch, returning `valid: false, tampered: true, status: "INTEGRITY FAILURE"`.
  - Restoring original byte immediately restores `valid: true, tampered: false, status: "INTEGRITY VERIFIED"`.
- [x] **4. Genuine TinyFish Search & Fetch API Integration**
  - Authoritative service: `server/tinyfish_service.py` querying `https://api.search.tinyfish.ai` with `X-API-Key`.
  - Real structured fields: title, url, snippet, author, score, timestamp.
  - Live status indicator: missing key, unverified, live verified, auth error, rate limited, timeout.
  - Research persistence linked to case with analyst review workflow, saved into `threat_intel_research` and `findings`.
  - SSRF protection against loopback/RFC-1918 IPs and dangerous schemes.
- [x] **5. Real MCP Support Verified**
  - JSON-RPC 2.0 stdio server in `server/mcp_server.py` with valid root `mcp_config.json`.
  - Supported tools: `jocky_list_cases`, `jocky_get_case_summary`, `jocky_research_indicator`, `jocky_list_findings`, `jocky_list_evidence`, `jocky_get_research_history`, `jocky_generate_investigation_summary`.
  - Full test suite `tests/test_mcp_server.py`: 7/7 tests passed.
- [x] **6. Graph, Timeline & Reports Derived from Same Persisted Data**
  - Evidence-to-Context Graph: interactive canvas view and API (`/api/cases/<case_id>/graph` and `/api/graph`) showing Case -> Device -> Job -> Evidence -> Hash -> Intel -> Sources -> Findings, all derived strictly from SQLite relational foreign keys.
  - Chronological Investigation Timeline (`/api/cases/<case_id>/timeline`): real audit, acquisition, job, research events.
  - Downloadable Forensic Reports (HTML, PDF, JSON): executive summary, evidence ledger, TinyFish intelligence, audit chain.
- [x] **7. Security Hardening & Complete Test Verification**
  - No secrets in git, code, or logs; `.env.example` with placeholders only; `.env` protected by `.gitignore`.
  - SSRF protection on URL fetch, safe path sanitization, bounded pagination.
  - Full test suite passing (369 tests across unit, integration, graph, MCP, and E2E acceptance suites).
  - Live acceptance script `tools/test_e2e_acceptance.py`: all 11 criteria verified against running server.

