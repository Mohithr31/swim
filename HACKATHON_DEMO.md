# JOCKY DFIR / TINY MONITOR — Hackathon Demonstration Guide
**Project:** JOCKY DFIR / Tiny Monitor — Digital Forensics & Incident Response Platform with TinyFish Threat Intelligence  
**Event:** Swim with TinyFish Hackathon • Presidency University, Bengaluru  
**Role:** Senior Full-Stack Cyber Forensics Engineer & Lead Developer  

---

## 1. Quick Start & Prerequisites

### Requirements
- **Python 3.10+** (Developed and verified on Python 3.12 / 3.15)
- Standard dependencies: `flask`, `requests`, `python-dotenv`, `reportlab`, `pillow`, `pytest`

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Configure Environment & Rotate TinyFish Key
Copy `.env.example` to `.env` (which is safely ignored by Git):
```powershell
cp .env.example .env
```
Open `.env` and configure your settings:
```ini
JOCKY_PORT=5000
JOCKY_DB=jocky_forensics.db
JOCKY_EVIDENCE_DIR=evidence

# Cryptographic and Session Security Secrets (auto-generated if empty)
JOCKY_API_KEY=REPLACE_WITH_GENERATED_AGENT_API_KEY

# TinyFish Live Threat Intelligence Search & Fetch API Configuration
TINYFISH_API_KEY=your_tinyfish_api_key_here
```
> **Security Notice:** Server credentials remain strictly server-side and are never passed to client JavaScript. Compromised credentials are permanently rejected by configuration validation.

### Step 3: Run the Automated Test Suite
Run the comprehensive test suite across all 41 test modules:
```bash
python -m pytest tests/ -q
```
*(All 352 test cases pass cleanly with 100% pass rate).*

### Step 4: Launch the Canonical Server
Launch via any of the unified commands:
```powershell
python run.py
# or
.\run_server.bat
# or
.\run_server.ps1
```
Open your browser to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 2. Complete Hackathon Demonstration Script (End-to-End DFIR Workflow)

```
INVESTIGATOR DASHBOARD ──▶ JOCKY SERVER ──▶ PERSISTENT JOB QUEUE ──▶ AUTHORIZED AGENT
          ▲                                                                 │
          │                                                                 ▼
   COURT REPORT  ◀── SHA-256 AUDIT VERIFICATION ◀── SECURE EVIDENCE ◀── READ-ONLY COLLECTION
          ▲
          │
  TINYFISH SEARCH API (Corroborated External Intelligence & SSRF-Defended Fetch)
```

---

### Act 1: Cyber SOC Incident Response Dashboard (Overview)
1. Point out the **Dark Navy / Cyberpunk SOC Aesthetic** tailored with electric cyan, blue, and hackathon orange accents.
2. Note the **Telemetry Badges** at the top right:
   - Live TinyFish API connection status (`Connected & Verified`, or honest status if key is not configured).
   - Zero hardcoded secrets in frontend scripts.
3. Review the **KPI Telemetry**:
   - Total Cases Registered
   - Enrolled Authorized Endpoints
   - Persistent Job Queue Status
   - Preserved Evidence Archives
   - Cryptographic SHA-256 Verification Matches
   - TinyFish Threat Intelligence Lookups

---

### Act 2: Case Intake & Scoping
1. In the sidebar, click **"Cases"** (or click **"+ New Case"** in the top bar).
2. Enter:
   - **Operation / Title:** `Incident Triage - DC01 Cobalt Strike Beaconing`
   - **Severity:** `Critical`
   - **Investigator Badge:** `INV-9042-FED`
   - **Scope Rationale:** `Defensive incident triage and forensic investigation using Tiny Monitor and TinyFish threat intelligence.`
3. Click **"Create & Scope Case"**.
4. The case immediately appears in the database with status `OPEN`. All metrics and banners update instantaneously.

---

### Act 3: Enrolled Endpoints & Agent Health
1. In the sidebar, click **"Enrolled Endpoints"**.
2. Explain JOCKY's cross-platform endpoint agent architecture:
   - Supports both Windows and Linux endpoints.
   - Enrolls via secure device token/API key.
   - Demonstrates agent health, hostname, OS release, and last-seen heartbeat.
3. To attach a live local agent in a secondary terminal:
   ```powershell
   python -m agent.jocky_agent --server http://127.0.0.1:5000
   ```
   The endpoint immediately appears in the **Enrolled Endpoints** table as `ACTIVE` with an alive indicator.

---

### Act 4: Persistent Job Queue & Read-Only Forensic Dispatch
1. Click **"Dispatch Job"** on the enrolled endpoint (or navigate to **"Job Queue & Dispatch"** and click **"+ New Collection Job"**).
2. The Dispatch Modal opens:
   - **Target Endpoint:** Select the enrolled agent.
   - **Case Association:** Select `Incident Triage - DC01`.
   - **Collection Profile:** Select `Process Inventory & Hashes (Read-Only)`.
   - **Scope Notes:** `Investigate unauthorized binary execution in AppData`.
3. Click **"Enqueue Collection Job"**.
4. Walk the judges through the execution safety design:
   - The server compiles a deterministic, read-only collection plan.
   - The job is queued in the database (`PENDING`).
   - The agent polls its assigned queue via `GET /api/agents/<agent_id>/jobs`.
   - The agent validates the plan hash against its strict internal allowlist.
   - The agent executes read-only telemetry collection (never arbitrary shell commands).
   - The agent bundles artifacts into a secure archive and streams it to `POST /api/evidence`.
   - The job completes (`COMPLETED`).

---

### Act 5: Digital Evidence Ingestion & Independent SHA-256 Verification
1. Navigate to **"Digital Evidence"** in the sidebar.
2. Observe the evidence archive uploaded by the agent:
   - Shows Job ID, Size, Upload Timestamp, and Server-Calculated SHA-256.
3. Click **"Verify Hash"**:
   - The server independently re-reads the raw evidence bytes from disk and re-calculates the 64-character SHA-256 hash.
   - The badge updates to an emerald glowing **"VERIFIED (MATCH)"**.
   - Explain the anti-tampering guarantee: any altered byte on disk triggers an immediate **"TAMPERED / MISMATCH"** alert.

---

### Act 6: Live TinyFish Threat Intelligence Research
1. Navigate to **"Threat Intelligence (TinyFish)"** in the sidebar.
2. Enter a suspicious indicator detected during host collection:
   - Domain: `cisa.gov` or `evil-phish.net`
   - IP: `185.220.101.5`
   - Hash: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
3. Click **"Classify Indicator"**:
   - Shows automated indicator type resolution (`domain`, `ipv4`, `sha256`).
   - Formulates a source-grounded threat query.
4. Click **"Execute TinyFish Query"**:
   - The server makes an authenticated, rate-limit-aware request to the official TinyFish REST API (`https://api.search.tinyfish.ai`).
   - Returns authoritative threat intel results with publisher domain, title, URL, snippet, and retrieval timestamp.
   - Ranks results by domain authority (e.g. CISA, CERT, VirusTotal, SANS ISC).
   - Protects against SSRF by blocking RFC 1918 private IP ranges and loopbacks when fetching sources.
   - Automatically associates findings with the active case and records an immutable audit log.

---

### Act 7: Unified Investigation Timeline & Audit Trail
1. Click **"Investigation Timeline"** in the sidebar.
2. Show the judges the unified forensic timeline:
   - `CASE_CREATED`: Initial intake and scoping.
   - `JOB_DISPATCHED`: Persistent job enqueued for agent.
   - `EVIDENCE_ACQUIRED`: Agent evidence archive uploaded.
   - `INTEGRITY_VERIFIED`: Cryptographic SHA-256 verification.
   - `THREAT_INTEL_RESEARCH`: Source-grounded TinyFish leads linked to case.
3. Note that each timeline event preserves original timestamps, source provenance, and actor attribution.

---

### Act 8: Court-Admissible Forensic Dossier Export (PDF & JSON)
1. Click **"Forensic Reports"** in the sidebar.
2. Select the case and click **"Generate Forensic Report"**:
   - Compiles a complete, court-admissible PDF dossier using ReportLab.
   - Contains Executive Summary, Target Endpoint Details, Evidence Manifest with SHA-256 hashes, Integrity Verification History, TinyFish Threat Intelligence Corroboration, and Chronological Timeline.
3. Click **"Download Report"** to view the generated document.

---

### Act 9: Model Context Protocol (MCP) Research Integration
1. Showcase `server/mcp_server.py` and `mcp_config.example.json`.
2. Demonstrate how AI assistants (e.g., Antigravity, Claude Desktop) connect via standard JSON-RPC 2.0 stdio:
   - `jocky_list_cases`: Retrieve active investigation cases.
   - `jocky_get_case_summary`: Inspect case telemetry and artifact counts.
   - `jocky_research_indicator`: Query TinyFish threat intelligence directly from the AI assistant.
   - `jocky_validate_indicator`: Validate and classify indicators.
   - `jocky_list_findings`: Review correlated findings.
3. Reiterate the safety architecture: MCP tools are strictly read-only and cannot trigger arbitrary commands or modify evidence without investigator authorization.

---

## 3. Architecture & Security Highlights for Judges

| Pillar | Implementation in JOCKY / Tiny Monitor |
|---|---|
| **Canonical Server** | Unified Flask architecture (`server/server.py`) serving all 168+ forensic routes, persistent job queue, and WebSocket/REST events. |
| **Endpoint Agent Workflow** | Authenticated agent (`agent/jocky_agent.py`) polling persistent database-backed jobs with allowlisted, read-only collection plans. |
| **Cryptographic Integrity** | Independent server-side streaming SHA-256 calculation; on-demand re-verification detects disk tampering bit-for-bit. |
| **TinyFish Search API** | Direct server-side authenticated integration with `https://api.search.tinyfish.ai` featuring authoritative domain weighting and strict SSRF defenses. |
| **Model Context Protocol** | Read-only JSON-RPC 2.0 MCP server (`server/mcp_server.py`) enabling AI copilots to assist investigation without privilege escalation. |
| **Evidence Soundness** | Complete separation between internal physical/logical endpoint evidence and external threat intelligence leads. |
| **Test Verification** | 352 automated unit and integration tests passing cleanly (100% pass rate). |
