# Tiny Monitor

> **TinyFish-Powered Digital Forensics & Incident Response (DFIR) Platform**  
> *Developed for the Swim with TinyFish Hackathon — Presidency University, Bengaluru*

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%20%7C%20Vanilla%20JS-success.svg)](https://flask.palletsprojects.com/)
[![Threat Intel](https://img.shields.io/badge/threat__intel-TinyFish%20Search%20API-00f0ff.svg)](https://docs.tinyfish.ai/)
[![Security](https://img.shields.io/badge/integrity-SHA--256%20Cryptographic%20Proof-orange.svg)]()
[![Event](https://img.shields.io/badge/hackathon-Swim%20with%20TinyFish%20%40%20Presidency%20University-blueviolet.svg)]()

---

## Table of Contents

- [Overview](#overview)
- [The Problem Tiny Monitor Solves](#the-problem-tiny-monitor-solves)
- [Architecture & Technical Design](#architecture--technical-design)
- [Key Features](#key-features)
- [TinyFish Threat Intelligence Integration](#tinyfish-threat-intelligence-integration)
- [Digital Evidence & Cryptographic Integrity](#digital-evidence--cryptographic-integrity)
- [Forensic Reporting](#forensic-reporting)
- [Security & Privacy Safeguards](#security--privacy-safeguards)
- [Installation & Quick Start](#installation--quick-start)
- [Running the Endpoint Agents](#running-the-endpoint-agents)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Hackathon Live Demonstration Script](#hackathon-live-demonstration-script)

---

## Overview

**Tiny Monitor** is an enterprise-grade, investigator-controlled Digital Forensics and Incident Response (DFIR) platform. It merges deep cross-platform endpoint artifact triage (Windows and Linux) with live external threat intelligence powered by the **TinyFish Search API**, all scoped strictly to active forensic cases.

Every suspicious artifact discovered during an endpoint investigation—whether an outbound beacon IP, malicious domain, downloaded executable hash, or CVE exploit string—can be instantly verified, researched through TinyFish in real time, correlated with MITRE ATT&CK techniques, and compiled into court-admissible forensic dossiers.

---

## The Problem Tiny Monitor Solves

In traditional incident response investigations, forensic analysts face severe fragmentation:
1. **Tool Sprawl**: Analysts must toggle between raw command-line forensic extractors, SQLite viewers, manual file-hashing tools, and separate web search engines.
2. **Context Switching & Provenance Loss**: Evidence gathered from endpoints is often researched manually in web browsers, disconnecting external threat intelligence findings from the formal chain of custody.
3. **Fabricated or Stale Threat Intelligence**: Many SOC tools rely on static local lists or simulated risk scores rather than live, verified threat intelligence with authentic source attribution.
4. **Evidence Tampering Risks**: Raw disk and memory evidence must remain bit-for-bit pristine with automated cryptographic validation to ensure legal admissibility.

**Tiny Monitor bridges this gap** by combining:
- Automated host artifact extraction across 12 forensic domains (B1–B12).
- Bit-preserving digital evidence intake with real-time SHA-256 fingerprinting.
- Live, authenticated threat intelligence lookups directly through **TinyFish**.
- Cryptographically chained audit logging and multi-format forensic reporting.

---

## Architecture & Technical Design

Tiny Monitor follows a centralized Server and lightweight Endpoint Agent architecture:

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    TINY MONITOR INVESTIGATOR CONSOLE                   │
 │       (Cyber SOC Dark Theme · Responsive HTML5 / JS · Real-time)       │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTPS / REST API
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                         TINY MONITOR SERVER API                        │
 │                                                                        │
 │  ┌───────────────────────┐ ┌──────────────────────┐ ┌────────────────┐ │
 │  │ Case & Session Mgmt   │ │ Evidence Vault &     │ │ Timeline &     │ │
 │  │ (Strict Scope Control)│ │ SHA-256 Verification │ │ Audit Chain    │ │
 │  └───────────────────────┘ └──────────────────────┘ └────────────────┘ │
 │                                                                        │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │        TINYFISH THREAT INTELLIGENCE ENGINE                       │  │
 │  │  • Strict SSRF & Indicator Validation (IPv4, IPv6, Domain, CVE)  │  │
 │  │  • Authenticated REST Client (Bearer sk-tinyfish-...)            │  │
 │  │  • External Provenance Attribution (Source URL, Title, Snippet)   │  │
 │  │  • Credential Redaction & Security Health Status                  │  │
 │  └─────────────────────────────────┬────────────────────────────────┘  │
 └────────────────────────────────────┼───────────────────────────────────┘
                                      │
                                      ▼
               ┌──────────────────────────────────────────────┐
               │         TINYFISH SEARCH API CLOUD            │
               │        https://api.search.tinyfish.ai        │
               └──────────────────────────────────────────────┘
```

### Core Architecture Components:
- **Investigator Console (`server/dashboard.html`)**: Single-page application built with modern dark Cyber SOC aesthetics (`#080c14` navy, `#00f0ff` cyan, `#ff6b35` orange highlight). Provides 7 primary workspace views plus deep telemetry panels.
- **REST Server (`server/server.py`)**: Flask-powered application implementing secure routing, parameterized SQLite operations, role-based investigator actions, and multi-format report generation.
- **TinyFish Service (`server/tinyfish_service.py`)**: Dedicated integration layer handling indicator normalization, external HTTP communication with TinyFish, error recovery, and secret redaction.
- **Evidence Vault (`server/evidence.py`)**: Secure physical evidence storage maintaining file byte preservation, SHA-256 integrity calculation, and automated verification.
- **Audit Chain (`server/audit.py`)**: Tamper-evident cryptographic ledger where each investigator action is hashed with the previous event hash (`prev_hash` $\to$ `curr_hash`).

---

## Key Features

### 1. Unified Case Management
- Create, track, update, and close forensic cases.
- Case-scoped filtering: every piece of evidence, investigator note, timeline entry, and intelligence lookup is bound to a case ID.
- Dynamic status tracking (OPEN, IN_PROGRESS, CLOSED) and severity levels (CRITICAL, HIGH, MEDIUM, LOW).

### 2. Digital Evidence Vault with SHA-256 Verification
- Direct intake of forensic files (packet captures, memory dumps, disk images, log files).
- Instant SHA-256 calculation upon upload.
- One-click **Verify Hash** action: calculates current on-disk hash against stored fingerprint to guarantee bit-for-bit authenticity.
- Verification history log recorded to the tamper-evident audit chain.

### 3. TinyFish Threat Intelligence Console
- Real-time indicator analysis for **Domains, IPv4, IPv6, URLs, CVEs, and cryptographic file hashes (MD5, SHA-1, SHA-256)**.
- Query categories: All, Threat Actor, Malware Family, Infrastructure, CVE Exploit, and Incident Report.
- Direct association with the active case.
- Persisted lookup history with full source attribution.

### 4. Deep Endpoint Artifact Extraction (B1–B12)
- **B1**: Browser History, Cookies, Downloads, Saved Logins.
- **B2**: Installed Applications & Package Inventories.
- **B3**: Running Processes, Tree Hierarchies, Memory Maps, Thread Lists.
- **B4**: Connected USB / Removable Media & File Access Logs.
- **B5**: Network Interfaces, Active Connections, Listening Ports, ARP Tables.
- **B6**: Filesystem Directory Traversal, Hex Inspection, File Metadata.
- **B7**: Live OS Events & Endpoint Monitoring Streams.
- **B8**: Email & Local Messaging Client Forensics.
- **B9**: System Hardware & OS Posture Specifications.
- **B10**: Autopsy Extension Mismatch & Suspicious Artifact Detectors.
- **B11**: Geolocation & Network Telemetry.
- **B12**: Tamper-Evident System Audit Trail.

### 5. Multi-Format Forensic Reporting
- **Standalone HTML Report**: Self-contained single-file dossier with embedded `@media print` CSS, ready for print/export.
- **Structured JSON Export**: Machine-readable format conforming to standard DFIR data schemas.
- **PDF Report**: Formatted investigative summary with chain of custody notice.
- **Standardized ZIP Evidence Package**: Complete legal archive containing evidence files, manifest.json, hashes, and timeline.

---

## TinyFish Threat Intelligence Integration

Tiny Monitor integrates with the official **TinyFish Search API** (`https://api.search.tinyfish.ai`) to provide investigators with live, actionable cyber threat intelligence.

### Complete Request & Validation Flow:
```text
[Investigator Console]
        │ 1. Submits Indicator (e.g. "github.com", "8.8.8.8", "CVE-2024-1234")
        ▼
[Tiny Monitor Backend (/api/threat-intel/research)]
        │ 2. Strict Input Validation & Normalization
        │    - Blocks private IP ranges (10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8)
        │    - Blocks link-local (169.254.0.0/16) and multicast addresses
        │    - Validates domain structure and RFC-compliant URL schemes
        ▼
[TinyFish REST Client (server/tinyfish_service.py)]
        │ 3. Dispatches HTTPS Request with Bearer API Key
        ▼
[TinyFish Cloud API (https://api.search.tinyfish.ai/v1/search)]
        │ 4. Executes Search & Returns Contextual Security Intelligence
        ▼
[Response Normalization & Provenance Capture]
        │ 5. Parses title, source URL, snippet, publication date
        │ 6. Persists finding to database under active case ID
        │ 7. Logs event to cryptographic audit chain
        ▼
[Investigator Console Display]
        │ 8. Displays verified sources, MITRE ATT&CK mapping, and lead badges
```

### Credential Protection & Compromised Key Recovery:
- The API key is stored securely on the server via `.env` (`TINYFISH_API_KEY`) and is **never** sent to the client browser.
- The `/api/threat-intel/status` endpoint reports system health, key configuration status, and a securely redacted preview (e.g., `sk-tinyfish-...8Q`), preventing credential leakage.
- Automatic revocation checking detects known compromised or placeholder keys (`REVOKED_KEYS`), alerting the investigator to configure a valid rotated key.

---

## Digital Evidence & Cryptographic Integrity

Admissibility in legal and regulatory proceedings requires strict chain of custody and bit-level integrity:

1. **Intake Fingerprinting**: As soon as evidence is uploaded through the console or collected via the endpoint agent, Tiny Monitor computes its SHA-256 hash using streaming chunked hashing (`hashlib.sha256()`).
2. **Metadata Binding**: The file size, original filename, ingest timestamp, and SHA-256 fingerprint are recorded in the `evidence` SQLite table.
3. **On-Demand Cryptographic Verification**: Investigators can trigger the `/api/evidence/<id>/verify` endpoint at any time. Tiny Monitor re-reads the raw archive file from disk, calculates the live hash, and compares it to the original stored hash:
   - **MATCH**: Returns `status: "VERIFIED"`, confirms bit preservation.
   - **MISMATCH**: Flags evidence tampering immediately.
4. **Audit Chain Logging**: Every verification event is appended to the tamper-evident audit ledger with the investigator's identifier and timestamp.

---

## Forensic Reporting

Tiny Monitor generates comprehensive, court-admissible forensic reports in four standard formats:

| Format | Endpoint | Purpose |
| :--- | :--- | :--- |
| **Printable HTML Dossier** | `GET /api/reports/html?case_id=<id>` | Self-contained, styled HTML report with executive summary, evidence tables, threat intelligence findings, and print CSS. |
| **Structured JSON** | `GET /api/reports/json?case_id=<id>` | Machine-readable dump of all normalized findings, MITRE ATT&CK mappings, and timeline events for SIEM/SOAR ingestion. |
| **PDF Summary** | `GET /api/reports/pdf?case_id=<id>` | Formal PDF document suitable for executive and legal briefing. |
| **ZIP Evidence Package** | `GET /api/reports/package?case_id=<id>` | Court-admissible ZIP bundle containing `manifest.json`, `SHA256SUMS`, SQLite evidence database, and original artifacts. |

---

## Security & Privacy Safeguards

Tiny Monitor is built strictly for **authorized defensive cybersecurity and digital forensics**:
- **Zero Sensitive Data Transmission**: Private host evidence files (disk images, packet captures, email databases) are **never** transmitted to TinyFish. Only the specific public indicator (e.g. domain, public IP, hash) is sent for external research.
- **SSRF Prevention**: All indicator inputs are validated against internal network boundaries, loopbacks, link-local addresses, and malicious URL schemes.
- **Read-Only Forensic Access**: Endpoint collectors and filesystem viewers operate in non-destructive read-only modes to prevent evidence alteration.
- **Credential Hygiene**: Production secrets, Flask session keys, and API tokens are loaded exclusively from `.env` and are strictly excluded from git tracking via `.gitignore`.

---

## Installation & Quick Start

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/Pratham-16/Z3r0_T34c3_01.git
cd Z3r0_T34c3_01
```

### 2. Set Up Virtual Environment & Dependencies
**On Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy the template and configure your parameters:
```bash
cp .env.example .env
```

Ensure `.env` contains:
```ini
TINYFISH_API_KEY=sk-tinyfish-your-api-key-here
JOCKY_PORT=5000
JOCKY_DB=jocky_forensics.db
JOCKY_SECRET_KEY=change-this-to-a-secure-random-key-in-production
```

### 4. Launch Tiny Monitor
**Using startup scripts:**
- Windows: Double-click or run `run_server.bat`
- Linux: Run `chmod +x run_server.sh && ./run_server.sh`

**Or using Python directly:**
```bash
python -m server.server
```

Open your browser to: **`http://localhost:5000`**

---

## Running the Endpoint Agents

To collect telemetry from remote or local endpoints:

### Windows Agent
```powershell
python -m agent.jocky_agent --server http://localhost:5000 --case CASE_001
```

### Linux Agent
```bash
python3 -m agent.jocky_agent --server http://localhost:5000 --case CASE_001
```

---

## Testing & Quality Assurance

Tiny Monitor maintains a comprehensive automated test suite covering unit, functional, cryptographic, and end-to-end scenarios.

### Run All Unit and Mocked Tests:
```bash
python -m pytest tests/ -v
```

### Run Tiny Monitor End-to-End Suite:
```bash
python -m pytest tests/test_tiny_monitor_e2e.py -v
```

### Run Live TinyFish Integration Test (Opt-in with real key):
```bash
python -m pytest tests/test_live_tinyfish.py -v
```

---

## Hackathon Live Demonstration Script

Follow this 5-minute workflow to demonstrate Tiny Monitor to judges and attendees at the **Swim with TinyFish** hackathon:

### Step 1: Open the Dashboard & Verify Live Status
1. Navigate to `http://localhost:5000`.
2. Direct attention to the top navigation bar:
   - **Product Identity**: *Tiny Monitor — TinyFish-Powered DFIR*.
   - **Event Label**: *Swim with TinyFish — Presidency University*.
   - **Connection Indicator**: The **TinyFish Connected** badge glows cyan, confirming live communication with the TinyFish cloud API.
3. Review the **Overview** dashboard displaying genuine case metrics, evidence count, and integrity statistics.

### Step 2: Create a Forensic Investigation Case
1. Click **+ New Case** in the top bar or sidebar.
2. Enter:
   - **Case Name**: `Operation Arctic Beacon — Endpoint Breach`
   - **Description**: `Investigation of unauthorized command-and-control beaconing and exfiltration.`
   - **Severity**: `CRITICAL`
   - **Investigator**: `SOC Analyst — Presidency University`
3. Click **Create Case**. Notice that all views instantly scope to this newly active case.

### Step 3: Ingest Digital Evidence & Verify SHA-256 Integrity
1. Navigate to **Digital Evidence** in the sidebar.
2. In the **Ingest Evidence File** card, select a file (e.g. sample network capture or log file).
3. Click **Upload Evidence Archive**.
4. The file is uploaded, preserved, and immediately displayed in the **Digital Evidence Vault** with its calculated **SHA-256 fingerprint**.
5. Click the **Verify Hash** button next to the evidence record:
   - The backend re-reads the bytes from disk in real time.
   - The status badge flashes **INTEGRITY VERIFIED (SHA-256 MATCH)**.
   - A cryptographic record is added to the tamper-evident audit ledger.

### Step 4: Research a Suspicious Indicator using TinyFish
1. Navigate to **Threat Intelligence** in the sidebar.
2. Notice the live **Threat Intelligence Console**:
   - Indicator input field with automatic type detection.
   - TinyFish connection status badge.
3. Enter a suspicious indicator (e.g., `8.8.8.8`, `github.com`, or `CVE-2024-3094`).
4. Select category: `Infrastructure / C2` or `Malware Family`.
5. Enter Research Purpose: `Investigating outbound command-and-control beaconing`.
6. Click **Execute TinyFish Query**:
   - A pulsing cyber loading indicator appears while the request is securely processed.
   - The live results populate with **Source Title**, **Authentic URL**, **Contextual Intelligence Snippet**, and **Retrieval Timestamp**.
7. Click **Save Finding to Case**:
   - Map to MITRE ATT&CK technique (e.g., `T1071.001 - Web Protocols`).
   - The finding is permanently bound to the active investigation case.

### Step 5: Review Chronological Timeline & Audit Trail
1. Navigate to **Investigation Timeline**:
   - Observe the unified timeline displaying case creation, evidence ingest, hash verification, and the TinyFish threat lookup in exact chronological order.
2. Open **System Logs & Audit** (under Deep Telemetry) to showcase the cryptographic hash chain (`prev_hash` $\to$ `curr_hash`) guaranteeing non-repudiation.

### Step 6: Generate Court-Admissible Forensic Dossier
1. Navigate to **Forensic Reports**.
2. Click **Open in New Tab** on the **Standalone HTML Forensic Report** card:
   - A complete forensic dossier opens with official executive summary, chain of custody verification, SHA-256 table, TinyFish external intelligence citations, and investigator sign-off blocks.
3. Demonstrate the **Download Structured JSON** and **Download Evidence ZIP Package** options for SIEM integration and formal court submission.

---

## License & Credits

Developed for the **Swim with TinyFish Hackathon** at **Presidency University, Bengaluru**.  
Powered by the **TinyFish Search API** ([https://tinyfish.ai](https://tinyfish.ai)).
