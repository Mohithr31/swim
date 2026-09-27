# JOCKY Architecture & Security Design — Stage 17/18 DFIR Platform

JOCKY is an authorized, closed, allowlisted Digital Forensics & Incident Response (DFIR) collection and investigation platform.

## System Architecture

```mermaid
flowchart TD
    DSL["JOCKY DSL Script (.jky)"] --> Lexer["Lexer (lexer.py)"]
    Lexer --> Parser["Parser (parser.py)"]
    Parser --> AST["AST Nodes (ast_nodes.py)"]
    AST --> Compiler["Plan Compiler (plan.py)"]
    Compiler --> Plan["Closed Forensic Plan (JSON + SHA256)"]
    Plan --> Agent["JOCKY Agent (jocky_agent.py)"]
    Agent --> Collect["Read-Only Forensic Collectors (collector/)"]
    
    subgraph Collectors ["Forensic Telemetry Modules"]
        Collect --> Device["Device & User Profile"]
        Collect --> Location["Honest Location Model (location.py)"]
        Collect --> Drivers["Driver BYOVD Assessment (driver_forensics.py)"]
        Collect --> Defender["Defender/EDR Events (security_telemetry.py)"]
        Collect --> Offline["Offline Image Parser (offline_forensics.py)"]
    end
    
    Collect --> Package["Evidence Packaging (archive.tar.gz)"]
    Package --> Hash["SHA-256 Manifest (manifest.py)"]
    Hash --> Encrypt["AES-256-GCM Encryption (evidence_crypto.py)"]
    Encrypt --> Server["Central Server (server.py)"]
    Server --> DB["SQLite Database (jocky_forensics.db)"]
    Server --> Audit["Cryptographic Audit Chain (audit.py)"]
    Server --> Timeline["Unified Timeline (timeline.py)"]
    Timeline --> Correlation["Correlation Engine (correlation.py)"]
    Correlation --> Dashboard["Investigator Dashboard (dashboard.html)"]
    Dashboard --> Viewer["Secure Evidence Viewer (In-Memory Decryption)"]
    Server --> Report["HTML & PDF Reports (reports.py)"]
```

## Case Architecture & Evidence Flow

```mermaid
flowchart LR
    Case["Case (Investigation)"] --> Session1["Session: Endpoint Triage"]
    Case --> Session2["Session: Offline Artifact Analysis"]
    Session1 --> Job1["Job: Live Endpoint Sweep"]
    Job1 --> Evidence1["Encrypted Evidence Archive (.jockyenc)"]
    Evidence1 --> SHA256["SHA-256 Verification"]
    SHA256 --> Storage["Encrypted Storage at Rest"]
    Storage --> View["In-Memory Decryption for Viewer"]
    Storage --> Export["Encrypted Export Package"]
```

## Security Boundaries & Forensics Principles

1. **No Security-Control Bypass**: JOCKY does not disable Windows Defender, EDRs, or security logging. Detections are recorded and preserved as evidence.
2. **Read-Only Telemetry**: Enforces read-only collection. No process injection, credential harvesting, LSASS dumping, or kernel driver subversion.
3. **Honest Location Model**: Tiered location model explicitly declaring accuracy, confidence, and disclosure warnings (`EXACT LOCATION: UNAVAILABLE` when GPS is missing).
4. **Driver BYOVD Assessment**: Analyzes digital signatures, publisher metadata, SHA-256 hashes, and known vulnerable driver databases without executing or exploiting drivers.
5. **Chain of Custody**: Cryptographic audit chaining of all investigator actions (`CASE_CREATED`, `COLLECTED`, `HASHED`, `ENCRYPTED`, `VIEWED`, `VERIFIED`, `EXPORTED`).
