"""
TINY MONITOR — Database Module
Thread-safe SQLite database manager with schema migrations, foreign keys, and dictionary rows.
"""

import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from app.config import Config


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Create and return a configured SQLite connection with foreign keys enabled."""
    target_path = db_path or Config.DB_PATH
    conn = sqlite3.connect(str(target_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[Path] = None):
    """Initialize database tables, indices, and constraints idempotently."""
    Config.ensure_directories()
    conn = get_db_connection(db_path)
    try:
        with conn:
            # 1. Cases table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_number TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    severity TEXT NOT NULL DEFAULT 'MEDIUM',
                    investigator TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                );
            """)

            # 2. Evidence table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    mime_type TEXT,
                    acquired_by TEXT NOT NULL,
                    acquisition_date TEXT NOT NULL,
                    description TEXT,
                    last_verified_at TEXT,
                    integrity_status TEXT NOT NULL DEFAULT 'UNVERIFIED',
                    verification_notes TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
            """)

            # 3. Threat Intelligence Lookups (TinyFish Search Results)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_lookups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER,
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    query TEXT NOT NULL,
                    purpose TEXT,
                    status TEXT NOT NULL,
                    results_count INTEGER NOT NULL DEFAULT 0,
                    results_json TEXT,
                    error_message TEXT,
                    investigator TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
                );
            """)

            # 4. Timeline Events (Audit Trail)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS timeline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER,
                    event_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata_json TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
            """)

            # 5. Investigation Notes
            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigation_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    author TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
            """)

            # 6. Integrity Audit Log
            conn.execute("""
                CREATE TABLE IF NOT EXISTS integrity_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL,
                    case_id INTEGER NOT NULL,
                    expected_hash TEXT NOT NULL,
                    calculated_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    verified_by TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    details TEXT,
                    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
                    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
            """)

            # Create Indexes for fast lookup
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(sha256_hash);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_case ON threat_intel_lookups(case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threat_intel_lookups(indicator);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_case ON timeline_events(case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_events(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_case ON investigation_notes(case_id);")
    finally:
        conn.close()


def utc_now_iso() -> str:
    """Return current UTC timestamp in standardized ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()
