"""
JOCKY Forensic Database — Schema, Access, Backup & Restore

Adds to the original:
  - API-key lifecycle table (creation, expiry, rotation, revocation)
  - SQLite WAL-mode for concurrent readers
  - backup_db() / restore_db() with SHA-256 integrity verification
  - Pagination helpers for large telemetry result sets
  - Stale-device cleanup helper
  - Job timeout helper
"""
import sqlite3
import os
import shutil
import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple

DEFAULT_DB_PATH = os.environ.get("JOCKY_DB", "jocky_forensics.db")
BACKUP_DIR      = os.environ.get("JOCKY_BACKUP_DIR", "backups")


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS devices (
    id         TEXT PRIMARY KEY,
    hostname   TEXT NOT NULL,
    os         TEXT NOT NULL,
    ip_address TEXT,
    status     TEXT DEFAULT 'ACTIVE',
    last_seen  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    created_at  TEXT NOT NULL,
    status      TEXT DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    case_id    TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    plan_hash    TEXT NOT NULL,
    status       TEXT DEFAULT 'PENDING',
    created_at   TEXT NOT NULL,
    completed_at TEXT,
    timeout_at   TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (agent_id)   REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS plans (
    plan_hash   TEXT PRIMARY KEY,
    module_name TEXT NOT NULL,
    plan_json   TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id           TEXT PRIMARY KEY,
    job_id       TEXT NOT NULL,
    archive_path TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    is_encrypted INTEGER DEFAULT 0,
    uploaded_at  TEXT NOT NULL,
    source_collector TEXT,
    device_id    TEXT,
    collector_timestamp TEXT,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id  TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    object    TEXT NOT NULL,
    metadata  TEXT,
    prev_hash TEXT NOT NULL,
    curr_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_telemetry (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id     TEXT NOT NULL,
    category     TEXT NOT NULL,
    payload      TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    UNIQUE(agent_id, category),
    FOREIGN KEY (agent_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS live_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT UNIQUE NOT NULL,
    case_id    TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    category   TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload    TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS browser_artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT UNIQUE NOT NULL,
    case_id     TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    browser     TEXT NOT NULL,
    type        TEXT NOT NULL,
    url         TEXT,
    title       TEXT,
    query       TEXT,
    file_path   TEXT,
    timestamp   TEXT NOT NULL,
    raw_payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovered_files (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id      TEXT UNIQUE NOT NULL,
    candidate_id     TEXT NOT NULL,
    case_id          TEXT NOT NULL,
    filename         TEXT NOT NULL,
    source_path      TEXT NOT NULL,
    destination_path TEXT NOT NULL,
    size_bytes       INTEGER NOT NULL,
    sha256           TEXT NOT NULL,
    recovered_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id     TEXT UNIQUE NOT NULL,
    case_id         TEXT NOT NULL,
    assessment_type TEXT NOT NULL,
    payload         TEXT NOT NULL,
    timestamp       TEXT NOT NULL
);

-- API key lifecycle management (rotation, expiry, revocation)
CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash    TEXT NOT NULL UNIQUE,   -- SHA-256 of the raw key; raw never stored
    label       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,                   -- NULL = no expiry
    revoked_at  TEXT,                   -- NULL = still active
    last_used   TEXT,
    rotate_from TEXT                    -- key_hash of the predecessor if this is a rotation
);

CREATE TABLE IF NOT EXISTS email_artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    from_addr     TEXT,
    to_addr       TEXT,
    cc_addr       TEXT,
    subject       TEXT,
    date          TEXT,
    message_id    TEXT,
    artifact_type TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    body_preview  TEXT,
    raw_payload   TEXT NOT NULL,
    collected_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS location_telemetry (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    latitude    REAL,
    longitude   REAL,
    city        TEXT,
    region      TEXT,
    country     TEXT,
    source      TEXT,
    accuracy    TEXT,
    confidence  TEXT,
    payload     TEXT NOT NULL,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS removable_media (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id          TEXT NOT NULL,
    agent_id         TEXT NOT NULL,
    device_name      TEXT NOT NULL,
    serial_number    TEXT,
    vendor_product   TEXT,
    interface        TEXT,
    media_type       TEXT,
    size_bytes       INTEGER,
    status           TEXT NOT NULL,
    evidence_type    TEXT NOT NULL,
    observed_at      TEXT NOT NULL,
    activity_summary TEXT,
    raw_payload      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_telemetry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    interface_name  TEXT,
    ipv4            TEXT,
    mac_address     TEXT,
    status          TEXT,
    active_sockets  TEXT NOT NULL,
    wifi_profiles   TEXT NOT NULL,
    dns_cache       TEXT NOT NULL,
    collected_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS forensic_carvings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id           TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    file_path         TEXT NOT NULL,
    detected_type     TEXT NOT NULL,
    expected_ext      TEXT,
    magic_hex         TEXT,
    mismatch_flag     INTEGER DEFAULT 0,
    hash_md5          TEXT,
    hash_sha256       TEXT,
    analyzed_at       TEXT NOT NULL
);

-- =========================================================================
-- B1-B12 NORMALIZED EVIDENCE SCHEMA
-- =========================================================================

CREATE TABLE IF NOT EXISTS artifacts (
    id            TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    category      TEXT NOT NULL,
    name          TEXT NOT NULL,
    path          TEXT,
    source        TEXT NOT NULL,
    status        TEXT NOT NULL,
    sha256        TEXT,
    size_bytes    INTEGER DEFAULT 0,
    timestamp     TEXT NOT NULL,
    raw_metadata  TEXT
);

CREATE TABLE IF NOT EXISTS browser_history (
    id            TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    browser       TEXT NOT NULL,
    profile       TEXT NOT NULL,
    url           TEXT NOT NULL,
    title         TEXT,
    visit_count   INTEGER DEFAULT 1,
    typed_count   INTEGER DEFAULT 0,
    timestamp     TEXT NOT NULL,
    source        TEXT NOT NULL,
    status        TEXT NOT NULL,
    sha256        TEXT,
    domain        TEXT
);

CREATE TABLE IF NOT EXISTS browser_downloads (
    id              TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL,
    case_id         TEXT NOT NULL,
    browser         TEXT NOT NULL,
    profile         TEXT NOT NULL,
    url             TEXT,
    target_path     TEXT,
    filename        TEXT,
    total_bytes     INTEGER DEFAULT 0,
    received_bytes  INTEGER DEFAULT 0,
    start_time      TEXT,
    end_time        TEXT,
    mime_type       TEXT,
    state           TEXT,
    timestamp       TEXT NOT NULL,
    source          TEXT NOT NULL,
    status          TEXT NOT NULL,
    sha256          TEXT,
    zone_identifier TEXT
);

CREATE TABLE IF NOT EXISTS browser_bookmarks (
    id          TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    browser     TEXT NOT NULL,
    profile     TEXT NOT NULL,
    title       TEXT,
    url         TEXT NOT NULL,
    folder      TEXT,
    date_added  TEXT,
    timestamp   TEXT NOT NULL,
    source      TEXT NOT NULL,
    status      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applications (
    id               TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    case_id          TEXT NOT NULL,
    name             TEXT NOT NULL,
    version          TEXT,
    publisher        TEXT,
    install_path     TEXT,
    install_date     TEXT,
    uninstall_string TEXT,
    category         TEXT,
    source           TEXT NOT NULL,
    status           TEXT NOT NULL,
    sha256           TEXT,
    timestamp        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processes (
    id              TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL,
    case_id         TEXT NOT NULL,
    pid             INTEGER NOT NULL,
    ppid            INTEGER DEFAULT 0,
    name            TEXT NOT NULL,
    executable_path TEXT,
    command_line    TEXT,
    user            TEXT,
    cpu_percent     REAL DEFAULT 0.0,
    memory_kb       INTEGER DEFAULT 0,
    threads         INTEGER DEFAULT 1,
    state           TEXT,
    start_time      TEXT,
    sha256          TEXT,
    source          TEXT NOT NULL,
    status          TEXT NOT NULL,
    timestamp       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id                  TEXT PRIMARY KEY,
    device_id           TEXT NOT NULL,
    case_id             TEXT NOT NULL,
    app_name            TEXT NOT NULL,
    profile_dir         TEXT,
    db_path             TEXT,
    message_id          TEXT,
    conversation_id     TEXT,
    sender              TEXT,
    recipient           TEXT,
    direction           TEXT,
    text_snippet        TEXT,
    message_count       INTEGER DEFAULT 1,
    attachment_names    TEXT,
    attachment_metadata TEXT,
    timestamp           TEXT NOT NULL,
    source              TEXT NOT NULL,
    status              TEXT NOT NULL,
    sha256              TEXT
);

CREATE TABLE IF NOT EXISTS email_messages (
    id              TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL,
    case_id         TEXT NOT NULL,
    client_name     TEXT NOT NULL,
    mailbox_name    TEXT,
    mailbox_path    TEXT,
    message_id      TEXT,
    from_addr       TEXT,
    to_addr         TEXT,
    cc_addr         TEXT,
    subject         TEXT,
    date            TEXT,
    body_snippet    TEXT,
    has_attachments INTEGER DEFAULT 0,
    timestamp       TEXT NOT NULL,
    source          TEXT NOT NULL,
    status          TEXT NOT NULL,
    sha256          TEXT
);

CREATE TABLE IF NOT EXISTS email_attachments (
    id           TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL,
    case_id      TEXT NOT NULL,
    message_id   TEXT,
    email_db_id  TEXT,
    filename     TEXT NOT NULL,
    size_bytes   INTEGER DEFAULT 0,
    mime_type    TEXT,
    sha256       TEXT,
    file_path    TEXT,
    timestamp    TEXT NOT NULL,
    source       TEXT NOT NULL,
    status       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS web_activity (
    id            TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    platform      TEXT NOT NULL,
    domain        TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    visit_count   INTEGER DEFAULT 1,
    evidence_type TEXT NOT NULL,
    browser       TEXT NOT NULL,
    profile       TEXT NOT NULL,
    source        TEXT NOT NULL,
    status        TEXT NOT NULL,
    timestamp     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices_artifacts (
    id                 TEXT PRIMARY KEY,
    device_id          TEXT NOT NULL,
    case_id            TEXT NOT NULL,
    device_type        TEXT NOT NULL,
    device_name        TEXT NOT NULL,
    vendor             TEXT,
    product            TEXT,
    serial_number      TEXT,
    hardware_id        TEXT,
    drive_letter       TEXT,
    interface          TEXT,
    status             TEXT NOT NULL,
    connection_time    TEXT,
    disconnection_time TEXT,
    raw_details        TEXT,
    source             TEXT NOT NULL,
    timestamp          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS filesystem (
    id            TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    path          TEXT NOT NULL,
    filename      TEXT NOT NULL,
    extension     TEXT,
    size_bytes    INTEGER DEFAULT 0,
    created_time  TEXT,
    modified_time TEXT,
    accessed_time TEXT,
    file_type     TEXT,
    owner         TEXT,
    permissions   TEXT,
    sha256        TEXT,
    is_directory  INTEGER DEFAULT 0,
    is_deleted    INTEGER DEFAULT 0,
    source        TEXT NOT NULL,
    status        TEXT NOT NULL,
    timestamp     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_events (
    id             TEXT PRIMARY KEY,
    device_id      TEXT NOT NULL,
    case_id        TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    protocol       TEXT,
    local_address  TEXT,
    local_port     TEXT,
    remote_address TEXT,
    remote_port    TEXT,
    state          TEXT,
    pid            INTEGER,
    process_name   TEXT,
    interface_name TEXT,
    details        TEXT,
    timestamp      TEXT NOT NULL,
    source         TEXT NOT NULL,
    status         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline (
    id               TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    case_id          TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    source           TEXT NOT NULL,
    category         TEXT NOT NULL,
    severity         TEXT DEFAULT 'INFO',
    description      TEXT NOT NULL,
    entity           TEXT,
    path             TEXT,
    process          TEXT,
    network_endpoint TEXT,
    raw_reference    TEXT,
    status           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL,
    case_id         TEXT NOT NULL,
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        TEXT DEFAULT 'MEDIUM',
    description     TEXT NOT NULL,
    evidence_refs   TEXT,
    recommendations TEXT,
    mitre_technique TEXT,
    timestamp       TEXT NOT NULL,
    status          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_files (
    id            TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    file_size     INTEGER DEFAULT 0,
    sha256        TEXT NOT NULL,
    mime_type     TEXT,
    category      TEXT NOT NULL,
    collected_at  TEXT NOT NULL,
    status        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collection_runs (
    id                TEXT PRIMARY KEY,
    device_id         TEXT NOT NULL,
    case_id           TEXT NOT NULL,
    start_time        TEXT NOT NULL,
    end_time          TEXT,
    status            TEXT NOT NULL,
    collector_version TEXT NOT NULL,
    platform          TEXT NOT NULL,
    options           TEXT,
    total_artifacts   INTEGER DEFAULT 0,
    summary_json      TEXT
);

CREATE TABLE IF NOT EXISTS hashes (
    id        TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    case_id   TEXT NOT NULL,
    item_type TEXT NOT NULL,
    item_id   TEXT NOT NULL,
    path      TEXT,
    md5       TEXT,
    sha1      TEXT,
    sha256    TEXT NOT NULL,
    verified  INTEGER DEFAULT 1,
    timestamp TEXT NOT NULL,
    status    TEXT NOT NULL
);

-- B1-B12 Indexes
CREATE INDEX IF NOT EXISTS idx_art_ts ON artifacts(timestamp);
CREATE INDEX IF NOT EXISTS idx_art_dev ON artifacts(device_id);
CREATE INDEX IF NOT EXISTS idx_art_case ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_art_type ON artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_art_src ON artifacts(source);
CREATE INDEX IF NOT EXISTS idx_art_path ON artifacts(path);

CREATE INDEX IF NOT EXISTS idx_bhist_ts ON browser_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_bhist_dev ON browser_history(device_id);
CREATE INDEX IF NOT EXISTS idx_bhist_case ON browser_history(case_id);
CREATE INDEX IF NOT EXISTS idx_bhist_dom ON browser_history(domain);

CREATE INDEX IF NOT EXISTS idx_bdl_ts ON browser_downloads(timestamp);
CREATE INDEX IF NOT EXISTS idx_bdl_dev ON browser_downloads(device_id);
CREATE INDEX IF NOT EXISTS idx_bdl_case ON browser_downloads(case_id);

CREATE INDEX IF NOT EXISTS idx_apps_dev ON applications(device_id);
CREATE INDEX IF NOT EXISTS idx_apps_case ON applications(case_id);

CREATE INDEX IF NOT EXISTS idx_proc_dev ON processes(device_id);
CREATE INDEX IF NOT EXISTS idx_proc_case ON processes(case_id);

CREATE INDEX IF NOT EXISTS idx_msg_dev ON messages(device_id);
CREATE INDEX IF NOT EXISTS idx_msg_case ON messages(case_id);

CREATE INDEX IF NOT EXISTS idx_email_dev ON email_messages(device_id);
CREATE INDEX IF NOT EXISTS idx_email_case ON email_messages(case_id);

CREATE INDEX IF NOT EXISTS idx_webact_dom ON web_activity(domain);
CREATE INDEX IF NOT EXISTS idx_webact_dev ON web_activity(device_id);
CREATE INDEX IF NOT EXISTS idx_webact_case ON web_activity(case_id);

CREATE INDEX IF NOT EXISTS idx_devart_dev ON devices_artifacts(device_id);
CREATE INDEX IF NOT EXISTS idx_devart_case ON devices_artifacts(case_id);

CREATE INDEX IF NOT EXISTS idx_fs_path ON filesystem(path);
CREATE INDEX IF NOT EXISTS idx_fs_dev ON filesystem(device_id);
CREATE INDEX IF NOT EXISTS idx_fs_case ON filesystem(case_id);

CREATE INDEX IF NOT EXISTS idx_net_dev ON network_events(device_id);
CREATE INDEX IF NOT EXISTS idx_net_case ON network_events(case_id);

CREATE INDEX IF NOT EXISTS idx_time_ts ON timeline(timestamp);
CREATE INDEX IF NOT EXISTS idx_time_dev ON timeline(device_id);
CREATE INDEX IF NOT EXISTS idx_time_case ON timeline(case_id);

CREATE INDEX IF NOT EXISTS idx_find_dev ON findings(device_id);
CREATE INDEX IF NOT EXISTS idx_find_case ON findings(case_id);


CREATE TABLE IF NOT EXISTS threat_intel_research (
    id                 TEXT PRIMARY KEY,
    case_id            TEXT NOT NULL,
    indicator          TEXT NOT NULL,
    indicator_type     TEXT NOT NULL,
    query              TEXT NOT NULL,
    sources_json       TEXT NOT NULL,
    fetched_urls_json  TEXT,
    fetched_content    TEXT,
    status             TEXT NOT NULL,
    review_status      TEXT DEFAULT 'UNREVIEWED',
    investigator_notes TEXT,
    created_at         TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_case ON threat_intel_research(case_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel_research(indicator);

CREATE INDEX IF NOT EXISTS idx_hashes_sha ON hashes(sha256);
"""


def init_db_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.commit()


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    chosen = db_path or os.environ.get("JOCKY_DB", DEFAULT_DB_PATH)
    target = chosen if chosen == ":memory:" else os.path.abspath(chosen)
    conn = sqlite3.connect(target, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL is initialized once during schema setup; do not switch journal mode
    # on every request because that itself can acquire SQLite locks.
    conn.execute("PRAGMA busy_timeout=10000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='devices'")
        if not cur.fetchone():
            init_db_schema(conn)
    except Exception:
        pass
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply incremental migrations for schema additions."""
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel_research (
                id                 TEXT PRIMARY KEY,
                case_id            TEXT NOT NULL,
                indicator          TEXT NOT NULL,
                indicator_type     TEXT NOT NULL,
                query              TEXT NOT NULL,
                sources_json       TEXT NOT NULL,
                fetched_urls_json  TEXT,
                fetched_content    TEXT,
                status             TEXT NOT NULL,
                review_status      TEXT DEFAULT 'UNREVIEWED',
                investigator_notes TEXT,
                created_at         TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_case ON threat_intel_research(case_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel_research(indicator)")
        conn.commit()
    except Exception:
        pass

    migrations = [
        ("evidence", "source_collector", "TEXT"),
        ("evidence", "device_id",        "TEXT"),
        ("evidence", "collector_timestamp", "TEXT"),
        ("jobs",     "timeout_at",        "TEXT"),
        ("devices",  "active_case_id",    "TEXT"),
        ("cases",    "investigator_name", "TEXT"),
        ("cases",    "investigator_org",  "TEXT"),
        ("cases",    "subject_name",      "TEXT"),
        ("cases",    "authorization_ref", "TEXT"),
        ("cases",    "evidence_source",   "TEXT"),
        ("cases",    "investigation_notes","TEXT"),
    ]
    for table, col, col_type in migrations:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            conn.commit()
        except Exception:
            pass  # Column already exists


def init_db(db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    init_db_schema(conn)
    # Schema migrations are startup work, never per-request work.
    _migrate(conn)
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Backup & restore
# ─────────────────────────────────────────────────────────────────────────────

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def backup_db(db_path: Optional[str] = None,
              backup_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a timestamped backup of the SQLite database using the SQLite
    Online Backup API (safe for concurrent use).

    Returns a provenance record: path, sha256, size, timestamp.
    """
    src = os.path.abspath(db_path or os.environ.get("JOCKY_DB", DEFAULT_DB_PATH))
    dest_dir = os.path.abspath(backup_dir or os.environ.get("JOCKY_BACKUP_DIR", BACKUP_DIR))
    os.makedirs(dest_dir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(dest_dir, f"jocky_forensics.{ts}.db")

    # Use SQLite online backup API
    src_conn = sqlite3.connect(src)
    dst_conn = sqlite3.connect(dest)
    src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()

    digest    = _sha256_file(dest)
    size      = os.path.getsize(dest)
    meta_path = dest + ".meta.json"

    meta = {
        "source":    src,
        "backup":    dest,
        "sha256":    digest,
        "size_bytes": size,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    return meta


def restore_db(backup_path: str,
               db_path: Optional[str] = None,
               expected_sha256: Optional[str] = None) -> Dict[str, Any]:
    """
    Restore a database from a backup file, verifying SHA-256 integrity first.
    The live database is backed up before overwrite.
    """
    if not os.path.isfile(backup_path):
        return {"success": False, "error": f"Backup not found: {backup_path}"}

    actual_hash = _sha256_file(backup_path)
    if expected_sha256 and actual_hash != expected_sha256:
        return {
            "success": False,
            "error": "SHA-256 integrity check failed — backup may be corrupted or tampered.",
            "expected": expected_sha256,
            "actual": actual_hash,
        }

    target = os.path.abspath(db_path or os.environ.get("JOCKY_DB", DEFAULT_DB_PATH))
    # Safety backup before overwrite
    pre_backup = backup_db(db_path=target)

    shutil.copy2(backup_path, target)
    return {
        "success": True,
        "restored_from": backup_path,
        "sha256_verified": actual_hash,
        "pre_restore_backup": pre_backup["backup"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def list_backups(backup_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """List available backup files with metadata."""
    bdir = os.path.abspath(backup_dir or os.environ.get("JOCKY_BACKUP_DIR", BACKUP_DIR))
    if not os.path.isdir(bdir):
        return []
    results = []
    for fname in sorted(os.listdir(bdir)):
        if not fname.endswith(".db"):
            continue
        fpath = os.path.join(bdir, fname)
        meta_path = fpath + ".meta.json"
        entry: Dict[str, Any] = {
            "path": fpath,
            "filename": fname,
            "size_bytes": os.path.getsize(fpath),
            "mtime": datetime.fromtimestamp(
                os.path.getmtime(fpath), tz=timezone.utc
            ).isoformat(),
        }
        if os.path.isfile(meta_path):
            try:
                with open(meta_path) as f:
                    entry["meta"] = json.load(f)
            except Exception:
                pass
        results.append(entry)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# API key lifecycle
# ─────────────────────────────────────────────────────────────────────────────

def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def create_api_key(raw_key: str, label: str,
                   expires_in_days: Optional[int] = None,
                   rotate_from_hash: Optional[str] = None,
                   db_path: Optional[str] = None) -> Dict[str, Any]:
    """Register a new API key (stores hash only, never the raw key)."""
    conn = get_db_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    expires_at = None
    if expires_in_days:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()
    key_hash = _hash_key(raw_key)
    conn.execute(
        "INSERT OR REPLACE INTO api_keys (key_hash, label, created_at, expires_at, rotate_from) "
        "VALUES (?, ?, ?, ?, ?)",
        (key_hash, label, now, expires_at, rotate_from_hash)
    )
    conn.commit()
    conn.close()
    return {"key_hash": key_hash, "label": label, "created_at": now, "expires_at": expires_at}


def validate_api_key(raw_key: str, db_path: Optional[str] = None) -> Tuple[bool, str]:
    """Return (valid, reason). Updates last_used on success."""
    if not raw_key:
        return False, "No key provided"
    key_hash = _hash_key(raw_key)
    conn = get_db_connection(db_path)
    row = conn.execute(
        "SELECT * FROM api_keys WHERE key_hash=?", (key_hash,)
    ).fetchone()
    if not row:
        conn.close()
        return False, "Unknown key"
    row = dict(row)
    if row.get("revoked_at"):
        conn.close()
        return False, f"Key revoked at {row['revoked_at']}"
    if row.get("expires_at"):
        if datetime.now(timezone.utc).isoformat() > row["expires_at"]:
            conn.close()
            return False, f"Key expired at {row['expires_at']}"
    # Update last_used
    conn.execute(
        "UPDATE api_keys SET last_used=? WHERE key_hash=?",
        (datetime.now(timezone.utc).isoformat(), key_hash)
    )
    conn.commit()
    conn.close()
    return True, "Valid"


def revoke_api_key(raw_key: str, db_path: Optional[str] = None) -> bool:
    """Revoke a key by recording its revocation timestamp."""
    key_hash = _hash_key(raw_key)
    conn = get_db_connection(db_path)
    cur = conn.execute(
        "UPDATE api_keys SET revoked_at=? WHERE key_hash=?",
        (datetime.now(timezone.utc).isoformat(), key_hash)
    )
    conn.commit()
    conn.close()
    return cur.rowcount > 0


def list_api_keys(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    rows = conn.execute(
        "SELECT key_hash, label, created_at, expires_at, revoked_at, last_used FROM api_keys"
    ).fetchall()
    conn.close()
    now = datetime.now(timezone.utc).isoformat()
    result = []
    for r in rows:
        d = dict(r)
        d["status"] = (
            "revoked"  if d.get("revoked_at") else
            "expired"  if (d.get("expires_at") and now > d["expires_at"]) else
            "active"
        )
        result.append(d)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Pagination helpers
# ─────────────────────────────────────────────────────────────────────────────

def paginate(query: str, params: tuple, conn: sqlite3.Connection,
             page: int = 1, page_size: int = 50) -> Dict[str, Any]:
    """Execute a SELECT with LIMIT/OFFSET pagination. Returns rows + metadata."""
    page = max(1, page)
    page_size = min(max(1, page_size), 500)
    offset = (page - 1) * page_size

    count_query = f"SELECT COUNT(*) FROM ({query})"
    total = conn.execute(count_query, params).fetchone()[0]

    rows = conn.execute(f"{query} LIMIT ? OFFSET ?", params + (page_size, offset)).fetchall()
    return {
        "rows": [dict(r) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Maintenance helpers
# ─────────────────────────────────────────────────────────────────────────────

def cleanup_stale_devices(inactive_days: int = 30,
                          db_path: Optional[str] = None) -> int:
    """Mark devices as STALE if last_seen is older than inactive_days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=inactive_days)).isoformat()
    conn = get_db_connection(db_path)
    cur = conn.execute(
        "UPDATE devices SET status='STALE' WHERE last_seen < ? AND status='ACTIVE'",
        (cutoff,)
    )
    conn.commit()
    conn.close()
    return cur.rowcount


def timeout_stale_jobs(timeout_minutes: int = 60,
                       db_path: Optional[str] = None) -> int:
    """Mark PENDING/RUNNING jobs as TIMEOUT if they've exceeded timeout_at."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    cur = conn.execute(
        "UPDATE jobs SET status='TIMEOUT' WHERE status IN ('PENDING','RUNNING') "
        "AND timeout_at IS NOT NULL AND timeout_at < ?",
        (now,)
    )
    conn.commit()
    conn.close()
    return cur.rowcount


# ─────────────────────────────────────────────────────────────────────────────
# B1-B12 Evidence Query & Overview Helpers
# ─────────────────────────────────────────────────────────────────────────────

ALLOWED_EVIDENCE_TABLES = {
    "artifacts", "browser_history", "browser_downloads", "browser_bookmarks",
    "applications", "processes", "messages", "email_messages", "email_attachments",
    "web_activity", "devices_artifacts", "filesystem", "network_events",
    "timeline", "findings", "evidence_files", "collection_runs", "hashes",
    "devices", "cases", "live_events", "audit_events"
}


def query_evidence_records(
    conn: sqlite3.Connection,
    table: str,
    case_id: Optional[str] = None,
    device_id: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None,
    search: Optional[str] = None,
    search_fields: Optional[List[str]] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    date_field: str = "timestamp",
    sort_by: Optional[str] = None,
    order: str = "desc",
    page: int = 1,
    limit: int = 50,
) -> Dict[str, Any]:
    """Universal query helper with pagination, filtering, search, and sorting."""
    if table not in ALLOWED_EVIDENCE_TABLES:
        return {
            "status": "COLLECTION_ERROR",
            "count": 0,
            "total": 0,
            "page": page,
            "limit": limit,
            "items": [],
            "error": f"Invalid table: {table}"
        }

    clauses: List[str] = []
    params: List[Any] = []

    if case_id:
        clauses.append("case_id = ?")
        params.append(case_id)
    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)

    if filters:
        for k, v in filters.items():
            if v is not None and v != "":
                clean_col = "".join(c for c in k if c.isalnum() or c == "_")
                clauses.append(f"{clean_col} = ?")
                params.append(v)

    if date_from:
        clean_date_col = "".join(c for c in date_field if c.isalnum() or c == "_")
        clauses.append(f"{clean_date_col} >= ?")
        params.append(date_from)
    if date_to:
        clean_date_col = "".join(c for c in date_field if c.isalnum() or c == "_")
        clauses.append(f"{clean_date_col} <= ?")
        params.append(date_to)

    if search and search_fields:
        search_clauses = []
        for sf in search_fields:
            clean_sf = "".join(c for c in sf if c.isalnum() or c == "_")
            search_clauses.append(f"{clean_sf} LIKE ?")
            params.append(f"%{search}%")
        if search_clauses:
            clauses.append(f"({' OR '.join(search_clauses)})")

    where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""

    # Count total
    count_sql = f"SELECT COUNT(*) FROM {table}{where_sql}"
    try:
        total = conn.execute(count_sql, tuple(params)).fetchone()[0]
    except Exception as e:
        return {
            "status": "COLLECTION_ERROR",
            "count": 0,
            "total": 0,
            "page": page,
            "limit": limit,
            "items": [],
            "error": str(e)
        }

    # Sorting
    clean_sort = "timestamp"
    if sort_by:
        clean_sort = "".join(c for c in sort_by if c.isalnum() or c == "_")
    sort_dir = "DESC" if str(order).lower() == "desc" else "ASC"

    # Pagination
    page = max(1, page)
    limit = min(max(1, limit), 500)
    offset = (page - 1) * limit

    data_sql = f"SELECT * FROM {table}{where_sql} ORDER BY {clean_sort} {sort_dir} LIMIT ? OFFSET ?"
    query_params = tuple(params) + (limit, offset)
    try:
        cur = conn.execute(data_sql, query_params)
        rows = [dict(r) for r in cur.fetchall()]
    except Exception as e:
        # Fallback if sort column doesn't exist
        try:
            fallback_sql = f"SELECT * FROM {table}{where_sql} LIMIT ? OFFSET ?"
            cur = conn.execute(fallback_sql, query_params)
            rows = [dict(r) for r in cur.fetchall()]
        except Exception as e2:
            return {
                "status": "COLLECTION_ERROR",
                "count": 0,
                "total": 0,
                "page": page,
                "limit": limit,
                "items": [],
                "error": str(e2)
            }

    status = "COLLECTED" if total > 0 else "NO_EVIDENCE_FOUND"

    return {
        "status": status,
        "count": len(rows),
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": max(1, (total + limit - 1) // limit),
        "items": rows,
    }


def get_dfir_overview_stats(
    conn: sqlite3.Connection,
    case_id: Optional[str] = None,
    device_id: Optional[str] = None
) -> Dict[str, Any]:
    """Calculates live totals across all B1-B12 forensic tables for the overview."""
    tables = [
        ("devices", "devices", "status != 'DELETED'"),
        ("artifacts", "artifacts", None),
        ("browser_records", "browser_history", None),
        ("browser_downloads", "browser_downloads", None),
        ("browser_bookmarks", "browser_bookmarks", None),
        ("applications", "applications", None),
        ("processes", "processes", None),
        ("messages", "messages", None),
        ("email_records", "email_messages", None),
        ("web_activity", "web_activity", None),
        ("device_artifacts", "devices_artifacts", None),
        ("files", "filesystem", None),
        ("network_events", "network_events", None),
        ("timeline_events", "timeline", None),
        ("findings", "findings", None),
        ("hashes", "hashes", None),
        ("threat_intel_records", "threat_intel_research", None),
    ]
    counts: Dict[str, int] = {}
    for key, tbl, extra_where in tables:
        clauses = []
        params: List[Any] = []
        if case_id and tbl not in ("devices",):
            clauses.append("case_id = ?")
            params.append(case_id)
        if device_id and tbl not in ("devices", "cases"):
            clauses.append("device_id = ?")
            params.append(device_id)
        if extra_where:
            clauses.append(extra_where)
        where_str = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            val = conn.execute(f"SELECT COUNT(*) FROM {tbl}{where_str}", tuple(params)).fetchone()[0]
            counts[key] = val
        except Exception:
            counts[key] = 0

    latest_run = None
    try:
        run_clauses = []
        run_params: List[Any] = []
        if case_id:
            run_clauses.append("case_id = ?")
            run_params.append(case_id)
        where_run = f" WHERE {' AND '.join(run_clauses)}" if run_clauses else ""
        cur = conn.execute(f"SELECT * FROM collection_runs{where_run} ORDER BY start_time DESC LIMIT 1", tuple(run_params))
        r = cur.fetchone()
        if r:
            latest_run = dict(r)
    except Exception:
        pass

    total_artifacts = counts.get("artifacts", 0) + counts.get("browser_records", 0) + counts.get("applications", 0) + counts.get("files", 0)
    status = "COLLECTED" if total_artifacts > 0 else "NO_EVIDENCE_FOUND"

    return {
        "status": status,
        "counts": counts,
        "latest_run": latest_run,
    }

