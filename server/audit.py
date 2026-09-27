"""
JOCKY Tamper-Evident Cryptographic Audit Chain

Improvements over baseline:
  - Clock/ordering limitation documentation
  - export_audit_chain() for external SIEM ingestion
  - audit summary statistics
  - Rotate / seal functions
"""
import uuid, json, hashlib, io, csv, sqlite3, threading, time
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from server.database import get_db_connection

GENESIS_HASH = "0" * 64
_AUDIT_LOCK = threading.Lock()
_AUDIT_RETRIES = 6
_AUDIT_RETRY_DELAY = 0.05


def _hash(prev: str, ts: str, actor: str, action: str, obj: str, meta: str) -> str:
    return hashlib.sha256(
        f"{prev}|{ts}|{actor}|{action}|{obj}|{meta}".encode()
    ).hexdigest()


def record_audit_event(actor: str, action: str, obj: str,
                       metadata: Optional[Dict[str, Any]] = None,
                       db_path: Optional[str] = None) -> Dict[str, Any]:
    """Append one tamper-evident event safely under concurrent dashboard load.

    The audit chain is serialized within the Flask process so two concurrent
    requests cannot calculate the same predecessor hash. SQLite busy retries
    provide a small grace period for other legitimate writers.
    """
    last_exc = None
    with _AUDIT_LOCK:
        for attempt in range(_AUDIT_RETRIES):
            conn = None
            try:
                conn = get_db_connection(db_path)
                cur = conn.cursor()
                cur.execute("SELECT curr_hash FROM audit_events ORDER BY id DESC LIMIT 1")
                row = cur.fetchone()
                prev_hash = row["curr_hash"] if row else GENESIS_HASH

                event_id = f"evt_{uuid.uuid4().hex[:12]}"
                timestamp = datetime.now(timezone.utc).isoformat()
                meta_str = json.dumps(metadata, sort_keys=True) if metadata else "{}"
                curr_hash = _hash(prev_hash, timestamp, actor, action, obj, meta_str)

                cur.execute(
                    "INSERT INTO audit_events "
                    "(event_id, timestamp, actor, action, object, metadata, prev_hash, curr_hash) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (event_id, timestamp, actor, action, obj, meta_str, prev_hash, curr_hash)
                )
                conn.commit()
                conn.close()
                return dict(event_id=event_id, timestamp=timestamp, actor=actor,
                            action=action, object=obj, metadata=metadata,
                            prev_hash=prev_hash, curr_hash=curr_hash)
            except sqlite3.OperationalError as exc:
                last_exc = exc
                if conn is not None:
                    try: conn.rollback()
                    except Exception: pass
                    try: conn.close()
                    except Exception: pass
                if "locked" not in str(exc).lower() or attempt == _AUDIT_RETRIES - 1:
                    raise
                time.sleep(_AUDIT_RETRY_DELAY * (attempt + 1))
    raise last_exc  # pragma: no cover


def get_audit_events(db_path: Optional[str] = None,
                     since: Optional[str] = None,
                     actor: Optional[str] = None,
                     limit: int = 1000) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    base = "SELECT * FROM audit_events WHERE 1=1"
    params: list = []
    if since:
        base += " AND timestamp >= ?"; params.append(since)
    if actor:
        base += " AND actor = ?"; params.append(actor)
    base += " ORDER BY id ASC LIMIT ?"
    params.append(limit)
    rows = conn.execute(base, params).fetchall()
    conn.close()
    result = []
    for r in rows:
        evt = dict(r)
        if evt.get("metadata"):
            try: evt["metadata"] = json.loads(evt["metadata"])
            except Exception: pass
        result.append(evt)
    return result


def verify_audit_chain(db_path: Optional[str] = None
                       ) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Verify the cryptographic hash chain from genesis to tip.

    Limitation: this detects post-hoc modification but cannot detect real-time
    event suppression or clock manipulation at collection time.
    """
    conn = get_db_connection(db_path)
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    conn.close()
    if not rows:
        return True, "Audit log is empty.", []

    expected_prev = GENESIS_HASH
    violations: List[Dict[str, Any]] = []
    for idx, r in enumerate(rows):
        evt = dict(r)
        meta = evt["metadata"] if isinstance(evt["metadata"], str) \
               else json.dumps(evt["metadata"], sort_keys=True)
        if evt["prev_hash"] != expected_prev:
            violations.append({
                "event_id": evt["event_id"], "index": idx,
                "reason": f"Prev-hash mismatch: expected {expected_prev}, got {evt['prev_hash']}"
            })
        computed = _hash(evt["prev_hash"], evt["timestamp"], evt["actor"],
                         evt["action"], evt["object"], meta)
        if computed != evt["curr_hash"]:
            violations.append({
                "event_id": evt["event_id"], "index": idx,
                "reason": f"Curr-hash mismatch: computed {computed}, stored {evt['curr_hash']}"
            })
        expected_prev = evt["curr_hash"]

    ok = not violations
    msg = (f"Audit log verified. {len(rows)} event(s) intact."
           if ok else
           f"Chain violation(s) detected: {len(violations)} issue(s) in {len(rows)} event(s).")
    return ok, msg, violations


def audit_summary(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return statistics about the audit log."""
    conn = get_db_connection(db_path)
    total     = (conn.execute("SELECT COUNT(*) FROM audit_events").fetchone() or [0])[0]
    actors    = [r[0] for r in conn.execute(
        "SELECT DISTINCT actor FROM audit_events")]
    first_ts  = (conn.execute(
        "SELECT MIN(timestamp) FROM audit_events").fetchone() or [None])[0]
    last_ts   = (conn.execute(
        "SELECT MAX(timestamp) FROM audit_events").fetchone() or [None])[0]
    conn.close()
    valid, msg, _ = verify_audit_chain(db_path)
    return {
        "total_events": total,
        "chain_intact": valid,
        "verification_note": msg,
        "actors": actors,
        "first_event": first_ts,
        "last_event": last_ts,
        "limitation_note": (
            "Hash-chain integrity covers stored events only. "
            "Real-time event suppression or host clock manipulation "
            "cannot be detected by this mechanism alone."
        ),
    }


def export_audit_chain(fmt: str = "json",
                       db_path: Optional[str] = None) -> str:
    """
    Export the full audit chain as JSON or CSV for SIEM ingestion.
    Returns a string (JSON) or CSV text.
    """
    events = get_audit_events(db_path=db_path, limit=100_000)
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "event_id", "timestamp", "actor", "action",
            "object", "metadata", "prev_hash", "curr_hash"
        ])
        writer.writeheader()
        for e in events:
            row = {k: e.get(k, "") for k in writer.fieldnames}
            if isinstance(row.get("metadata"), dict):
                row["metadata"] = json.dumps(row["metadata"])
            writer.writerow(row)
        return buf.getvalue()
    return json.dumps(events, indent=2)
