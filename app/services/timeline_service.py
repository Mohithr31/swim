"""
TINY MONITOR — Timeline and Threat Intel Service
Preserves immutable chronological audit events and stores research queries and results.
"""

import json
from typing import Any, Dict, List, Optional
from app.database import get_db_connection, utc_now_iso


class TimelineService:
    """Manages immutable audit trail events and persisted threat intelligence lookups."""

    @classmethod
    def record_event(
        cls,
        case_id: Optional[int],
        event_type: str,
        title: str,
        description: str,
        actor: str = "System",
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """Record an immutable event into the timeline audit log."""
        now = utc_now_iso()
        meta_json = json.dumps(metadata) if metadata else None

        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO timeline_events (
                        case_id, event_type, title, description, actor, timestamp, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (case_id, event_type, title, description, actor, now, meta_json))
                return cursor.lastrowid
        finally:
            conn.close()

    @classmethod
    def get_case_timeline(cls, case_id: int) -> List[Dict[str, Any]]:
        """Fetch chronological timeline events for a specific case (oldest to newest)."""
        conn = get_db_connection()
        try:
            rows = conn.execute("""
                SELECT * FROM timeline_events
                WHERE case_id = ?
                ORDER BY timestamp ASC
            """, (case_id,)).fetchall()

            events = []
            for r in rows:
                ev = dict(r)
                if ev.get("metadata_json"):
                    try:
                        ev["metadata"] = json.loads(ev["metadata_json"])
                    except Exception:
                        ev["metadata"] = {}
                else:
                    ev["metadata"] = {}
                events.append(ev)
            return events
        finally:
            conn.close()

    @classmethod
    def get_global_timeline(cls, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch global chronological timeline across all cases (newest first)."""
        conn = get_db_connection()
        try:
            rows = conn.execute("""
                SELECT t.*, c.case_number, c.title as case_title
                FROM timeline_events t
                LEFT JOIN cases c ON c.id = t.case_id
                ORDER BY t.timestamp DESC
                LIMIT ?
            """, (limit,)).fetchall()

            events = []
            for r in rows:
                ev = dict(r)
                if ev.get("metadata_json"):
                    try:
                        ev["metadata"] = json.loads(ev["metadata_json"])
                    except Exception:
                        ev["metadata"] = {}
                else:
                    ev["metadata"] = {}
                events.append(ev)
            return events
        finally:
            conn.close()

    @classmethod
    def save_threat_lookup(
        cls,
        case_id: Optional[int],
        indicator: str,
        indicator_type: str,
        query: str,
        purpose: Optional[str],
        status: str,
        results_count: int,
        results: List[Dict[str, Any]],
        error_message: Optional[str],
        investigator: str
    ) -> Dict[str, Any]:
        """
        Persist a threat intelligence lookup and its source-backed results in database,
        and link to case timeline if case_id is supplied.
        """
        now = utc_now_iso()
        results_json = json.dumps(results) if results else None

        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO threat_intel_lookups (
                        case_id, indicator, indicator_type, query, purpose,
                        status, results_count, results_json, error_message,
                        investigator, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    case_id,
                    indicator.strip(),
                    indicator_type,
                    query,
                    purpose,
                    status,
                    results_count,
                    results_json,
                    error_message,
                    investigator.strip() or "Investigator",
                    now
                ))
                lookup_id = cursor.lastrowid

                # If attached to a case, record timeline event and touch updated_at
                if case_id:
                    event_title = f"Threat Intel Lookup: {indicator}"
                    if status == "SUCCESS":
                        desc = f"Retrieved {results_count} source-backed intelligence leads from TinyFish."
                    elif status == "ZERO_RESULTS":
                        desc = "TinyFish Search returned 0 public threat advisories for this indicator."
                    else:
                        desc = f"Threat intelligence query failed: {error_message}"

                    cursor.execute("""
                        INSERT INTO timeline_events (
                            case_id, event_type, title, description, actor, timestamp, metadata_json
                        ) VALUES (?, 'THREAT_INTEL_SEARCH', ?, ?, ?, ?, ?)
                    """, (
                        case_id,
                        event_title,
                        desc,
                        investigator.strip() or "Investigator",
                        now,
                        json.dumps({
                            "lookup_id": lookup_id,
                            "indicator": indicator,
                            "indicator_type": indicator_type,
                            "results_count": results_count,
                            "status": status
                        })
                    ))
                    cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))

            return cls.get_threat_lookup_by_id(lookup_id)
        finally:
            conn.close()

    @classmethod
    def get_threat_lookup_by_id(cls, lookup_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve single threat intelligence lookup including parsed results."""
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT * FROM threat_intel_lookups WHERE id = ?", (lookup_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            if item.get("results_json"):
                try:
                    item["results"] = json.loads(item["results_json"])
                except Exception:
                    item["results"] = []
            else:
                item["results"] = []
            return item
        finally:
            conn.close()

    @classmethod
    def list_threat_lookups(cls, case_id: Optional[int] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """List threat lookups, optionally filtered by case."""
        conn = get_db_connection()
        try:
            if case_id:
                rows = conn.execute("""
                    SELECT t.*, c.case_number
                    FROM threat_intel_lookups t
                    LEFT JOIN cases c ON c.id = t.case_id
                    WHERE t.case_id = ?
                    ORDER BY t.created_at DESC
                    LIMIT ?
                """, (case_id, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT t.*, c.case_number
                    FROM threat_intel_lookups t
                    LEFT JOIN cases c ON c.id = t.case_id
                    ORDER BY t.created_at DESC
                    LIMIT ?
                """, (limit,)).fetchall()

            results = []
            for r in rows:
                item = dict(r)
                if item.get("results_json"):
                    try:
                        item["results"] = json.loads(item["results_json"])
                    except Exception:
                        item["results"] = []
                else:
                    item["results"] = []
                results.append(item)
            return results
        finally:
            conn.close()
