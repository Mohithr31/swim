"""
TINY MONITOR — Case Management Service
Handles case creation, status workflows, severity updates, metrics aggregation,
and investigator notes.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from app.database import get_db_connection, utc_now_iso


class CaseService:
    """Provides case management operations and audit logging."""

    VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "CLOSED"}
    VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    @classmethod
    def generate_case_number(cls) -> str:
        """Generate human-readable sequential case identifier like TM-2026-001."""
        year = datetime.now(timezone.utc).year
        conn = get_db_connection()
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM cases WHERE case_number LIKE ?",
                (f"TM-{year}-%",)
            ).fetchone()[0]
            return f"TM-{year}-{count + 1:03d}"
        finally:
            conn.close()

    @classmethod
    def create_case(
        cls,
        title: str,
        investigator: str,
        severity: str = "MEDIUM",
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new DFIR case, persist in SQLite, and log the creation event."""
        if not title or not title.strip():
            raise ValueError("Case title cannot be empty.")
        if not investigator or not investigator.strip():
            raise ValueError("Investigator name cannot be empty.")

        sev = severity.upper().strip()
        if sev not in cls.VALID_SEVERITIES:
            sev = "MEDIUM"

        case_number = cls.generate_case_number()
        now = utc_now_iso()

        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO cases (
                        case_number, title, description, status, severity,
                        investigator, created_at, updated_at
                    ) VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?)
                """, (case_number, title.strip(), (description or "").strip(), sev, investigator.strip(), now, now))
                case_id = cursor.lastrowid

                # Add timeline event
                cursor.execute("""
                    INSERT INTO timeline_events (
                        case_id, event_type, title, description, actor, timestamp, metadata_json
                    ) VALUES (?, 'CASE_CREATED', ?, ?, ?, ?, ?)
                """, (
                    case_id,
                    f"Case Initialized: {case_number}",
                    f"Case created with severity {sev}. Title: {title.strip()}",
                    investigator.strip(),
                    now,
                    json.dumps({"case_number": case_number, "severity": sev})
                ))

            return cls.get_case_by_id(case_id)
        finally:
            conn.close()

    @classmethod
    def get_case_by_id(cls, case_id: int) -> Optional[Dict[str, Any]]:
        """Fetch single case record with aggregated statistics."""
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not row:
                return None
            case = dict(row)

            # Evidence counts
            evidence_count = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id = ?",
                (case_id,)
            ).fetchone()[0]
            verified_count = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND integrity_status = 'VERIFIED_MATCH'",
                (case_id,)
            ).fetchone()[0]
            lookups_count = conn.execute(
                "SELECT COUNT(*) FROM threat_intel_lookups WHERE case_id = ?",
                (case_id,)
            ).fetchone()[0]

            case["evidence_count"] = evidence_count
            case["verified_evidence_count"] = verified_count
            case["lookups_count"] = lookups_count
            return case
        finally:
            conn.close()

    @classmethod
    def list_cases(cls, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List cases with aggregated metrics, sorted by last update."""
        conn = get_db_connection()
        try:
            query = """
                SELECT c.*,
                       COUNT(DISTINCT e.id) as evidence_count,
                       COUNT(DISTINCT t.id) as lookups_count
                FROM cases c
                LEFT JOIN evidence e ON e.case_id = c.id
                LEFT JOIN threat_intel_lookups t ON t.case_id = c.id
            """
            params: List[Any] = []
            if status:
                query += " WHERE c.status = ?"
                params.append(status.upper())

            query += " GROUP BY c.id ORDER BY c.updated_at DESC"

            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @classmethod
    def update_case(
        cls,
        case_id: int,
        title: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        actor: str = "Investigator"
    ) -> Dict[str, Any]:
        """Update case details and record state transitions in audit timeline."""
        conn = get_db_connection()
        try:
            with conn:
                existing = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
                if not existing:
                    raise ValueError(f"Case with ID {case_id} not found.")

                now = utc_now_iso()
                new_title = title.strip() if title is not None else existing["title"]
                new_desc = description.strip() if description is not None else existing["description"]

                new_sev = existing["severity"]
                if severity:
                    sev_upper = severity.upper().strip()
                    if sev_upper in cls.VALID_SEVERITIES:
                        new_sev = sev_upper

                new_status = existing["status"]
                closed_at = existing["closed_at"]
                status_changed = False

                if status:
                    stat_upper = status.upper().strip()
                    if stat_upper in cls.VALID_STATUSES and stat_upper != existing["status"]:
                        new_status = stat_upper
                        status_changed = True
                        if new_status == "CLOSED":
                            closed_at = now
                        elif existing["status"] == "CLOSED" and new_status != "CLOSED":
                            closed_at = None

                conn.execute("""
                    UPDATE cases
                    SET title = ?, description = ?, severity = ?, status = ?,
                        updated_at = ?, closed_at = ?
                    WHERE id = ?
                """, (new_title, new_desc, new_sev, new_status, now, closed_at, case_id))

                # Log timeline events
                if status_changed:
                    event_type = "CASE_CLOSED" if new_status == "CLOSED" else "CASE_UPDATED"
                    conn.execute("""
                        INSERT INTO timeline_events (
                            case_id, event_type, title, description, actor, timestamp, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        case_id,
                        event_type,
                        f"Case Status Changed to {new_status}",
                        f"Status transitioned from {existing['status']} to {new_status}.",
                        actor,
                        now,
                        json.dumps({"old_status": existing["status"], "new_status": new_status})
                    ))
                else:
                    conn.execute("""
                        INSERT INTO timeline_events (
                            case_id, event_type, title, description, actor, timestamp, metadata_json
                        ) VALUES (?, 'CASE_UPDATED', 'Case Details Updated', ?, ?, ?, ?)
                    """, (
                        case_id,
                        f"Updated metadata (Severity: {new_sev})",
                        actor,
                        now,
                        json.dumps({"severity": new_sev})
                    ))

            return cls.get_case_by_id(case_id)
        finally:
            conn.close()

    @classmethod
    def add_note(cls, case_id: int, author: str, note: str) -> Dict[str, Any]:
        """Attach an investigator note to a case and log to timeline."""
        if not note or not note.strip():
            raise ValueError("Note content cannot be empty.")
        if not author or not author.strip():
            author = "Investigator"

        now = utc_now_iso()
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO investigation_notes (case_id, author, note, created_at)
                    VALUES (?, ?, ?, ?)
                """, (case_id, author.strip(), note.strip(), now))
                note_id = cursor.lastrowid

                # Timeline entry
                cursor.execute("""
                    INSERT INTO timeline_events (
                        case_id, event_type, title, description, actor, timestamp, metadata_json
                    ) VALUES (?, 'INVESTIGATION_NOTE', 'Investigator Note Added', ?, ?, ?, ?)
                """, (
                    case_id,
                    note.strip()[:150] + ("..." if len(note.strip()) > 150 else ""),
                    author.strip(),
                    now,
                    json.dumps({"note_id": note_id})
                ))

                # Touch updated_at
                cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))

            return {
                "id": note_id,
                "case_id": case_id,
                "author": author.strip(),
                "note": note.strip(),
                "created_at": now
            }
        finally:
            conn.close()

    @classmethod
    def get_notes(cls, case_id: int) -> List[Dict[str, Any]]:
        """List notes for a case."""
        conn = get_db_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM investigation_notes WHERE case_id = ? ORDER BY created_at ASC",
                (case_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @classmethod
    def get_dashboard_metrics(cls) -> Dict[str, Any]:
        """Aggregate global counts for dashboard overview."""
        conn = get_db_connection()
        try:
            total_cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            open_cases = conn.execute(
                "SELECT COUNT(*) FROM cases WHERE status IN ('OPEN', 'INVESTIGATING')"
            ).fetchone()[0]
            closed_cases = conn.execute(
                "SELECT COUNT(*) FROM cases WHERE status = 'CLOSED'"
            ).fetchone()[0]
            contained_cases = conn.execute(
                "SELECT COUNT(*) FROM cases WHERE status = 'CONTAINED'"
            ).fetchone()[0]

            total_evidence = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            verified_evidence = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE integrity_status = 'VERIFIED_MATCH'"
            ).fetchone()[0]
            failed_integrity = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE integrity_status = 'FAILED_MISMATCH'"
            ).fetchone()[0]

            total_lookups = conn.execute("SELECT COUNT(*) FROM threat_intel_lookups").fetchone()[0]

            # Recent 5 activity items
            recent_events = conn.execute("""
                SELECT t.*, c.case_number
                FROM timeline_events t
                LEFT JOIN cases c ON c.id = t.case_id
                ORDER BY t.timestamp DESC LIMIT 8
            """).fetchall()

            # Recent 5 lookups
            recent_lookups = conn.execute("""
                SELECT l.*, c.case_number
                FROM threat_intel_lookups l
                LEFT JOIN cases c ON c.id = l.case_id
                ORDER BY l.created_at DESC LIMIT 5
            """).fetchall()

            return {
                "total_cases": total_cases,
                "open_cases": open_cases,
                "closed_cases": closed_cases,
                "contained_cases": contained_cases,
                "total_evidence": total_evidence,
                "verified_evidence": verified_evidence,
                "failed_integrity": failed_integrity,
                "total_lookups": total_lookups,
                "recent_activity": [dict(r) for r in recent_events],
                "recent_lookups": [dict(r) for r in recent_lookups]
            }
        finally:
            conn.close()
