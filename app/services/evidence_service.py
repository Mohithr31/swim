"""
TINY MONITOR — Digital Evidence Service
Forensic evidence acquisition, streaming SHA-256 calculation, path traversal protection,
and on-demand integrity verification audit logging.
"""

import hashlib
import os
import re
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple
from werkzeug.utils import secure_filename

from app.config import Config
from app.database import get_db_connection, utc_now_iso


class EvidenceService:
    """Manages digital evidence acquisition, SHA-256 cryptographic hashing, and integrity verification."""

    CHUNK_SIZE = 64 * 1024  # 64 KB streaming hash buffer

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent directory traversal or unsafe control characters."""
        base = Path(filename).name
        clean = secure_filename(base)
        if not clean:
            clean = f"evidence_{uuid.uuid4().hex[:8]}.bin"
        return clean

    @classmethod
    def calculate_stream_sha256(cls, file_stream: BinaryIO) -> Tuple[str, int]:
        """
        Calculate SHA-256 hash and total size while streaming chunks without loading
        the entire file into memory. Rewinds the stream to byte 0 before returning.
        Returns: (sha256_hex, total_bytes)
        """
        hasher = hashlib.sha256()
        total_bytes = 0
        file_stream.seek(0)

        while True:
            chunk = file_stream.read(cls.CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            total_bytes += len(chunk)

        file_stream.seek(0)
        return hasher.hexdigest().lower(), total_bytes

    @classmethod
    def calculate_file_sha256(cls, file_path: Path) -> str:
        """Calculate SHA-256 hash of an existing file on disk in streaming chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(cls.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    @classmethod
    def store_evidence(
        cls,
        case_id: int,
        file_stream: BinaryIO,
        original_filename: str,
        acquired_by: str,
        description: Optional[str] = None,
        mime_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Securely store evidence file, calculate initial SHA-256, record in database,
        and append to investigation audit timeline.
        """
        Config.ensure_directories()
        clean_name = cls.sanitize_filename(original_filename)

        # Generate unique storage filename to prevent collisions and overwrites
        unique_prefix = uuid.uuid4().hex[:12]
        stored_name = f"{unique_prefix}_{clean_name}"

        # Target directory: data/evidence/case_<id>/
        case_evidence_dir = Config.EVIDENCE_DIR / f"case_{case_id}"
        case_evidence_dir.mkdir(parents=True, exist_ok=True)

        target_path = case_evidence_dir / stored_name

        # Ensure the resolved target path is strictly within EVIDENCE_DIR (Anti-path traversal)
        if not str(target_path.resolve()).startswith(str(Config.EVIDENCE_DIR.resolve())):
            raise ValueError("Invalid storage path: Path traversal attempt detected.")

        # Compute initial cryptographic SHA-256 hash
        sha256_hash, file_size = cls.calculate_stream_sha256(file_stream)

        # Check file size limit
        if file_size > Config.MAX_UPLOAD_SIZE_BYTES:
            raise ValueError(f"File size ({file_size} bytes) exceeds limit of {Config.MAX_UPLOAD_SIZE_BYTES} bytes.")

        # Write bytes safely to disk
        file_stream.seek(0)
        with open(target_path, "wb") as out_file:
            while True:
                chunk = file_stream.read(cls.CHUNK_SIZE)
                if not chunk:
                    break
                out_file.write(chunk)

        # Relative path stored in database for portability
        relative_path = str(target_path.relative_to(Config.EVIDENCE_DIR)).replace("\\", "/")
        now = utc_now_iso()

        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO evidence (
                        case_id, filename, stored_path, file_size, sha256_hash,
                        mime_type, acquired_by, acquisition_date, description,
                        last_verified_at, integrity_status, verification_notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED_MATCH', ?)
                """, (
                    case_id,
                    clean_name,
                    relative_path,
                    file_size,
                    sha256_hash,
                    mime_type or "application/octet-stream",
                    acquired_by or "Investigator",
                    now,
                    description or "",
                    now,
                    "Initial acquisition hash calculated and verified."
                ))
                evidence_id = cursor.lastrowid

                # Record in integrity audit log
                cursor.execute("""
                    INSERT INTO integrity_audit_log (
                        evidence_id, case_id, expected_hash, calculated_hash,
                        status, verified_by, verified_at, details
                    ) VALUES (?, ?, ?, ?, 'MATCH', ?, ?, 'Initial acquisition verification.')
                """, (evidence_id, case_id, sha256_hash, sha256_hash, acquired_by or "Investigator", now))

                # Add to case timeline
                cursor.execute("""
                    INSERT INTO timeline_events (
                        case_id, event_type, title, description, actor, timestamp, metadata_json
                    ) VALUES (?, 'EVIDENCE_UPLOADED', ?, ?, ?, ?, ?)
                """, (
                    case_id,
                    f"Evidence Acquired: {clean_name}",
                    f"SHA-256: {sha256_hash} ({file_size} bytes)",
                    acquired_by or "Investigator",
                    now,
                    json_str({
                        "evidence_id": evidence_id,
                        "filename": clean_name,
                        "sha256": sha256_hash,
                        "size": file_size
                    })
                ))

                # Touch case updated_at
                cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))

            return cls.get_evidence_by_id(evidence_id)
        finally:
            conn.close()

    @classmethod
    def verify_integrity(cls, evidence_id: int, verified_by: str = "Investigator") -> Dict[str, Any]:
        """
        Recalculate SHA-256 hash of stored evidence file from disk,
        compare against originally acquired hash, update status, and log audit event.
        """
        conn = get_db_connection()
        try:
            with conn:
                row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
                if not row:
                    raise FileNotFoundError(f"Evidence item {evidence_id} not found.")

                expected_hash = row["sha256_hash"].lower()
                stored_path = Config.EVIDENCE_DIR / Path(row["stored_path"])
                now = utc_now_iso()
                case_id = row["case_id"]
                filename = row["filename"]

                if not stored_path.exists():
                    status = "FILE_MISSING"
                    notes = f"Physical file missing from storage: {stored_path.name}"
                    calculated_hash = ""
                else:
                    calculated_hash = cls.calculate_file_sha256(stored_path)
                    if calculated_hash == expected_hash:
                        status = "VERIFIED_MATCH"
                        notes = f"Integrity check PASSED. Current SHA-256 matches acquisition baseline."
                    else:
                        status = "FAILED_MISMATCH"
                        notes = f"Integrity check FAILED! File hash mismatch. Expected: {expected_hash}, Calculated: {calculated_hash}"

                # Update evidence record
                conn.execute("""
                    UPDATE evidence
                    SET last_verified_at = ?, integrity_status = ?, verification_notes = ?
                    WHERE id = ?
                """, (now, status, notes, evidence_id))

                # Insert into integrity audit log
                audit_status = "MATCH" if status == "VERIFIED_MATCH" else ("MISMATCH" if status == "FAILED_MISMATCH" else "ERROR")
                conn.execute("""
                    INSERT INTO integrity_audit_log (
                        evidence_id, case_id, expected_hash, calculated_hash,
                        status, verified_by, verified_at, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (evidence_id, case_id, expected_hash, calculated_hash, audit_status, verified_by, now, notes))

                # Add to case timeline
                event_type = "INTEGRITY_VERIFIED" if status == "VERIFIED_MATCH" else "INTEGRITY_FAILED"
                conn.execute("""
                    INSERT INTO timeline_events (
                        case_id, event_type, title, description, actor, timestamp, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    case_id,
                    event_type,
                    f"Integrity Check: {filename} ({'PASSED' if status == 'VERIFIED_MATCH' else 'FAILED'})",
                    notes,
                    verified_by,
                    now,
                    json_str({
                        "evidence_id": evidence_id,
                        "expected_hash": expected_hash,
                        "calculated_hash": calculated_hash,
                        "status": status
                    })
                ))

            return cls.get_evidence_by_id(evidence_id)
        finally:
            conn.close()

    @classmethod
    def get_evidence_by_id(cls, evidence_id: int) -> Optional[Dict[str, Any]]:
        """Fetch single evidence item details as dictionary."""
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @classmethod
    def list_case_evidence(cls, case_id: int) -> List[Dict[str, Any]]:
        """List all evidence items for a given case ordered by acquisition date."""
        conn = get_db_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE case_id = ? ORDER BY acquisition_date DESC",
                (case_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @classmethod
    def get_evidence_stats(cls) -> Dict[str, int]:
        """Return global evidence counts and integrity summary for dashboard."""
        conn = get_db_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            verified = conn.execute("SELECT COUNT(*) FROM evidence WHERE integrity_status = 'VERIFIED_MATCH'").fetchone()[0]
            mismatch = conn.execute("SELECT COUNT(*) FROM evidence WHERE integrity_status = 'FAILED_MISMATCH'").fetchone()[0]
            unverified = conn.execute("SELECT COUNT(*) FROM evidence WHERE integrity_status = 'UNVERIFIED'").fetchone()[0]
            return {
                "total_evidence": total,
                "verified_match": verified,
                "failed_mismatch": mismatch,
                "unverified": unverified
            }
        finally:
            conn.close()


def json_str(data: Any) -> str:
    """Helper to convert dictionary to compact JSON string."""
    import json
    return json.dumps(data)
