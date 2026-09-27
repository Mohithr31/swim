"""
JOCKY Forensic Evidence Manager

Full provenance traceability: every evidence record now carries
  - source_collector, device_id, collector_timestamp
  - SHA-256 verification on retrieve
  - Paginated listing with filter support
"""
import os, uuid, json, hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from server.database import get_db_connection, paginate
from collector.manifest import calculate_sha256


DEFAULT_EVIDENCE_DIR = os.environ.get("JOCKY_EVIDENCE_DIR", "evidence")


class EvidenceModel:

    @staticmethod
    def register_evidence(
        job_id: str,
        archive_path: str,
        manifest_data: Dict[str, Any],
        is_encrypted: bool = False,
        source_collector: Optional[str] = None,
        device_id: Optional[str] = None,
        collector_timestamp: Optional[str] = None,
        db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        evidence_id = f"evd_{uuid.uuid4().hex[:8]}"
        sha256_hash = calculate_sha256(archive_path) if os.path.exists(archive_path) else ""
        size_bytes  = os.path.getsize(archive_path)  if os.path.exists(archive_path) else 0
        now         = datetime.now(timezone.utc).isoformat()
        manifest_str = json.dumps(manifest_data)

        conn = get_db_connection(db_path)
        conn.execute(
            "INSERT INTO evidence "
            "(id, job_id, archive_path, manifest_json, sha256, size_bytes, "
            "is_encrypted, uploaded_at, source_collector, device_id, collector_timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, job_id, archive_path, manifest_str, sha256_hash,
             size_bytes, 1 if is_encrypted else 0, now,
             source_collector, device_id, collector_timestamp)
        )
        conn.commit()
        conn.close()

        return {
            "id": evidence_id, "job_id": job_id,
            "archive_path": archive_path, "sha256": sha256_hash,
            "size_bytes": size_bytes, "is_encrypted": is_encrypted,
            "uploaded_at": now, "source_collector": source_collector,
            "device_id": device_id, "collector_timestamp": collector_timestamp,
        }

    @staticmethod
    def list_all(db_path: Optional[str] = None,
                 page: int = 1, page_size: int = 50,
                 device_id: Optional[str] = None,
                 since: Optional[str] = None) -> Dict[str, Any]:
        conn = get_db_connection(db_path)
        q = ("SELECT e.*, j.session_id, s.case_id, s.name as session_name, "
             "c.name as case_name FROM evidence e "
             "JOIN jobs j ON e.job_id=j.id "
             "JOIN sessions s ON j.session_id=s.id "
             "JOIN cases c ON s.case_id=c.id WHERE 1=1")
        params: tuple = ()
        if device_id:
            q += " AND e.device_id=?"; params += (device_id,)
        if since:
            q += " AND e.uploaded_at>=?"; params += (since,)
        q += " ORDER BY e.uploaded_at DESC"
        result = paginate(q, params, conn, page, page_size)
        conn.close()
        for evd in result["rows"]:
            if evd.get("manifest_json"):
                try: evd["manifest"] = json.loads(evd.pop("manifest_json"))
                except Exception: pass
        return result

    @staticmethod
    def get_by_id(evidence_id: str,
                  verify_hash: bool = False,
                  db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        row = conn.execute(
            "SELECT * FROM evidence WHERE id=?", (evidence_id,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        evd = dict(row)
        if evd.get("manifest_json"):
            try: evd["manifest"] = json.loads(evd.pop("manifest_json"))
            except Exception: pass
        if verify_hash and os.path.exists(evd.get("archive_path", "")):
            actual = calculate_sha256(evd["archive_path"])
            evd["integrity_check"] = {
                "stored_sha256": evd.get("sha256"),
                "actual_sha256": actual,
                "verified": actual == evd.get("sha256"),
            }
        return evd

    @staticmethod
    def verify_all(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Re-hash every on-disk archive and report any hash mismatches."""
        conn = get_db_connection(db_path)
        rows = conn.execute("SELECT id, archive_path, sha256 FROM evidence").fetchall()
        conn.close()
        results = []
        for r in rows:
            r = dict(r)
            path = r.get("archive_path", "")
            if not os.path.exists(path):
                r["integrity_check"] = {"status": "FILE_MISSING"}
            else:
                actual = calculate_sha256(path)
                r["integrity_check"] = {
                    "status": "OK" if actual == r["sha256"] else "MISMATCH",
                    "stored": r["sha256"],
                    "actual": actual,
                }
            results.append(r)
        return results
