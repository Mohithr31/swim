"""
Tiny Monitor — B10 Evidence Transport & Packaging Engine
Generates standardized, tamper-evident evidence packages:
case/
    manifest.json
    evidence.sqlite
    timeline.json
    raw/
    artifacts/
    reports/
    hashes/
Includes SHA-256 cryptographic manifests, local evidence spooling,
and authenticated HTTP upload with retry queue.
Strictly defensive: No covert tunneling or stealth exfiltration.
"""
import os
import sys
import json
import shutil
import zipfile
import sqlite3
import hashlib
import platform
import tempfile
import requests
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


def _to_iso(dt_or_ts=None) -> str:
    if dt_or_ts is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(dt_or_ts, datetime):
        if dt_or_ts.tzinfo is None:
            dt_or_ts = dt_or_ts.replace(tzinfo=timezone.utc)
        return dt_or_ts.astimezone(timezone.utc).isoformat()
    try:
        ts = float(dt_or_ts)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return str(dt_or_ts)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class EvidencePackager:
    """B10 Evidence Packaging & Transport Subsystem."""

    def __init__(
        self,
        output_dir: str = "evidence",
        spool_dir: Optional[str] = None,
        collector_version: str = "5.2.0-DFIR-PRO"
    ):
        self.output_dir = os.path.abspath(output_dir)
        self.spool_dir = os.path.abspath(spool_dir or os.path.join(self.output_dir, "spool"))
        self.collector_version = collector_version
        self.platform_name = platform.system()
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.spool_dir, exist_ok=True)

    def create_evidence_package(
        self,
        case_id: str,
        device_id: str,
        db_path: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        raw_files: Optional[List[str]] = None,
        reports_files: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Build standard ZIP package containing manifest.json, evidence.sqlite, timeline.json, etc."""
        start_iso = start_time or datetime.now(timezone.utc).isoformat()
        end_iso = end_time or datetime.now(timezone.utc).isoformat()

        safe_case = "".join(c for c in case_id if c.isalnum() or c in ("-", "_"))
        pkg_basename = f"JOCKY_CASE_{safe_case}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        pkg_dir = os.path.join(self.output_dir, pkg_basename)

        # Structure
        raw_dir = os.path.join(pkg_dir, "raw")
        artifacts_dir = os.path.join(pkg_dir, "artifacts")
        reports_dir = os.path.join(pkg_dir, "reports")
        hashes_dir = os.path.join(pkg_dir, "hashes")

        for d in [pkg_dir, raw_dir, artifacts_dir, reports_dir, hashes_dir]:
            os.makedirs(d, exist_ok=True)

        file_hashes: Dict[str, str] = {}

        # 1. Copy SQLite Database
        dest_db = os.path.join(pkg_dir, "evidence.sqlite")
        artifact_counts: Dict[str, int] = {}
        if os.path.isfile(db_path):
            shutil.copy2(db_path, dest_db)
            db_sha = _sha256_file(dest_db)
            file_hashes["evidence.sqlite"] = db_sha

            # Extract artifact counts and timeline from SQLite
            try:
                conn = sqlite3.connect(dest_db)
                conn.row_factory = sqlite3.Row
                tables = [
                    "artifacts", "browser_history", "browser_downloads", "browser_bookmarks",
                    "applications", "processes", "messages", "email_messages",
                    "web_activity", "devices_artifacts", "filesystem", "network_events",
                    "timeline", "findings"
                ]
                for tbl in tables:
                    try:
                        c = conn.execute(f"SELECT COUNT(*) FROM {tbl} WHERE case_id = ?", (case_id,)).fetchone()[0]
                        if c == 0:
                            c = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
                        artifact_counts[tbl] = c
                    except Exception:
                        artifact_counts[tbl] = 0

                # 2. Extract timeline.json
                timeline_rows = conn.execute(
                    "SELECT * FROM timeline WHERE case_id = ? ORDER BY timestamp ASC", (case_id,)
                ).fetchall()
                if not timeline_rows:
                    timeline_rows = conn.execute("SELECT * FROM timeline ORDER BY timestamp ASC LIMIT 500").fetchall()

                timeline_data = [dict(r) for r in timeline_rows]
                timeline_path = os.path.join(pkg_dir, "timeline.json")
                with open(timeline_path, "w", encoding="utf-8") as f:
                    json.dump(timeline_data, f, indent=2)
                file_hashes["timeline.json"] = _sha256_file(timeline_path)

                conn.close()
            except Exception:
                pass

        # 3. Add Raw Files if provided
        if raw_files:
            for rf in raw_files:
                if os.path.isfile(rf):
                    dest = os.path.join(raw_dir, os.path.basename(rf))
                    shutil.copy2(rf, dest)
                    file_hashes[f"raw/{os.path.basename(rf)}"] = _sha256_file(dest)

        # 4. Add Report Files if provided
        if reports_files:
            for rep in reports_files:
                if os.path.isfile(rep):
                    dest = os.path.join(reports_dir, os.path.basename(rep))
                    shutil.copy2(rep, dest)
                    file_hashes[f"reports/{os.path.basename(rep)}"] = _sha256_file(dest)

        # 5. Write hashes manifest into hashes/SHA256SUMS
        hashes_manifest_path = os.path.join(hashes_dir, "SHA256SUMS")
        with open(hashes_manifest_path, "w", encoding="utf-8") as f:
            for rel_path, h in sorted(file_hashes.items()):
                f.write(f"{h}  {rel_path}\n")
        file_hashes["hashes/SHA256SUMS"] = _sha256_file(hashes_manifest_path)

        # 6. Generate Root manifest.json
        manifest = {
            "case_id": case_id,
            "device_id": device_id,
            "collection_start": start_iso,
            "collection_end": end_iso,
            "collector_version": self.collector_version,
            "platform": self.platform_name,
            "artifact_counts": artifact_counts,
            "file_hashes": file_hashes,
            "package_name": pkg_basename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "COLLECTED"
        }

        manifest_path = os.path.join(pkg_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        manifest_sha = _sha256_file(manifest_path)
        manifest["manifest_hash"] = manifest_sha

        # 7. Compress into .ZIP Package
        zip_path = os.path.join(self.output_dir, f"{pkg_basename}.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(pkg_dir):
                for file in files:
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, pkg_dir)
                    zf.write(full_p, rel_p)

        pkg_sha256 = _sha256_file(zip_path)
        manifest["package_hash"] = pkg_sha256
        manifest["package_zip_path"] = zip_path
        manifest["package_zip_size"] = os.path.getsize(zip_path)

        # Re-save manifest with package hash
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest

    def spool_package(self, package_zip_path: str, manifest: Dict[str, Any]) -> str:
        """Enqueue package in offline local spool queue."""
        dest_zip = os.path.join(self.spool_dir, os.path.basename(package_zip_path))
        dest_meta = dest_zip + ".meta.json"
        shutil.copy2(package_zip_path, dest_zip)
        with open(dest_meta, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        return dest_zip

    def upload_package(
        self,
        package_zip_path: str,
        server_url: str = "http://127.0.0.1:5000",
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Upload evidence package to configured authenticated server."""
        if not os.path.isfile(package_zip_path):
            return {"status": "COLLECTION_ERROR", "error": f"File not found: {package_zip_path}"}

        endpoint = f"{server_url.rstrip('/')}/api/evidence"
        headers = {}
        if api_key:
            headers["X-API-Key"] = api_key

        try:
            with open(package_zip_path, "rb") as f:
                files = {"file": (os.path.basename(package_zip_path), f, "application/zip")}
                data = {
                    "sha256": _sha256_file(package_zip_path),
                    "package_name": os.path.basename(package_zip_path)
                }
                resp = requests.post(endpoint, files=files, data=data, headers=headers, timeout=60)

            if resp.status_code in (200, 201):
                return {"status": "COLLECTED", "message": "Evidence package uploaded successfully", "response": resp.json()}
            else:
                # Spool for retry
                return {"status": "UPLOAD_FAILED", "http_status": resp.status_code, "error": resp.text}
        except Exception as e:
            return {"status": "UPLOAD_FAILED", "error": str(e)}

    def retry_spooled_uploads(
        self,
        server_url: str = "http://127.0.0.1:5000",
        api_key: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retry sending spooled packages upon network reconnection."""
        results = []
        if not os.path.isdir(self.spool_dir):
            return results

        spooled_zips = glob.glob(os.path.join(self.spool_dir, "*.zip"))
        for z in spooled_zips:
            res = self.upload_package(z, server_url, api_key)
            if res.get("status") == "COLLECTED":
                # Remove from spool
                try:
                    os.remove(z)
                    meta = z + ".meta.json"
                    if os.path.exists(meta):
                        os.remove(meta)
                except Exception:
                    pass
            results.append({"package": z, "result": res})
        return results
