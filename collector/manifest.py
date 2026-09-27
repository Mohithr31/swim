"""
JOCKY Forensic Evidence Manifest Generator — v2

Full artifact provenance:
  - Source revision (git SHA), build ID, platform, Python version,
    compiler/toolchain, timestamp, configuration, artifact hash
  - Manifest SHA-256 chained over file list + provenance
  - files_base stored in manifest so verify_manifest is self-contained
"""
import os, json, hashlib, platform, subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def calculate_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()


def _git_revision() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True,
            stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "UNKNOWN"


def _toolchain_info() -> Dict[str, str]:
    clang = llvm = ""
    try:
        clang = subprocess.check_output(
            ["clang", "--version"], text=True, stderr=subprocess.DEVNULL
        ).splitlines()[0].strip()
    except Exception:
        pass
    try:
        llvm = subprocess.check_output(
            ["llvm-config", "--version"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        pass
    return {
        "python": platform.python_version(),
        "clang":  clang or "not found",
        "llvm":   llvm  or "not found",
        "os":     platform.platform(),
        "arch":   platform.machine(),
    }


class ManifestGenerator:
    """Generates tamper-evident forensic manifest.json files with full provenance."""

    def generate_manifest(
        self,
        case_id: str,
        session_id: str,
        job_id: str,
        agent_id: str,
        files_dir: str,
        output_manifest_path: Optional[str] = None,
        build_id: Optional[str] = None,
        source_revision: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        abs_files_dir = os.path.abspath(files_dir)

        file_entries: List[Dict[str, Any]] = []
        if os.path.exists(abs_files_dir):
            for root, _, files in os.walk(abs_files_dir):
                for fname in sorted(files):
                    full_path = os.path.join(root, fname)
                    rel_path  = os.path.relpath(full_path, abs_files_dir)
                    file_entries.append({
                        "path":   rel_path.replace("\\", "/"),
                        "size":   os.path.getsize(full_path),
                        "sha256": calculate_sha256(full_path),
                    })

        timestamp = datetime.now(timezone.utc).isoformat()
        manifest: Dict[str, Any] = {
            "version":    "2.0",
            "case_id":    case_id,
            "session_id": session_id,
            "job_id":     job_id,
            "agent_id":   agent_id,
            "timestamp":  timestamp,
            "file_count": len(file_entries),
            "files_base": abs_files_dir,   # stored so verify_manifest is self-contained
            "files":      file_entries,
            "provenance": {
                "source_revision": source_revision or _git_revision(),
                "build_id":        build_id or "N/A",
                "platform":        platform.platform(),
                "python_version":  platform.python_version(),
                "toolchain":       _toolchain_info(),
                "configuration":   configuration or {},
            },
        }

        digest_src = json.dumps(
            {"files": file_entries, "provenance": manifest["provenance"]},
            sort_keys=True
        )
        manifest["manifest_sha256"] = hashlib.sha256(digest_src.encode()).hexdigest()

        if output_manifest_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_manifest_path)),
                        exist_ok=True)
            with open(output_manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

        return manifest

    def verify_manifest(self, manifest_path: str) -> Dict[str, Any]:
        """
        Re-verify a manifest file: re-hash all listed files and compare.
        Uses `files_base` stored in the manifest for path resolution.
        Falls back to the manifest's directory if `files_base` is absent.
        """
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)

        # Prefer the stored files_base; fall back to manifest directory
        files_base = manifest.get("files_base") or os.path.dirname(manifest_path)

        mismatches, missing = [], []
        for entry in manifest.get("files", []):
            full = os.path.join(files_base, entry["path"])
            if not os.path.exists(full):
                missing.append(entry["path"])
                continue
            actual = calculate_sha256(full)
            if actual != entry["sha256"]:
                mismatches.append({
                    "path":   entry["path"],
                    "stored": entry["sha256"],
                    "actual": actual,
                })

        # Re-verify manifest_sha256
        digest_src = json.dumps(
            {"files": manifest["files"],
             "provenance": manifest.get("provenance", {})},
            sort_keys=True
        )
        computed = hashlib.sha256(digest_src.encode()).hexdigest()
        manifest_hash_ok = computed == manifest.get("manifest_sha256", "")

        intact = not mismatches and not missing and manifest_hash_ok
        return {
            "intact":               intact,
            "manifest_hash_valid":  manifest_hash_ok,
            "file_mismatches":      mismatches,
            "missing_files":        missing,
            "files_checked":        len(manifest.get("files", [])),
            "provenance":           manifest.get("provenance", {}),
        }
