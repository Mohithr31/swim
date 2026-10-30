"""
Tiny Monitor — B8 Filesystem Forensics Engine
Triage and recursive inventory of user folders (Desktop, Documents, Downloads, Pictures, Videos, Music).
Collects file attributes, timestamps, hashes, owner, permissions, and small-file preview safely.
Windows Volume Shadow Copy (VSS) discovery with strict permission and state reporting.
"""
import os
import sys
import glob
import json
import base64
import hashlib
import platform
import mimetypes
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


def _to_iso(dt_or_ts) -> str:
    if not dt_or_ts:
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


def _safe_hash_file(path: str, max_size_bytes: int = 15 * 1024 * 1024) -> Optional[str]:
    """Safely hash file up to max_size_bytes in streaming chunks without loading file into memory."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > max_size_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class FilesystemForensicsCollector:
    """B8 Filesystem Forensics Engine."""

    def __init__(
        self,
        device_id: str = "DEV-LOCAL",
        case_id: str = "CAS-DEFAULT",
        max_depth: int = 3,
        max_files_per_category: int = 150,
        max_hash_size_mb: int = 15
    ):
        self.device_id = device_id
        self.case_id = case_id
        self.max_depth = max_depth
        self.max_files_per_category = max_files_per_category
        self.max_hash_size_bytes = max_hash_size_mb * 1024 * 1024
        self.os_type = platform.system()

    def get_user_directories(self) -> Dict[str, str]:
        """Resolve standard user locations cross-platform."""
        user_home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        return {
            "Desktop": os.path.join(user_home, "Desktop"),
            "Documents": os.path.join(user_home, "Documents"),
            "Downloads": os.path.join(user_home, "Downloads"),
            "Pictures": os.path.join(user_home, "Pictures"),
            "Videos": os.path.join(user_home, "Videos"),
            "Music": os.path.join(user_home, "Music"),
        }

    def collect_all_filesystem_evidence(
        self,
        include_extensions: Optional[List[str]] = None,
        exclude_extensions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Perform triage inventory across standard user locations."""
        locations = self.get_user_directories()
        category_files: Dict[str, List[Dict[str, Any]]] = {}
        all_files: List[Dict[str, Any]] = []

        for category, folder_path in locations.items():
            if not os.path.isdir(folder_path):
                category_files[category] = []
                continue

            files_in_cat = self.scan_directory_recursive(
                folder_path,
                category=category,
                max_depth=self.max_depth,
                limit=self.max_files_per_category,
                include_extensions=include_extensions,
                exclude_extensions=exclude_extensions
            )
            category_files[category] = files_in_cat
            all_files.extend(files_in_cat)

        # Volume Shadow Copies (Windows)
        vss_info = self.collect_vss_snapshots()

        total_collected = len(all_files)
        status = "COLLECTED" if total_collected > 0 else "NO_EVIDENCE_FOUND"

        return {
            "status": status,
            "total_files": total_collected,
            "categories": category_files,
            "files": all_files,
            "vss": vss_info,
            "locations": locations
        }

    def scan_directory_recursive(
        self,
        root_dir: str,
        category: str = "Filesystem",
        max_depth: int = 3,
        limit: int = 150,
        include_extensions: Optional[List[str]] = None,
        exclude_extensions: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Scan directory recursively with safety bounds."""
        collected: List[Dict[str, Any]] = []
        if not os.path.isdir(root_dir):
            return collected

        norm_root = os.path.abspath(root_dir)
        inc_exts = {e.lower().lstrip(".") for e in include_extensions} if include_extensions else None
        exc_exts = {e.lower().lstrip(".") for e in exclude_extensions} if exclude_extensions else None

        try:
            for current_root, dirs, files in os.walk(norm_root):
                rel_path = os.path.relpath(current_root, norm_root)
                depth = 0 if rel_path == "." else rel_path.count(os.sep) + 1
                if depth >= max_depth:
                    dirs.clear()  # Do not descend deeper

                for f in files:
                    if len(collected) >= limit:
                        return collected

                    full_path = os.path.join(current_root, f)
                    ext = os.path.splitext(f)[1].lower().lstrip(".")

                    if inc_exts and ext not in inc_exts:
                        continue
                    if exc_exts and ext in exc_exts:
                        continue

                    try:
                        st = os.stat(full_path)
                        size = st.st_size
                        mime, _ = mimetypes.guess_type(full_path)

                        # Hash only if <= allowed size
                        f_hash = _safe_hash_file(full_path, self.max_hash_size_bytes) if size <= self.max_hash_size_bytes else None

                        fid = f"FS-{hashlib.md5(full_path.encode()).hexdigest()[:12]}"
                        collected.append({
                            "id": fid,
                            "device_id": self.device_id,
                            "case_id": self.case_id,
                            "path": full_path,
                            "filename": f,
                            "extension": f".{ext}" if ext else "",
                            "size_bytes": size,
                            "created_time": _to_iso(st.st_ctime),
                            "modified_time": _to_iso(st.st_mtime),
                            "accessed_time": _to_iso(st.st_atime),
                            "file_type": mime or ("Directory" if os.path.isdir(full_path) else "File"),
                            "owner": os.environ.get("USERNAME") or "User",
                            "permissions": oct(st.st_mode)[-3:],
                            "sha256": f_hash,
                            "is_directory": 0,
                            "is_deleted": 0,
                            "category": category,
                            "source": root_dir,
                            "status": "COLLECTED",
                            "timestamp": _to_iso(st.st_mtime)
                        })
                    except Exception:
                        continue
        except Exception:
            pass

        return collected

    def collect_vss_snapshots(self) -> Dict[str, Any]:
        """Detect Volume Shadow Copy Service (VSS) snapshots on Windows without fabrication."""
        if self.os_type != "Windows":
            return {
                "status": "NOT_SUPPORTED",
                "count": 0,
                "snapshots": [],
                "message": "Volume Shadow Copies (VSS) are exclusive to Windows NTFS."
            }

        try:
            # Query vssadmin
            out = subprocess.check_output(
                ["vssadmin", "list", "shadows"],
                text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=6
            )
            snapshots = []
            current_snap: Dict[str, Any] = {}
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Shadow Copy ID:"):
                    if current_snap:
                        snapshots.append(current_snap)
                    current_snap = {"id": line.split(":", 1)[1].strip()}
                elif line.startswith("Original Volume:") and current_snap:
                    current_snap["original_volume"] = line.split(":", 1)[1].strip()
                elif line.startswith("Creation Time:") and current_snap:
                    current_snap["creation_time"] = line.split(":", 1)[1].strip()
                elif line.startswith("Shadow Copy Volume:") and current_snap:
                    current_snap["shadow_volume"] = line.split(":", 1)[1].strip()

            if current_snap:
                snapshots.append(current_snap)

            return {
                "status": "COLLECTED" if snapshots else "NO_EVIDENCE_FOUND",
                "count": len(snapshots),
                "snapshots": snapshots
            }

        except subprocess.CalledProcessError:
            return {
                "status": "PERMISSION_REQUIRED",
                "count": 0,
                "snapshots": [],
                "message": "Administrator privileges required to query Volume Shadow Copies (vssadmin list shadows)."
            }
        except Exception as e:
            return {
                "status": "COLLECTION_ERROR",
                "count": 0,
                "snapshots": [],
                "error": str(e)
            }

    @staticmethod
    def get_file_content_preview(file_path: str, max_bytes: int = 100 * 1024) -> Dict[str, Any]:
        """Safe small-file content and hex preview."""
        if not os.path.isfile(file_path):
            return {"status": "NOT_PRESENT", "error": "File does not exist"}

        try:
            size = os.path.getsize(file_path)
            read_size = min(size, max_bytes)
            with open(file_path, "rb") as f:
                raw = f.read(read_size)

            mime, _ = mimetypes.guess_type(file_path)
            mime = mime or "application/octet-stream"

            is_text = False
            text_snippet = None
            try:
                text_snippet = raw.decode("utf-8")
                is_text = True
            except UnicodeDecodeError:
                try:
                    text_snippet = raw.decode("latin-1")
                    is_text = True
                except Exception:
                    pass

            hex_dump = []
            for i in range(0, min(len(raw), 512), 16):
                chunk = raw[i:i+16]
                hex_bytes = " ".join(f"{b:02X}" for b in chunk)
                ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                hex_dump.append(f"{i:08X}  {hex_bytes:<48}  |{ascii_chars}|")

            return {
                "status": "COLLECTED",
                "path": file_path,
                "size_bytes": size,
                "mime_type": mime,
                "is_text": is_text,
                "text_preview": text_snippet[:10000] if is_text else None,
                "hex_preview": "\n".join(hex_dump),
                "sha256": _safe_hash_file(file_path)
            }
        except PermissionError:
            return {"status": "PERMISSION_REQUIRED", "error": "Access Denied"}
        except Exception as e:
            return {"status": "COLLECTION_ERROR", "error": str(e)}
