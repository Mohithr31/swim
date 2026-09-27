"""
JOCKY DFIR Gateway — B3 Messaging Forensics Engine
Defensive local artifact discovery for WhatsApp, Telegram, Signal, Discord, iMessage, and Android backups.
Discovers application presence, profile directories, local database presence, metadata, timestamps,
attachment metadata, file hashes, and message counts without collecting credentials, tokens, or session secrets.
"""
import os
import sys
import glob
import json
import shutil
import sqlite3
import hashlib
import platform
import tempfile
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


def _hash_file(path: str, max_size_mb: int = 10) -> Optional[str]:
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > max_size_mb * 1024 * 1024:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _safe_sqlite_copy(src_path: str) -> Optional[str]:
    if not os.path.isfile(src_path):
        return None
    try:
        temp_dir = tempfile.gettempdir()
        temp_filename = f"jocky_msg_{hashlib.md5(src_path.encode()).hexdigest()[:10]}_{os.path.basename(src_path)}"
        dest_path = os.path.join(temp_dir, temp_filename)
        shutil.copy2(src_path, dest_path)
        for ext in ["-wal", "-shm"]:
            wal_src = src_path + ext
            if os.path.exists(wal_src):
                try:
                    shutil.copy2(wal_src, dest_path + ext)
                except Exception:
                    pass
        return dest_path
    except Exception:
        return None


class MessagingForensicsCollector:
    """B3 Messaging Forensics Engine."""

    def __init__(self, device_id: str = "DEV-LOCAL", case_id: str = "CAS-DEFAULT"):
        self.device_id = device_id
        self.case_id = case_id
        self.os_type = platform.system()

    def collect_all_messaging_evidence(self) -> Dict[str, Any]:
        """Collect all local defensive messaging artifacts."""
        apps_data = {
            "WhatsApp": self.collect_whatsapp(),
            "Telegram": self.collect_telegram(),
            "Signal": self.collect_signal(),
            "Discord": self.collect_discord(),
            "iMessage": self.collect_imessage(),
            "Android": self.collect_android_artifacts(),
        }

        # Flatten all message records and database records
        all_messages: List[Dict[str, Any]] = []
        all_artifacts: List[Dict[str, Any]] = []

        for app_name, app_info in apps_data.items():
            for m in app_info.get("messages", []):
                all_messages.append(m)
            for a in app_info.get("artifacts", []):
                all_artifacts.append(a)

        any_collected = any(v.get("status") == "COLLECTED" for v in apps_data.values())
        overall_status = "COLLECTED" if any_collected else "NO_EVIDENCE_FOUND"

        return {
            "status": overall_status,
            "applications": apps_data,
            "total_messages": len(all_messages),
            "total_artifacts": len(all_artifacts),
            "messages": all_messages,
            "artifacts": all_artifacts
        }

    def collect_whatsapp(self) -> Dict[str, Any]:
        """Detect WhatsApp Desktop / UWP artifacts."""
        candidates = []
        if self.os_type == "Windows":
            local_appdata = os.environ.get("LOCALAPPDATA", "")
            appdata = os.environ.get("APPDATA", "")

            # UWP Package
            pkg_pattern = os.path.join(local_appdata, "Packages", "*WhatsApp*", "LocalState")
            for match in glob.glob(pkg_pattern):
                candidates.append(("UWP", match))

            # Classic desktop
            candidates.append(("Desktop", os.path.join(appdata, "WhatsApp")))
            candidates.append(("Desktop-Local", os.path.join(local_appdata, "WhatsApp")))

        elif self.os_type == "Linux":
            home = os.path.expanduser("~")
            candidates.append(("Linux-Client", os.path.join(home, ".config", "whatsapp-for-linux")))
            candidates.append(("Linux-Snap", os.path.join(home, "snap", "whatsapp-for-linux")))

        elif self.os_type == "Darwin":
            home = os.path.expanduser("~")
            candidates.append(("macOS", os.path.join(home, "Library", "Application Support", "WhatsApp")))
            candidates.append(("macOS-Container", os.path.join(home, "Library", "Containers", "net.whatsapp.WhatsApp", "Data", "Library", "Application Support", "WhatsApp")))

        found_path = None
        found_type = None
        for ctype, cpath in candidates:
            if os.path.isdir(cpath):
                found_path = cpath
                found_type = ctype
                break

        if not found_path:
            return {"status": "NOT_PRESENT", "app": "WhatsApp", "installed": False, "messages": [], "artifacts": []}

        artifacts = []
        messages = []
        db_path = None

        # Look for SQLite databases or ChatStorage
        for root, dirs, files in os.walk(found_path):
            for f in files:
                full_f = os.path.join(root, f)
                lower_f = f.lower()
                if lower_f.endswith((".sqlite", ".db")) or "chatstorage" in lower_f or "messages" in lower_f:
                    st = os.stat(full_f)
                    db_path = full_f
                    artifacts.append({
                        "name": f,
                        "path": full_f,
                        "size_bytes": st.st_size,
                        "modified": _to_iso(st.st_mtime),
                        "sha256": _hash_file(full_f),
                        "type": "Database"
                    })
                elif lower_f in ("settings.json", "config.json", "preferences"):
                    st = os.stat(full_f)
                    artifacts.append({
                        "name": f,
                        "path": full_f,
                        "size_bytes": st.st_size,
                        "modified": _to_iso(st.st_mtime),
                        "sha256": _hash_file(full_f),
                        "type": "Configuration"
                    })

        # Count attachments if directory exists
        attachments_dir = os.path.join(found_path, "shared") if os.path.isdir(os.path.join(found_path, "shared")) else None
        attachment_count = 0
        if attachments_dir:
            try:
                attachment_count = sum(len(files) for _, _, files in os.walk(attachments_dir))
            except Exception:
                pass

        # Parse SQLite metadata if accessible
        msg_count = 0
        if db_path:
            temp_db = _safe_sqlite_copy(db_path)
            if temp_db:
                try:
                    conn = sqlite3.connect(temp_db, timeout=3.0)
                    cur = conn.cursor()
                    # Check tables
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [r[0] for r in cur.fetchall()]
                    for tbl in ["messages", "message", "chat", "chats", "ZWAMESSAGE"]:
                        if tbl in tables:
                            try:
                                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                                msg_count = cur.fetchone()[0]
                                break
                            except Exception:
                                pass
                    conn.close()
                except Exception:
                    pass
                finally:
                    if os.path.exists(temp_db):
                        try:
                            os.remove(temp_db)
                        except Exception:
                            pass

        msg_record = {
            "id": f"MSG-WA-{hashlib.md5(found_path.encode()).hexdigest()[:10]}",
            "device_id": self.device_id,
            "case_id": self.case_id,
            "app_name": "WhatsApp",
            "profile_dir": found_path,
            "db_path": db_path or found_path,
            "message_id": "WA-LOCAL-SUMMARY",
            "conversation_id": "All Conversations",
            "sender": "Local User",
            "recipient": "Multiple Contacts",
            "direction": "LOCAL_ARCHIVE",
            "text_snippet": f"Local WhatsApp store: {found_type}. Database: {os.path.basename(db_path or 'None')}. Attachments: {attachment_count}.",
            "message_count": msg_count or 1,
            "attachment_names": f"{attachment_count} local attachment files detected" if attachment_count else None,
            "attachment_metadata": json.dumps({"attachment_count": attachment_count, "store_type": found_type}),
            "timestamp": _to_iso(os.path.getmtime(found_path)),
            "source": f"WhatsApp: {found_path}",
            "status": "COLLECTED",
            "sha256": _hash_file(db_path) if db_path else None
        }
        messages.append(msg_record)

        return {
            "status": "COLLECTED",
            "app": "WhatsApp",
            "installed": True,
            "type": found_type,
            "path": found_path,
            "database_present": bool(db_path),
            "message_count": msg_count,
            "attachment_count": attachment_count,
            "messages": messages,
            "artifacts": artifacts
        }

    def collect_telegram(self) -> Dict[str, Any]:
        """Detect Telegram Desktop artifacts."""
        tdata_path = None
        if self.os_type == "Windows":
            appdata = os.environ.get("APPDATA", "")
            cand = os.path.join(appdata, "Telegram Desktop", "tdata")
            if os.path.isdir(cand):
                tdata_path = cand
        elif self.os_type == "Linux":
            cand = os.path.expanduser("~/.local/share/TelegramDesktop/tdata")
            if os.path.isdir(cand):
                tdata_path = cand
        elif self.os_type == "Darwin":
            cand = os.path.expanduser("~/Library/Application Support/Telegram Desktop/tdata")
            if os.path.isdir(cand):
                tdata_path = cand

        if not tdata_path:
            return {"status": "NOT_PRESENT", "app": "Telegram", "installed": False, "messages": [], "artifacts": []}

        artifacts = []
        messages = []
        file_count = 0
        map_files = []

        try:
            for root, dirs, files in os.walk(tdata_path):
                file_count += len(files)
                for f in files:
                    if f.startswith("D877F783D5D3EF8C") or f == "key_datas" or f == "settingss":
                        full_f = os.path.join(root, f)
                        st = os.stat(full_f)
                        f_sha = _hash_file(full_f)
                        artifacts.append({
                            "name": f,
                            "path": full_f,
                            "size_bytes": st.st_size,
                            "modified": _to_iso(st.st_mtime),
                            "sha256": f_sha,
                            "type": "Telegram Storage Map / Key Data"
                        })
                        map_files.append(f)
        except Exception:
            pass

        t_record = {
            "id": f"MSG-TG-{hashlib.md5(tdata_path.encode()).hexdigest()[:10]}",
            "device_id": self.device_id,
            "case_id": self.case_id,
            "app_name": "Telegram",
            "profile_dir": tdata_path,
            "db_path": tdata_path,
            "message_id": "TG-TDATA-SUMMARY",
            "conversation_id": "Telegram Local Cache",
            "sender": "Local User",
            "recipient": "Telegram Cloud Contacts",
            "direction": "LOCAL_ARCHIVE",
            "text_snippet": f"Telegram Desktop tdata store present with {file_count} files and key_datas metadata. (Decryption keys protected).",
            "message_count": file_count,
            "attachment_names": f"{len(map_files)} map/storage structures detected",
            "attachment_metadata": json.dumps({"tdata_file_count": file_count, "map_structures": map_files[:10]}),
            "timestamp": _to_iso(os.path.getmtime(tdata_path)),
            "source": f"Telegram Desktop: {tdata_path}",
            "status": "COLLECTED",
            "sha256": artifacts[0].get("sha256") if artifacts else None
        }
        messages.append(t_record)

        return {
            "status": "COLLECTED",
            "app": "Telegram",
            "installed": True,
            "path": tdata_path,
            "file_count": file_count,
            "map_files": map_files,
            "messages": messages,
            "artifacts": artifacts
        }

    def collect_signal(self) -> Dict[str, Any]:
        """Detect Signal Desktop artifacts."""
        signal_dir = None
        if self.os_type == "Windows":
            appdata = os.environ.get("APPDATA", "")
            cand = os.path.join(appdata, "Signal")
            if os.path.isdir(cand):
                signal_dir = cand
        elif self.os_type == "Linux":
            cand = os.path.expanduser("~/.config/Signal")
            if os.path.isdir(cand):
                signal_dir = cand
        elif self.os_type == "Darwin":
            cand = os.path.expanduser("~/Library/Application Support/Signal")
            if os.path.isdir(cand):
                signal_dir = cand

        if not signal_dir:
            return {"status": "NOT_PRESENT", "app": "Signal", "installed": False, "messages": [], "artifacts": []}

        artifacts = []
        messages = []
        db_file = os.path.join(signal_dir, "sql", "db.sqlite")
        config_file = os.path.join(signal_dir, "config.json")
        att_dir = os.path.join(signal_dir, "attachments.noindex")

        att_count = 0
        if os.path.isdir(att_dir):
            try:
                att_count = sum(len(f) for _, _, f in os.walk(att_dir))
            except Exception:
                pass

        if os.path.isfile(config_file):
            st = os.stat(config_file)
            artifacts.append({
                "name": "config.json",
                "path": config_file,
                "size_bytes": st.st_size,
                "modified": _to_iso(st.st_mtime),
                "sha256": _hash_file(config_file),
                "type": "Configuration"
            })

        db_sha = None
        if os.path.isfile(db_file):
            st = os.stat(db_file)
            db_sha = _hash_file(db_file)
            artifacts.append({
                "name": "db.sqlite",
                "path": db_file,
                "size_bytes": st.st_size,
                "modified": _to_iso(st.st_mtime),
                "sha256": db_sha,
                "type": "Encrypted SQLCipher Database"
            })

        sig_record = {
            "id": f"MSG-SIG-{hashlib.md5(signal_dir.encode()).hexdigest()[:10]}",
            "device_id": self.device_id,
            "case_id": self.case_id,
            "app_name": "Signal",
            "profile_dir": signal_dir,
            "db_path": db_file if os.path.exists(db_file) else signal_dir,
            "message_id": "SIGNAL-STORE-SUMMARY",
            "conversation_id": "Signal SQLCipher Store",
            "sender": "Local User",
            "recipient": "Signal Contacts",
            "direction": "LOCAL_ARCHIVE",
            "text_snippet": f"Signal Desktop profile present. Encrypted db.sqlite present. Attachments: {att_count}.",
            "message_count": att_count or 1,
            "attachment_names": f"{att_count} attachments stored in attachments.noindex" if att_count else None,
            "attachment_metadata": json.dumps({"attachment_count": att_count, "db_present": os.path.exists(db_file)}),
            "timestamp": _to_iso(os.path.getmtime(signal_dir)),
            "source": f"Signal: {signal_dir}",
            "status": "COLLECTED",
            "sha256": db_sha
        }
        messages.append(sig_record)

        return {
            "status": "COLLECTED",
            "app": "Signal",
            "installed": True,
            "path": signal_dir,
            "db_present": os.path.isfile(db_file),
            "attachment_count": att_count,
            "messages": messages,
            "artifacts": artifacts
        }

    def collect_discord(self) -> Dict[str, Any]:
        """Detect Discord Desktop client artifacts (WITHOUT token theft)."""
        discord_dir = None
        if self.os_type == "Windows":
            appdata = os.environ.get("APPDATA", "")
            cand = os.path.join(appdata, "discord")
            if os.path.isdir(cand):
                discord_dir = cand
        elif self.os_type == "Linux":
            cand = os.path.expanduser("~/.config/discord")
            if os.path.isdir(cand):
                discord_dir = cand
        elif self.os_type == "Darwin":
            cand = os.path.expanduser("~/Library/Application Support/discord")
            if os.path.isdir(cand):
                discord_dir = cand

        if not discord_dir:
            return {"status": "NOT_PRESENT", "app": "Discord", "installed": False, "messages": [], "artifacts": []}

        artifacts = []
        messages = []
        settings_file = os.path.join(discord_dir, "settings.json")
        cache_dir = os.path.join(discord_dir, "Cache", "Cache_Data")
        leveldb_dir = os.path.join(discord_dir, "Local Storage", "leveldb")

        cache_count = 0
        if os.path.isdir(cache_dir):
            try:
                cache_count = len(os.listdir(cache_dir))
            except Exception:
                pass

        leveldb_count = 0
        if os.path.isdir(leveldb_dir):
            try:
                leveldb_count = len(os.listdir(leveldb_dir))
            except Exception:
                pass

        if os.path.isfile(settings_file):
            st = os.stat(settings_file)
            artifacts.append({
                "name": "settings.json",
                "path": settings_file,
                "size_bytes": st.st_size,
                "modified": _to_iso(st.st_mtime),
                "sha256": _hash_file(settings_file),
                "type": "Client Settings"
            })

        disc_record = {
            "id": f"MSG-DISC-{hashlib.md5(discord_dir.encode()).hexdigest()[:10]}",
            "device_id": self.device_id,
            "case_id": self.case_id,
            "app_name": "Discord",
            "profile_dir": discord_dir,
            "db_path": leveldb_dir if os.path.isdir(leveldb_dir) else discord_dir,
            "message_id": "DISCORD-LOCAL-SUMMARY",
            "conversation_id": "Discord Client Cache",
            "sender": "Local User",
            "recipient": "Discord Servers / DMs",
            "direction": "LOCAL_ARCHIVE",
            "text_snippet": f"Discord desktop client directory present. LevelDB storage files: {leveldb_count}. Cache objects: {cache_count}.",
            "message_count": cache_count or leveldb_count or 1,
            "attachment_names": f"{cache_count} cached media objects" if cache_count else None,
            "attachment_metadata": json.dumps({"cache_objects": cache_count, "leveldb_files": leveldb_count}),
            "timestamp": _to_iso(os.path.getmtime(discord_dir)),
            "source": f"Discord: {discord_dir}",
            "status": "COLLECTED",
            "sha256": artifacts[0].get("sha256") if artifacts else None
        }
        messages.append(disc_record)

        return {
            "status": "COLLECTED",
            "app": "Discord",
            "installed": True,
            "path": discord_dir,
            "leveldb_count": leveldb_count,
            "cache_count": cache_count,
            "messages": messages,
            "artifacts": artifacts
        }

    def collect_imessage(self) -> Dict[str, Any]:
        """Collect Apple iMessage chat.db (macOS only)."""
        if self.os_type != "Darwin":
            return {
                "status": "NOT_SUPPORTED",
                "app": "iMessage",
                "installed": False,
                "message": "iMessage chat.db is exclusive to macOS.",
                "messages": [],
                "artifacts": []
            }

        chat_db = os.path.expanduser("~/Library/Messages/chat.db")
        if not os.path.isfile(chat_db):
            return {"status": "NOT_PRESENT", "app": "iMessage", "installed": True, "messages": [], "artifacts": []}

        # Safe SQLite query
        temp_db = _safe_sqlite_copy(chat_db)
        if not temp_db:
            return {"status": "PERMISSION_REQUIRED", "app": "iMessage", "installed": True, "messages": [], "artifacts": []}

        artifacts = [{
            "name": "chat.db",
            "path": chat_db,
            "size_bytes": os.path.getsize(chat_db),
            "modified": _to_iso(os.path.getmtime(chat_db)),
            "sha256": _hash_file(chat_db),
            "type": "iMessage Database"
        }]

        messages = []
        msg_count = 0
        try:
            conn = sqlite3.connect(temp_db, timeout=3.0)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM message")
            msg_count = cur.fetchone()[0]

            cur.execute("""
                SELECT ROWID, guid, text, handle_id, date, is_from_me
                FROM message
                ORDER BY date DESC
                LIMIT 100
            """)
            for row in cur.fetchall():
                # Apple date is nanoseconds since 2001-01-01
                raw_d = row[4] or 0
                sec_d = (raw_d / 1000000000.0) + 978307200
                iso_d = _to_iso(sec_d)
                messages.append({
                    "id": f"MSG-IM-{row[0]}",
                    "device_id": self.device_id,
                    "case_id": self.case_id,
                    "app_name": "iMessage",
                    "profile_dir": os.path.dirname(chat_db),
                    "db_path": chat_db,
                    "message_id": row[1] or str(row[0]),
                    "conversation_id": f"Handle-{row[3]}",
                    "sender": "Local User" if row[5] else f"Contact-{row[3]}",
                    "recipient": f"Contact-{row[3]}" if row[5] else "Local User",
                    "direction": "OUTGOING" if row[5] else "INCOMING",
                    "text_snippet": (row[2] or "")[:200],
                    "message_count": 1,
                    "attachment_names": None,
                    "attachment_metadata": None,
                    "timestamp": iso_d,
                    "source": chat_db,
                    "status": "COLLECTED",
                    "sha256": None
                })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except Exception:
                    pass

        return {
            "status": "COLLECTED",
            "app": "iMessage",
            "installed": True,
            "path": chat_db,
            "message_count": msg_count,
            "messages": messages,
            "artifacts": artifacts
        }

    def collect_android_artifacts(self) -> Dict[str, Any]:
        """Detect local Android backup or synchronization archives."""
        user_prof = os.environ.get("USERPROFILE", os.path.expanduser("~"))
        candidates = [
            os.path.join(user_prof, "Apple", "MobileSync", "Backup"),
            os.path.join(os.environ.get("APPDATA", ""), "Apple Computer", "MobileSync", "Backup"),
            os.path.join(user_prof, "Downloads"),
            os.path.join(user_prof, "Documents"),
        ]

        found_backups = []
        artifacts = []
        for cdir in candidates:
            if not os.path.isdir(cdir):
                continue
            # Look for backup folders or android backup .ab / sms xml files
            try:
                for entry in os.listdir(cdir)[:100]:
                    full_p = os.path.join(cdir, entry)
                    lower = entry.lower()
                    if lower.endswith((".ab", ".backup")) or "sms" in lower and lower.endswith(".xml"):
                        st = os.stat(full_p)
                        found_backups.append(full_p)
                        artifacts.append({
                            "name": entry,
                            "path": full_p,
                            "size_bytes": st.st_size,
                            "modified": _to_iso(st.st_mtime),
                            "sha256": _hash_file(full_p),
                            "type": "Android / Mobile Backup Artifact"
                        })
            except Exception:
                pass

        if not found_backups:
            return {"status": "NO_EVIDENCE_FOUND", "app": "Android Backups", "installed": False, "messages": [], "artifacts": []}

        messages = [{
            "id": f"MSG-AND-{hashlib.md5(found_backups[0].encode()).hexdigest()[:10]}",
            "device_id": self.device_id,
            "case_id": self.case_id,
            "app_name": "Android / Mobile Backups",
            "profile_dir": os.path.dirname(found_backups[0]),
            "db_path": found_backups[0],
            "message_id": "AND-BACKUP-001",
            "conversation_id": "Mobile Backup Store",
            "sender": "Mobile Device",
            "recipient": "Local Host",
            "direction": "DEVICE_SYNC",
            "text_snippet": f"Found {len(found_backups)} mobile backup/SMS export files on local host.",
            "message_count": len(found_backups),
            "attachment_names": ", ".join(os.path.basename(p) for p in found_backups[:5]),
            "attachment_metadata": json.dumps({"backup_files": found_backups}),
            "timestamp": _to_iso(os.path.getmtime(found_backups[0])),
            "source": found_backups[0],
            "status": "COLLECTED",
            "sha256": artifacts[0].get("sha256") if artifacts else None
        }]

        return {
            "status": "COLLECTED",
            "app": "Android Backups",
            "installed": True,
            "backup_count": len(found_backups),
            "messages": messages,
            "artifacts": artifacts
        }
