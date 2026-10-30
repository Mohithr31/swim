"""
Tiny Monitor — B4 Email Forensics Engine
Safe local discovery of email clients, profiles, mailboxes (PST, OST, MBOX, EML, MSG),
message metadata, and attachment metadata across Windows, Linux, and macOS.
Defensively extracts metadata (sender, recipient, subject, timestamp, attachments)
WITHOUT extracting passwords or authentication tokens.
"""
import os
import sys
import glob
import json
import email
import mailbox
import hashlib
import platform
import shutil
from email import policy
from email.parser import BytesParser
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

try:
    import winreg
except ImportError:
    winreg = None


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


def _hash_file(path: str, max_size_mb: int = 15) -> Optional[str]:
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


class EmailForensicsCollector:
    """B4 Email Forensics Engine."""

    def __init__(self, device_id: str = "DEV-LOCAL", case_id: str = "CAS-DEFAULT"):
        self.device_id = device_id
        self.case_id = case_id
        self.os_type = platform.system()

    def collect_all_email_evidence(self) -> Dict[str, Any]:
        """Execute complete B4 email forensic collection."""
        clients = self.detect_mail_clients()
        profiles = self.collect_email_profiles()
        mailboxes, artifacts = self.discover_mailboxes_and_artifacts()
        messages, attachments = self.parse_message_metadata(mailboxes, artifacts)

        any_evidence = bool(mailboxes or messages or profiles or [c for c in clients if c.get("installed")])
        status = "COLLECTED" if (mailboxes or messages) else ("NO_EVIDENCE_FOUND" if any_evidence else "NOT_PRESENT")

        return {
            "status": status,
            "clients": clients,
            "profiles": profiles,
            "mailboxes": mailboxes,
            "messages": messages,
            "attachments": attachments,
            "artifacts": artifacts
        }

    def detect_mail_clients(self) -> List[Dict[str, Any]]:
        """Detect installed mail clients on current OS."""
        clients = []

        # 1. Microsoft Outlook (Windows)
        outlook_installed = False
        outlook_version = "N/A"
        outlook_path = ""
        if self.os_type == "Windows" and winreg:
            # Check Outlook registry
            for key_path in [r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE",
                            r"SOFTWARE\Microsoft\Office\16.0\Outlook",
                            r"SOFTWARE\Microsoft\Office\15.0\Outlook"]:
                try:
                    k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                    try:
                        v, _ = winreg.QueryValue(k, "")
                        if v and os.path.exists(v):
                            outlook_installed = True
                            outlook_path = v
                    except Exception:
                        outlook_installed = True
                    winreg.CloseKey(k)
                    if outlook_installed:
                        break
                except Exception:
                    pass

        clients.append({
            "name": "Microsoft Outlook",
            "installed": outlook_installed,
            "executable_path": outlook_path or ("Detected in Registry" if outlook_installed else "Not Installed"),
            "os": "Windows",
            "status": "COLLECTED" if outlook_installed else "NOT_PRESENT"
        })

        # 2. Windows Mail / New Outlook
        winmail_installed = False
        if self.os_type == "Windows":
            local_appdata = os.environ.get("LOCALAPPDATA", "")
            # Check for Windows Mail app or new Outlook package
            matches = glob.glob(os.path.join(local_appdata, "Packages", "*OutlookForWindows*", "LocalState"))
            matches += glob.glob(os.path.join(local_appdata, "Packages", "*windowscommunicationsapps*", "LocalState"))
            if matches:
                winmail_installed = True

        clients.append({
            "name": "Windows Mail / Outlook (Modern)",
            "installed": winmail_installed,
            "executable_path": "UWP AppX Package",
            "os": "Windows",
            "status": "COLLECTED" if winmail_installed else "NOT_PRESENT"
        })

        # 3. Mozilla Thunderbird
        tb_installed = False
        tb_path = ""
        if self.os_type == "Windows":
            appdata = os.environ.get("APPDATA", "")
            if os.path.isdir(os.path.join(appdata, "Thunderbird")):
                tb_installed = True
        elif self.os_type == "Linux":
            if os.path.isdir(os.path.expanduser("~/.thunderbird")) or shutil.which("thunderbird"):
                tb_installed = True
        elif self.os_type == "Darwin":
            if os.path.isdir(os.path.expanduser("~/Library/Thunderbird")) or os.path.isdir("/Applications/Thunderbird.app"):
                tb_installed = True

        clients.append({
            "name": "Mozilla Thunderbird",
            "installed": tb_installed,
            "executable_path": tb_path or ("Config detected" if tb_installed else "Not Installed"),
            "os": self.os_type,
            "status": "COLLECTED" if tb_installed else "NOT_PRESENT"
        })

        # 4. Apple Mail (macOS)
        if self.os_type == "Darwin":
            apple_mail_dir = os.path.expanduser("~/Library/Mail")
            am_installed = os.path.isdir(apple_mail_dir)
            clients.append({
                "name": "Apple Mail",
                "installed": am_installed,
                "executable_path": "/System/Applications/Mail.app",
                "os": "Darwin",
                "status": "COLLECTED" if am_installed else "NOT_PRESENT"
            })
        else:
            clients.append({
                "name": "Apple Mail",
                "installed": False,
                "executable_path": "N/A",
                "os": "Darwin",
                "status": "NOT_SUPPORTED"
            })

        return clients

    def collect_email_profiles(self) -> List[Dict[str, Any]]:
        """Discover profile directories for Outlook and Thunderbird."""
        profiles = []

        # Windows Outlook Profiles
        if self.os_type == "Windows" and winreg:
            outlook_profile_keys = [
                r"Software\Microsoft\Office\16.0\Outlook\Profiles",
                r"Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles"
            ]
            for pkey in outlook_profile_keys:
                try:
                    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, pkey, 0, winreg.KEY_READ)
                    n_sub = winreg.QueryInfoKey(k)[0]
                    for i in range(n_sub):
                        pname = winreg.EnumKey(k, i)
                        profiles.append({
                            "client": "Microsoft Outlook",
                            "profile_name": pname,
                            "path": f"HKCU\\{pkey}\\{pname}",
                            "status": "COLLECTED",
                            "source": "Windows Registry"
                        })
                    winreg.CloseKey(k)
                except Exception:
                    pass

        # Thunderbird Profiles
        tb_roots = []
        if self.os_type == "Windows":
            tb_roots.append(os.path.join(os.environ.get("APPDATA", ""), "Thunderbird", "Profiles"))
        elif self.os_type == "Linux":
            tb_roots.append(os.path.expanduser("~/.thunderbird"))
        elif self.os_type == "Darwin":
            tb_roots.append(os.path.expanduser("~/Library/Thunderbird/Profiles"))

        for tb_root in tb_roots:
            if os.path.isdir(tb_root):
                try:
                    for prof_dir in os.listdir(tb_root):
                        full_prof = os.path.join(tb_root, prof_dir)
                        if os.path.isdir(full_prof):
                            profiles.append({
                                "client": "Mozilla Thunderbird",
                                "profile_name": prof_dir,
                                "path": full_prof,
                                "status": "COLLECTED",
                                "source": "Thunderbird Profile Directory"
                            })
                except Exception:
                    pass

        return profiles

    def discover_mailboxes_and_artifacts(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Scan candidate paths for PST, OST, MBOX, EML, MSG stores."""
        user_prof = os.environ.get("USERPROFILE", os.path.expanduser("~"))
        local_app = os.environ.get("LOCALAPPDATA", "")
        app_data = os.environ.get("APPDATA", "")

        candidate_dirs = [
            os.path.join(local_app, "Microsoft", "Outlook"),
            os.path.join(app_data, "Microsoft", "Outlook"),
            os.path.join(user_prof, "Documents", "Outlook Files"),
            os.path.join(user_prof, "Documents"),
            os.path.join(user_prof, "Downloads"),
            os.path.join(user_prof, "Desktop"),
            os.path.join(app_data, "Thunderbird", "Profiles"),
            os.path.expanduser("~/.thunderbird"),
            os.path.expanduser("~/Library/Mail"),
        ]

        mailboxes: List[Dict[str, Any]] = []
        artifacts: List[Dict[str, Any]] = []
        seen_paths = set()

        for cdir in candidate_dirs:
            if not os.path.isdir(cdir):
                continue
            is_broad = any(b in cdir.lower() for b in ("documents", "downloads", "desktop")) and "outlook" not in cdir.lower()
            try:
                for root, dirs, files in os.walk(cdir):
                    rel = os.path.relpath(root, cdir)
                    max_d = 1 if is_broad else 3
                    if rel.count(os.sep) >= max_d:
                        dirs.clear()
                    for f in files:
                        lower_f = f.lower()
                        ext = os.path.splitext(lower_f)[1]
                        if ext in (".pst", ".ost", ".mbox", ".eml", ".msg") or lower_f in ("inbox", "sent"):
                            full_f = os.path.join(root, f)
                            if full_f in seen_paths:
                                continue
                            seen_paths.add(full_f)

                            try:
                                st = os.stat(full_f)
                                size = st.st_size
                                mod_iso = _to_iso(st.st_mtime)
                                sha = _hash_file(full_f) if size <= 15*1024*1024 else None

                                art_id = f"EML-ART-{hashlib.md5(full_f.encode()).hexdigest()[:10]}"
                                art_rec = {
                                    "id": art_id,
                                    "device_id": self.device_id,
                                    "case_id": self.case_id,
                                    "name": f,
                                    "path": full_f,
                                    "extension": ext or "mbox",
                                    "size_bytes": size,
                                    "modified": mod_iso,
                                    "sha256": sha,
                                    "status": "COLLECTED",
                                    "source": cdir
                                }
                                artifacts.append(art_rec)

                                if ext in (".pst", ".ost", ".mbox") or lower_f in ("inbox", "sent"):
                                    client_hint = "Microsoft Outlook" if ext in (".pst", ".ost") else "Thunderbird / Mbox"
                                    mailboxes.append({
                                        "id": f"MBX-{hashlib.md5(full_f.encode()).hexdigest()[:10]}",
                                        "device_id": self.device_id,
                                        "case_id": self.case_id,
                                        "client": client_hint,
                                        "mailbox_name": f,
                                        "path": full_f,
                                        "format": ext.upper().lstrip(".") or "MBOX",
                                        "size_bytes": size,
                                        "modified": mod_iso,
                                        "status": "COLLECTED",
                                        "sha256": sha
                                    })
                            except Exception:
                                continue
            except Exception:
                pass

        return mailboxes, artifacts

    def parse_message_metadata(
        self, mailboxes: List[Dict[str, Any]], artifacts: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Safely parse RFC-822 headers and metadata from .eml and .mbox files."""
        messages: List[Dict[str, Any]] = []
        attachments: List[Dict[str, Any]] = []

        parser = BytesParser(policy=policy.default)

        # Parse standalone .eml files
        eml_artifacts = [a for a in artifacts if a.get("extension") == ".eml"]
        for art in eml_artifacts[:100]:
            fpath = art["path"]
            try:
                with open(fpath, "rb") as fh:
                    msg = parser.parse(fh)

                msg_id_val = str(msg.get("Message-ID", "")).strip() or os.path.basename(fpath)
                subject = str(msg.get("Subject", "")).strip() or "(No Subject)"
                from_addr = str(msg.get("From", "")).strip()
                to_addr = str(msg.get("To", "")).strip()
                cc_addr = str(msg.get("Cc", "")).strip()
                date_hdr = str(msg.get("Date", "")).strip()

                # Extract body preview
                body_text = ""
                try:
                    body = msg.get_body(preferencelist=('plain', 'html'))
                    if body:
                        body_text = body.get_content()[:300]
                except Exception:
                    pass

                # Check attachments
                att_names = []
                for part in msg.iter_attachments():
                    fn = part.get_filename() or "attachment"
                    part_bytes = part.get_payload(decode=True) or b""
                    part_size = len(part_bytes)
                    part_sha = hashlib.sha256(part_bytes).hexdigest() if part_bytes else None

                    att_id = f"ATT-{hashlib.md5(f'{fpath}_{fn}'.encode()).hexdigest()[:10]}"
                    att_record = {
                        "id": att_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "message_id": msg_id_val,
                        "email_db_id": art["id"],
                        "filename": fn,
                        "size_bytes": part_size,
                        "mime_type": part.get_content_type() or "application/octet-stream",
                        "sha256": part_sha,
                        "file_path": fpath,
                        "timestamp": _to_iso(art["modified"]),
                        "source": fpath,
                        "status": "COLLECTED"
                    }
                    attachments.append(att_record)
                    att_names.append(fn)

                msg_record = {
                    "id": f"EMSG-{hashlib.md5(f'{fpath}_{msg_id_val}'.encode()).hexdigest()[:12]}",
                    "device_id": self.device_id,
                    "case_id": self.case_id,
                    "client_name": "RFC-822 EML File",
                    "mailbox_name": os.path.basename(fpath),
                    "mailbox_path": fpath,
                    "message_id": msg_id_val,
                    "from_addr": from_addr,
                    "to_addr": to_addr,
                    "cc_addr": cc_addr,
                    "subject": subject,
                    "date": date_hdr or art["modified"],
                    "body_snippet": body_text,
                    "has_attachments": 1 if att_names else 0,
                    "timestamp": _to_iso(art["modified"]),
                    "source": fpath,
                    "status": "COLLECTED",
                    "sha256": art.get("sha256")
                }
                messages.append(msg_record)
            except Exception:
                continue

        # If mailboxes (PST/OST) were found, add summary records for each
        for mb in mailboxes:
            fmt = mb.get("format", "")
            if fmt in ("PST", "OST"):
                # Register structured mailbox message summary
                messages.append({
                    "id": f"EMSG-MBX-{mb['id']}",
                    "device_id": self.device_id,
                    "case_id": self.case_id,
                    "client_name": mb.get("client", "Microsoft Outlook"),
                    "mailbox_name": mb.get("mailbox_name", "Outlook Store"),
                    "mailbox_path": mb.get("path"),
                    "message_id": f"STORE-{mb['id']}",
                    "from_addr": "Store Owner",
                    "to_addr": "Local Mailbox",
                    "cc_addr": "",
                    "subject": f"Outlook {fmt} Mail Store ({round(mb['size_bytes'] / (1024*1024), 2)} MB)",
                    "date": mb.get("modified"),
                    "body_snippet": f"Local Outlook {fmt} storage file: {mb.get('path')}. Forensic metadata collected without credential extraction.",
                    "has_attachments": 0,
                    "timestamp": mb.get("modified"),
                    "source": mb.get("path"),
                    "status": "COLLECTED",
                    "sha256": mb.get("sha256")
                })

        return messages, attachments
