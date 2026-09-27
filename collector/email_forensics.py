"""Read-only local email artifact metadata collector.

Searches endpoint user profile directories and system mail stores for email artifacts
(.eml, .msg, .mbox, .pst, .ost, maildir). Parses RFC-822 headers, message metadata,
body snippets, and attachment listings.
"""
import email
import mailbox
import os
import re
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional

_MAX_ARTIFACTS = 300
_MAX_MESSAGES_PER_MAILBOX = 100
_MAX_HEADER_BYTES = 128 * 1024


def _roots() -> List[Path]:
    roots: List[Path] = []
    home = Path.home()
    cwd = Path.cwd()
    candidates = [
        cwd / "evidence",
        cwd / "samples",
        cwd / "runtime",
        cwd / "examples",
        cwd,
        home / "AppData" / "Local" / "Microsoft" / "Outlook",
        home / "AppData" / "Roaming" / "Microsoft" / "Outlook",
        home / "Documents" / "Outlook Files",
        home / "AppData" / "Roaming" / "Thunderbird" / "Profiles",
        home / "Desktop",
        home / "Downloads",
        home / "Documents",
        home,
        home / ".thunderbird",
        home / ".local" / "share" / "evolution",
        home / ".mail",
        Path("/var/mail"),
        Path("/var/spool/mail")
    ]
    
    # On Windows, check user directories under C:\Users if accessible
    if sys.platform == "win32":
        users_dir = Path("C:/Users")
        if users_dir.exists():
            try:
                for user_folder in users_dir.iterdir():
                    if user_folder.is_dir() and not user_folder.name.startswith("."):
                        candidates.append(user_folder / "Downloads")
                        candidates.append(user_folder / "Documents")
                        candidates.append(user_folder / "Desktop")
            except Exception:
                pass

    seen = set()
    for path in candidates:
        try:
            if path.exists() and str(path) not in seen:
                seen.add(str(path))
                roots.append(path)
        except Exception:
            continue
    return roots


def _artifact(path: Path) -> Dict[str, Any]:
    try:
        stat = path.stat()
        return {
            "artifact_type": path.suffix.lower().lstrip(".") or "mailbox",
            "path": str(path),
            "size_bytes": stat.st_size,
            "modified_time": stat.st_mtime,
            "status": "metadata_only",
        }
    except Exception:
        return {
            "artifact_type": path.suffix.lower().lstrip(".") or "mailbox",
            "path": str(path),
            "size_bytes": 0,
            "modified_time": 0,
            "status": "access_error",
        }


def _clean_human_readable_text(text: str) -> str:
    """Format raw email body text or HTML into clean, human-readable prose."""
    if not text:
        return ""
    import html
    import quopri
    try:
        if "=" in text and any(c in text for c in ("=3D", "=20", "=\n", "=\r\n")):
            text = quopri.decodestring(text.encode("utf-8", errors="ignore")).decode("utf-8", errors="ignore")
    except Exception:
        pass
    text = html.unescape(text)
    text = re.sub(r"<(br|p|div|tr|li|h[1-6])\b[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    lines = [line.strip() for line in text.splitlines()]
    clean_lines = []
    prev_blank = False
    for line in lines:
        if not line:
            if not prev_blank:
                clean_lines.append("")
                prev_blank = True
        else:
            clean_lines.append(line)
            prev_blank = False
    return "\n".join(clean_lines).strip() or text.strip()


def _extract_body_and_attachments(msg: email.message.EmailMessage) -> Dict[str, Any]:
    import hashlib
    body_text = ""
    attachments = []
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                if filename or "attachment" in content_disposition:
                    data = payload or b""
                    h_sha256 = hashlib.sha256(data).hexdigest() if data else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    attachments.append({
                        "filename": filename or "attachment.bin",
                        "size_bytes": len(data),
                        "mime": part.get_content_type() or "application/octet-stream",
                        "hash_sha256": h_sha256,
                    })
                elif part.get_content_type() in ("text/plain", "text/html") and not body_text:
                    if payload:
                        body_text = payload.decode(errors="replace")[:100000]
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode(errors="replace")[:100000]
    except Exception:
        pass
    cleaned_body = _clean_human_readable_text(body_text)
    return {"body_preview": cleaned_body, "attachments": attachments}


def _message_headers(path: Path) -> List[Dict[str, Any]]:
    headers: List[Dict[str, Any]] = []
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_HEADER_BYTES)
        message = BytesParser(policy=policy.default).parsebytes(raw)
        extra = _extract_body_and_attachments(message)
        
        # Collect all RFC headers as dictionary
        header_dict = {}
        for k, v in message.items():
            header_dict[str(k)] = str(v)

        headers.append({
            "artifact_type": "eml",
            "path": str(path),
            "from": str(message.get("From", "")),
            "to": str(message.get("To", "")),
            "cc": str(message.get("Cc", "")),
            "subject": str(message.get("Subject", "")),
            "date": str(message.get("Date", "")),
            "message_id": str(message.get("Message-ID", "")),
            "headers": header_dict,
            "body_preview": extra["body_preview"],
            "attachments": extra["attachments"],
            "body_collected": False,
        })
    except (OSError, ValueError, email.errors.MessageParseError):
        return []
    return headers


def _parse_msg_file(path: Path) -> List[Dict[str, Any]]:
    """Basic fallback parser for .msg files without requiring compound binary dependencies."""
    try:
        with path.open("rb") as f:
            raw = f.read(_MAX_HEADER_BYTES)
        # Search for ASCII/UTF-16 headers in raw compound binary
        text = raw.decode("latin-1", errors="ignore")
        subj_match = re.search(r"Subject[\:\s]+([^\r\n\x00]+)", text, re.IGNORECASE)
        from_match = re.search(r"From[\:\s]+([^\r\n\x00]+)", text, re.IGNORECASE)
        to_match = re.search(r"To[\:\s]+([^\r\n\x00]+)", text, re.IGNORECASE)
        
        stat = path.stat()
        return [{
            "artifact_type": "msg",
            "path": str(path),
            "from": from_match.group(1).strip() if from_match else "Outlook MSG File",
            "to": to_match.group(1).strip() if to_match else "",
            "subject": subj_match.group(1).strip() if subj_match else path.name,
            "date": str(stat.st_mtime),
            "message_id": f"msg_{stat.st_size}_{stat.st_mtime}",
            "body_preview": "Binary Outlook MSG artifact detected on endpoint.",
            "attachments": [],
            "body_collected": True,
        }]
    except Exception:
        return []


def _mailbox_headers(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        box = mailbox.Maildir(path) if path.is_dir() else mailbox.mbox(path)
        for index, message in enumerate(box):
            if index >= _MAX_MESSAGES_PER_MAILBOX:
                break
            msg_obj = email.message_from_string(str(message))
            extra = _extract_body_and_attachments(msg_obj)
            rows.append({
                "artifact_type": "mailbox_message",
                "path": str(path),
                "from": str(message.get("From", "")),
                "to": str(message.get("To", "")),
                "cc": str(message.get("Cc", "")),
                "subject": str(message.get("Subject", "")),
                "date": str(message.get("Date", "")),
                "message_id": str(message.get("Message-ID", "")),
                "body_preview": extra["body_preview"],
                "attachments": extra["attachments"],
                "body_collected": bool(extra["body_preview"]),
            })
    except (OSError, ValueError, mailbox.Error):
        return []
    return rows


def _get_mail_client_telemetry() -> List[Dict[str, Any]]:
    """Collect installed/configured mail client metadata when no email files are found."""
    clients = []
    home = Path.home()

    # Check for common mail client indicators
    mail_client_paths = {
        "Outlook": [
            home / "AppData" / "Local" / "Microsoft" / "Outlook",
            home / "AppData" / "Roaming" / "Microsoft" / "Outlook",
        ],
        "Thunderbird": [
            home / "AppData" / "Roaming" / "Thunderbird",
            home / ".thunderbird",
        ],
        "Windows Mail": [
            home / "AppData" / "Local" / "Packages",
        ],
        "Evolution": [
            home / ".local" / "share" / "evolution",
        ],
    }

    for client_name, paths in mail_client_paths.items():
        for p in paths:
            try:
                if p.exists():
                    stat = p.stat()
                    clients.append({
                        "artifact_type": "mail_client_store",
                        "path": str(p),
                        "from": "",
                        "to": "",
                        "subject": f"{client_name} Profile/Store Directory Detected",
                        "date": str(stat.st_mtime),
                        "message_id": "",
                        "size_bytes": 0,
                        "body_preview": (
                            f"{client_name} mail store directory detected on this endpoint. "
                            "No parseable .eml/.mbox/.pst files found in standard scan depth. "
                            "Run a full forensic job to collect email artifacts."
                        ),
                        "attachments": [],
                        "body_collected": False,
                        "status": "store_directory_only",
                    })
                    break  # Only report each client once
            except Exception:
                pass

def _get_linux_browser_history() -> List[Dict[str, Any]]:
    """Read Chrome, Chromium, Brave, Edge and Firefox browser history on Linux."""
    import glob, sqlite3, tempfile, shutil
    rows: List[Dict[str, Any]] = []

    chrome_patterns = [
        os.path.expanduser("~/.config/google-chrome/*/History"),
        os.path.expanduser("~/.config/chromium/*/History"),
        os.path.expanduser("~/.config/BraveSoftware/Brave-Browser/*/History"),
        os.path.expanduser("~/.config/microsoft-edge/*/History"),
    ]
    for pattern in chrome_patterns:
        for db_path in glob.glob(pattern):
            try:
                with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
                    tmp_name = tmp.name
                shutil.copy2(db_path, tmp_name)
                con = sqlite3.connect(tmp_name)
                cur = con.cursor()
                cur.execute("SELECT url,title,last_visit_time,visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 500")
                browser = ("Chrome" if "chrome" in db_path.lower()
                           else "Brave" if "brave" in db_path.lower()
                           else "Edge" if "edge" in db_path.lower() else "Chromium")
                for url, title, ts, vc in cur.fetchall():
                    rows.append({"browser": browser, "url": str(url or ""), "title": str(title or ""),
                                 "timestamp": str(ts or ""), "visit_count": vc or 1, "source_path": db_path})
                con.close()
                try: os.unlink(tmp_name)
                except Exception: pass
            except Exception:
                continue

    ff_patterns = [
        os.path.expanduser("~/.mozilla/firefox/*/places.sqlite"),
        os.path.expanduser("~/snap/firefox/common/.mozilla/firefox/*/places.sqlite"),
        os.path.expanduser("~/.var/app/org.mozilla.firefox/.mozilla/firefox/*/places.sqlite"),
    ]
    for pattern in ff_patterns:
        for db_path in glob.glob(pattern):
            try:
                with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
                    tmp_name = tmp.name
                shutil.copy2(db_path, tmp_name)
                con = sqlite3.connect(tmp_name)
                cur = con.cursor()
                cur.execute(
                    "SELECT p.url, p.title, h.visit_date, p.visit_count "
                    "FROM moz_places p "
                    "LEFT JOIN moz_historyvisits h ON h.place_id = p.id "
                    "ORDER BY h.visit_date DESC LIMIT 500"
                )
                for url, title, ts, vc in cur.fetchall():
                    rows.append({"browser": "Firefox", "url": str(url or ""), "title": str(title or ""),
                                 "timestamp": str(ts or ""), "visit_count": vc or 1, "source_path": db_path})
                con.close()
                try: os.unlink(tmp_name)
                except Exception: pass
            except Exception:
                continue

    return rows


def _get_webmail_browser_artifacts() -> List[Dict[str, Any]]:
    """Extract Gmail, Outlook Web, Yahoo, and ProtonMail sessions from browser history.

    OS-aware: uses Windows collector on Windows, local reader on Linux/macOS.
    Also covers Firefox on Linux (default browser on Kali/Ubuntu).
    """
    webmail_keywords = (
        "mail.google.com", "gmail.com",
        "outlook.office.com", "outlook.live.com", "outlook.com/mail",
        "mail.yahoo.com", "proton.me", "protonmail.com",
        "webmail", "roundcube", "squirrelmail",
    )

    history: List[Dict[str, Any]] = []
    import sys
    if sys.platform == "win32":
        try:
            from collector.windows_collector import get_windows_browser_history
            history = get_windows_browser_history() or []
        except Exception:
            pass
    else:
        try:
            history = _get_linux_browser_history()
        except Exception:
            pass

    webmail_artifacts = []
    seen_urls: set = set()
    for item in history:
        url   = str(item.get("url", ""))
        title = str(item.get("title", ""))
        if not any(kw in url.lower() for kw in webmail_keywords):
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)

        email_match = re.search(r"[\w\.\+\-]+@[\w\.\-]+\.\w{2,}", title + " " + url)
        acct = email_match.group(0) if email_match else "Webmail User"

        if "google" in url or "gmail" in url:
            provider = "Google Gmail (Webmail)"
        elif "outlook" in url or "office" in url:
            provider = "Outlook Web / Office 365"
        elif "yahoo" in url:
            provider = "Yahoo Mail (Webmail)"
        elif "proton" in url:
            provider = "ProtonMail (Webmail)"
        else:
            provider = "Webmail Service"

        browser_name = item.get("browser", "Web Browser")
        visit_count  = item.get("visit_count", 1)
        clean_title  = title if (title and not title.lower().startswith("http")) else f"{provider} Session"
        readable_body = (
            f"Webmail Activity Logged: Account '{acct}' accessed {provider} via {browser_name}.\n"
            f"Page Title: \"{clean_title}\"\n"
            f"Session Records: {visit_count} visit(s) detected in browser history."
        )
        webmail_artifacts.append({
            "artifact_type": "webmail_session",
            "path": item.get("source_path", "Browser History Store"),
            "from": acct,
            "to": f"{provider} Portal",
            "cc": "",
            "subject": clean_title,
            "date": item.get("timestamp") or "",
            "message_id": f"webmail_{abs(hash(url))}",
            "body_preview": readable_body,
            "attachments": [],
            "body_collected": False,
        })
        if len(webmail_artifacts) >= 50:
            break

    return webmail_artifacts




def _classify_email(item: Dict[str, Any]) -> Dict[str, Any]:
    """Tag a real email dictionary with forensic category, badges, and risk flags based on its actual headers and content."""
    frm = str(item.get("from", "")).lower()
    to = str(item.get("to", "")).lower()
    subj = str(item.get("subject", "")).lower()
    body = str(item.get("body_preview", "")).lower()
    path = str(item.get("path", "")).lower()
    is_del = bool(item.get("is_deleted") or "trash" in path or "deleted" in path or item.get("status") == "DELETED" or "deleted" in subj)
    attachments = item.get("attachments") or []

    cat = item.get("category")
    flags = list(item.get("forensic_flags") or [])

    if not cat:
        personal_domains = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "protonmail.com", "aol.com"}
        is_personal_from = any(d in frm for d in personal_domains)
        is_personal_to = any(d in to for d in personal_domains)

        exfil_keywords = {"confidential", "exfiltration", "dump", "export", "pii", "hashes", "database", "passwords", "backup", "secret"}
        suspicious_keywords = {"urgent wire", "invoice overdue", "verify password", "account suspended", "click link", "security alert", "password expiration", "exe"}

        if is_del:
            cat = "deleted"
            if "DELETED_ARTIFACT" not in flags: flags.append("DELETED_ARTIFACT")
        elif any(kw in subj or kw in body for kw in suspicious_keywords) or "spoof" in subj:
            cat = "suspicious"
            if "SUSPICIOUS_PHISHING" not in flags: flags.append("SUSPICIOUS_PHISHING")
        elif any(kw in subj or kw in body for kw in exfil_keywords):
            cat = "data_transfer"
            if "DATA_TRANSFER" not in flags: flags.append("DATA_TRANSFER")
            if "CONFIDENTIAL_KEYWORDS" not in flags: flags.append("CONFIDENTIAL_KEYWORDS")
        elif len(attachments) > 0:
            cat = "data_transfer"
            if "DATA_TRANSFER" not in flags: flags.append("DATA_TRANSFER")
        elif is_personal_from or is_personal_to:
            cat = "personal"
            if "PERSONAL_WEBMAIL" not in flags: flags.append("PERSONAL_WEBMAIL")
        else:
            cat = "company"
            if "CORPORATE_INTERNAL" not in flags: flags.append("CORPORATE_INTERNAL")

    cat_labels = {
        "company": "🏢 Company",
        "personal": "👤 Personal",
        "deleted": "🗑️ Deleted",
        "data_transfer": "📦 Data Transfer",
        "suspicious": "⚠️ Suspicious",
        "encrypted": "🔒 Encrypted",
    }

    item["category"] = cat
    item["category_label"] = cat_labels.get(cat, "📩 Email")
    item["forensic_flags"] = flags
    item["is_deleted"] = is_del
    if is_del and not item.get("when_deleted"):
        item["when_deleted"] = item.get("date") or "Recently Deleted"
    return item


def get_email_forensics() -> List[Dict[str, Any]]:
    """Return exact local email artifacts, RFC headers, and message previews extracted from the target system.
    Scans Outlook profiles, Thunderbird stores, Windows Mail databases, and user directories.
    """
    results: List[Dict[str, Any]] = []
    extensions = {".pst", ".ost", ".eml", ".msg", ".mbox", ".emlx"}

    skip_dir_parts = {"node_modules", "site-packages", "tcl", "tcl8.6", ".cache", "venv", ".git", "AppData\\Local\\Programs\\Python"}

    for root in _roots():
        try:
            paths_to_check = []
            if root.is_dir():
                try:
                    for dirpath, _, filenames in os.walk(root):
                        if any(part in dirpath.lower() for part in ("node_modules", "site-packages", "tcl", ".cache", "venv", ".git")):
                            continue
                        for f in filenames:
                            if len(paths_to_check) >= 150:
                                break
                            p = Path(dirpath) / f
                            if p.suffix.lower() in extensions:
                                paths_to_check.append(p)
                        if len(paths_to_check) >= 150:
                            break
                except Exception:
                    pass
            elif root.is_file() and root.suffix.lower() in extensions:
                paths_to_check.append(root)

            for path in paths_to_check:
                if len(results) >= _MAX_ARTIFACTS:
                    break
                ext = path.suffix.lower()
                if ext in {".eml", ".emlx"}:
                    results.extend(_message_headers(path))
                elif ext == ".msg":
                    parsed = _parse_msg_file(path)
                    if parsed and parsed[0].get("subject") != path.name:  # Ensure it's not a Tcl msg translation file
                        results.extend(parsed)
                elif ext == ".mbox":
                    results.extend(_mailbox_headers(path))
                else:
                    results.append(_artifact(path))
        except (OSError, PermissionError):
            continue

    # Also collect Webmail / Gmail browser session history artifacts
    webmail_artifacts = _get_webmail_browser_artifacts()
    results.extend(webmail_artifacts)

    classified_results = [_classify_email(r) for r in results if r.get("from") or r.get("subject") or r.get("path")]

    if not classified_results:
        client_telemetry = _get_mail_client_telemetry()
        if client_telemetry:
            return [_classify_email(ct) for ct in client_telemetry]
        return []

    return classified_results[:_MAX_ARTIFACTS]




