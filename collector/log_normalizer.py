"""
JOCKY Unified Log Normalizer

Standardises log records from Linux journald/syslog/dmesg and Windows
Event Log into a common schema:
  timestamp, channel, event_id, level, severity_num,
  provider, message, source, raw, user, host

Covers P1 item: "Improve logs normalization".
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Common normalized schema keys (always present)
_REQUIRED_KEYS = (
    "timestamp", "channel", "event_id", "level",
    "severity_num", "provider", "message", "source", "raw",
)

# Syslog priority to level mapping
_SYSLOG_LEVELS = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# Windows EventRecord level mapping
_WIN_LEVELS = {
    1: "CRITICAL", 2: "ERROR", 3: "WARNING",
    4: "INFORMATION", 5: "VERBOSE",
}


def _ensure_utc(ts: str) -> str:
    """Best-effort normalization of timestamps to ISO 8601 UTC."""
    if not ts:
        return datetime.now(timezone.utc).isoformat()
    ts = ts.strip()
    # Already ISO with offset
    if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts):
        if ts.endswith("Z"):
            return ts[:-1] + "+00:00"
        return ts
    # Try common formats
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return ts


def generate_plain_english_description(event_id: str, channel: str, provider: str, level: str, message: str) -> str:
    """Generate a clear, plain-language description for non-technical users."""
    eid = str(event_id).strip()
    msg = str(message or "").strip()
    prov = str(provider or "").strip().lower()
    chan = str(channel or "").strip().lower()
    lvl = str(level or "").upper()

    win_events = {
        "4624": "Successful Sign-In: A user or background process successfully signed into this computer.",
        "4625": "Failed Sign-In Attempt: Someone tried to sign in using an invalid password or unauthorized account.",
        "4634": "Sign-Out Event: A logged-in user ended their active session and signed off.",
        "4648": "Credential Delegation Sign-In: A program or command was executed using alternate user credentials.",
        "4672": "Admin Privileges Assigned: Elevated administrative rights were granted to a user logon session.",
        "4720": "User Account Created: A new user account was added to this system.",
        "4722": "User Account Enabled: A previously disabled user account was reactivated.",
        "4723": "Password Change Attempt: An attempt was made to change an existing account password.",
        "4724": "Password Reset Attempt: An administrator attempted to reset a user account password.",
        "4726": "User Account Deleted: A user account was permanently deleted from the system.",
        "4732": "Added to Security Group: A user account was given elevated permissions in a security group.",
        "4740": "Account Lockout: An account was locked due to repeated incorrect password attempts.",
        "4688": "Program Execution: A new software application or background process was launched.",
        "4689": "Program Exit: A running application or process completed and closed.",
        "5156": "Firewall Connection Allowed: Network traffic was allowed by the Windows Firewall.",
        "5157": "Firewall Connection Blocked: Network traffic was blocked by the Windows Firewall.",
        "7001": "User Logon: User session connected to the Windows desktop interface.",
        "7002": "User Logoff: User session disconnected from the Windows desktop interface.",
        "7036": "Service State Changed: A background system service started, stopped, or restarted.",
        "7040": "Service Setting Modified: The startup mode of a system service was changed.",
        "1074": "System Restart/Shutdown: The computer was ordered to shut down or restart.",
        "6005": "Computer Booted Up: System Event Log service started, indicating the machine turned on.",
        "6006": "Clean Computer Shutdown: System Event Log service stopped during a normal shutdown.",
        "6008": "Unexpected Shutdown: The system shut down unexpectedly due to power loss or a crash.",
        "6009": "OS Version Detected: Operating system kernel version logged during system boot.",
        "1000": "Application Error Crash: A software application crashed due to an unhandled exception.",
        "1001": "Crash Report Generated: Windows generated a diagnostic report following an error.",
        "1002": "Application Hang/Freeze: An application stopped responding to user interactions.",
        "1102": "Security Log Cleared: The security audit log was wiped. This requires immediate investigation.",
        "7045": "New Service Installed: A new background service or device driver was installed."
    }

    if eid in win_events:
        return win_events[eid]

    if "ssh" in prov or "ssh" in chan or "pam" in prov:
        if "failed password" in msg.lower():
            return "Failed Remote Access: Invalid password attempt over SSH/network login."
        if "accepted" in msg.lower():
            return "Successful Remote Access: User logged in over SSH/network."
        if "session opened" in msg.lower():
            return "Terminal Session Started: A user opened an active command terminal."
        if "session closed" in msg.lower():
            return "Terminal Session Ended: A user closed their command terminal."

    if "sudo" in prov or "sudo" in msg.lower():
        return "Elevated Command (sudo): A user ran a command with administrator privileges."

    if "usb" in msg.lower() or "removable" in msg.lower():
        return "USB Device Event: Hardware storage device was plugged in, removed, or accessed."

    if "oom" in msg.lower() or "out of memory" in msg.lower():
        return "Memory Critical Warning: System ran low on RAM memory and closed a process."

    if "error" in lvl or "critical" in lvl:
        return f"System Alert ({lvl}): An operational error occurred in '{provider or channel or 'System'}'. Details: {msg[:120]}"
    if "warn" in lvl:
        return f"System Warning: '{provider or channel or 'System'}' reported a warning. Details: {msg[:120]}"

    if msg:
        clean = msg.replace("\r\n", " ").replace("\n", " ").strip()
        if len(clean) > 160:
            clean = clean[:160] + "..."
        return f"Activity Event ({provider or channel or 'System'}): {clean}"

    return f"Standard activity record from {provider or channel or 'System'}."


def _base_record(**kw: Any) -> Dict[str, Any]:
    eid = str(kw.get("event_id", ""))
    chan = str(kw.get("channel", ""))
    prov = str(kw.get("provider", ""))
    lvl = str(kw.get("level", "INFO"))
    msg = str(kw.get("message", ""))
    desc = kw.get("description") or generate_plain_english_description(eid, chan, prov, lvl, msg)

    return {
        "timestamp":    kw.get("timestamp", ""),
        "channel":      chan,
        "event_id":     eid,
        "level":        lvl,
        "severity_num": int(kw.get("severity_num", 6)),
        "provider":     prov,
        "message":      msg,
        "source":       kw.get("source", ""),
        "raw":          kw.get("raw", ""),
        "user":         kw.get("user", ""),
        "host":         kw.get("host", ""),
        "description":  desc,
    }


# ─── Linux normalizers ────────────────────────────────────────────────────────

# journald JSON field → normalized field mapping
_JOURNALD_MAP = {
    "__REALTIME_TIMESTAMP": None,   # handled specially
    "SYSLOG_IDENTIFIER": "provider",
    "SYSLOG_FACILITY":   None,
    "PRIORITY":          None,      # → severity_num + level
    "_COMM":             "provider",
    "_HOSTNAME":         "host",
    "_UID":              None,
    "MESSAGE":           "message",
    "SYSLOG_TIMESTAMP":  None,
}


def normalize_journald_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a single journald JSON log entry."""
    ts_raw = entry.get("__REALTIME_TIMESTAMP", "")
    if ts_raw and ts_raw.isdigit():
        # microseconds since epoch
        ts = datetime.fromtimestamp(int(ts_raw) / 1e6, tz=timezone.utc).isoformat()
    else:
        ts = _ensure_utc(str(ts_raw))

    priority = entry.get("PRIORITY", 6)
    try: priority = int(priority)
    except Exception: priority = 6

    provider = (entry.get("SYSLOG_IDENTIFIER")
                or entry.get("_COMM")
                or entry.get("_EXE", "")
                or "kernel")

    return _base_record(
        timestamp=ts,
        channel=entry.get("SYSLOG_FACILITY", provider),
        event_id=entry.get("MESSAGE_ID", ""),
        level=_SYSLOG_LEVELS.get(priority, "INFO"),
        severity_num=priority,
        provider=provider,
        message=str(entry.get("MESSAGE", "")),
        source="journald",
        raw=str(entry),
        user=str(entry.get("_UID", "")),
        host=str(entry.get("_HOSTNAME", "")),
    )


_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<ident>[^[:]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)


def normalize_syslog_line(line: str) -> Optional[Dict[str, Any]]:
    """Normalize a classic RFC 3164 syslog line."""
    m = _SYSLOG_RE.match(line.strip())
    if not m:
        return None
    g = m.groupdict()
    # Build a naive timestamp (no year in syslog)
    ts_str = f"{g['month']} {g['day']} {g['time']}"
    ts = _ensure_utc(ts_str)
    provider = g["ident"].strip().rstrip(":")
    return _base_record(
        timestamp=ts,
        channel=provider,
        event_id="",
        level="INFO",
        severity_num=6,
        provider=provider,
        message=g["message"],
        source="syslog",
        raw=line,
        host=g["host"],
    )


def normalize_dmesg_line(line: str) -> Optional[Dict[str, Any]]:
    """Normalize a dmesg line (with or without timestamp prefix)."""
    # Strip ANSI codes
    line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
    # Optional [    0.000000] prefix
    ts_prefix = re.match(r"^\[\s*(\d+\.\d+)\]", line)
    message = re.sub(r"^\[\s*\d+\.\d+\]\s*", "", line)
    return _base_record(
        timestamp=datetime.now(timezone.utc).isoformat(),  # dmesg has boot-relative time
        channel="kernel",
        event_id="",
        level="INFO",
        severity_num=6,
        provider="kernel",
        message=message,
        source="dmesg",
        raw=line,
    )


def normalize_linux_logs(raw_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize a list of raw Linux log records (journald JSON dicts or
    pre-parsed dicts from linux_collector) into the common schema.
    """
    normalized = []
    for rec in raw_logs:
        # Already has common schema keys → patch missing ones
        if "message" in rec and "source" in rec:
            n = _base_record(
                timestamp=_ensure_utc(rec.get("timestamp", "")),
                channel=rec.get("channel", rec.get("source", "")),
                event_id=str(rec.get("event_id", "")),
                level=rec.get("level", "INFO"),
                severity_num=int(rec.get("priority", rec.get("severity_num", 6))),
                provider=rec.get("provider", rec.get("channel", "")),
                message=rec.get("message", ""),
                source=rec.get("source", "journald"),
                raw=rec.get("raw", ""),
                user=rec.get("user", ""),
                host=rec.get("host", ""),
            )
        elif "__REALTIME_TIMESTAMP" in rec or "MESSAGE" in rec:
            n = normalize_journald_entry(rec)
        else:
            n = _base_record(**{k: rec.get(k, "") for k in _REQUIRED_KEYS})
        normalized.append(n)
    return normalized


# ─── Windows normalizer ───────────────────────────────────────────────────────

def normalize_windows_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize Windows Event Log records (from windows_collector) into the
    common schema.
    """
    normalized = []
    for evt in raw_events:
        level_num = int(evt.get("Level", evt.get("level_num", 4)))
        level_str = _WIN_LEVELS.get(level_num, "INFORMATION")
        # Map Windows level numbers to syslog-like severity_num for unified sorting
        sev_num = {1: 2, 2: 3, 3: 4, 4: 6, 5: 7}.get(level_num, 6)

        normalized.append(_base_record(
            timestamp=_ensure_utc(str(evt.get("TimeCreated", evt.get("timestamp", "")))),
            channel=str(evt.get("LogName", evt.get("channel", "System"))),
            event_id=str(evt.get("Id", evt.get("event_id", ""))),
            level=level_str,
            severity_num=sev_num,
            provider=str(evt.get("ProviderName", evt.get("provider", "Microsoft-Windows-Security-Auditing"))),
            message=str(evt.get("Message", evt.get("message", ""))),
            source="Windows Event Log",
            raw=str(evt.get("raw", "")),
            user=str(evt.get("UserId", evt.get("user", ""))),
            host=str(evt.get("MachineName", evt.get("host", ""))),
        ))
    return normalized


# ─── Unified entry point ──────────────────────────────────────────────────────

def normalize_logs(raw_logs: List[Dict[str, Any]],
                   platform: str = "linux") -> List[Dict[str, Any]]:
    """
    Normalize log records from any platform.
    platform: 'linux' | 'windows'
    """
    if platform.lower() == "windows":
        return normalize_windows_events(raw_logs)
    return normalize_linux_logs(raw_logs)
