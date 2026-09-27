"""JOCKY DFIR Investigator.

Defensive, metadata-only triage analysis. This module intentionally does not
extract, decrypt, or transmit credentials, cookies, session tokens, messages,
or other authentication material.
"""
from __future__ import annotations

import base64
import csv
import io
import ipaddress
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

SUSPICIOUS_PATH_RE = re.compile(r"(?:\\|/)(?:appdata|temp|tmp|public|downloads?)(?:\\|/)", re.I)
POWERSHELL_RE = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.I)
DOWNLOAD_SWITCH_RE = re.compile(r"(?:-enc(?:odedcommand)?\b|(?:iwr|invoke-webrequest|irm|invoke-restmethod)\b|(?:downloadstring|downloadfile)\b|(?:bitsadmin|certutil)\b)", re.I)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/])")
URL_RE = re.compile(r"https?://([^/\\\s:'\"]+)", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)

SEVERITY_ORDER = {"Low": 1, "Med": 2, "High": 3}


def _text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _pick(row: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    lowered = {str(k).lower().replace("-", "_"): v for k, v in row.items()}
    for key in keys:
        k = key.lower().replace("-", "_")
        if k in lowered and lowered[k] not in (None, ""):
            return lowered[k]
    return default


def parse_input(data: Any) -> List[Dict[str, Any]]:
    """Accept JSON object/list, JSONL, CSV text, or an already parsed list."""
    if isinstance(data, list):
        return [dict(x) for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("artifacts", "events", "records", "data", "timeline"):
            if isinstance(data.get(key), list):
                return [dict(x) for x in data[key] if isinstance(x, dict)]
        return [data]
    if not isinstance(data, str):
        raise ValueError("Input must be JSON/CSV text or a parsed JSON object/list")
    s = data.strip()
    if not s:
        return []
    try:
        return parse_input(json.loads(s))
    except json.JSONDecodeError:
        pass
    lines = s.splitlines()
    if lines and all(line.strip().startswith("{") for line in lines if line.strip()):
        out = []
        for line in lines:
            if line.strip():
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except json.JSONDecodeError:
                    continue
        if out:
            return out
    reader = csv.DictReader(io.StringIO(s))
    return [dict(r) for r in reader]


def _parse_ts(value: Any) -> Optional[datetime]:
    s = _text(value).strip()
    if not s:
        return None
    if s.isdigit():
        n = int(s)
        if n > 10**12:
            n /= 1000
        if n > 10**9:
            return datetime.fromtimestamp(n, tz=timezone.utc)
    try:
        x = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(x)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _iso(value: Any) -> str:
    dt = _parse_ts(value)
    return dt.isoformat().replace("+00:00", "Z") if dt else ""


def _event_type(row: Dict[str, Any]) -> str:
    raw = _pick(row, "event_type", "type", "artifact_type", "source_artifact", "category")
    return _text(raw).strip().lower().replace(" ", "_")


def _timestamp(row: Dict[str, Any]) -> str:
    return _iso(_pick(row, "timestamp", "utc_timestamp", "time", "created", "start_time", "event_time", "modified"))


def _details(row: Dict[str, Any]) -> str:
    parts = []
    for key in ("name", "process", "executable", "path", "command_line", "command", "url", "domain", "remote_address", "remote_ip", "source_url", "destination", "device", "action", "status", "sha256", "hash"):
        v = _pick(row, key)
        if v not in ("", None):
            parts.append(f"{key}={_text(v)}")
    if not parts:
        parts.append(_text(row))
    return "; ".join(parts)


def _risk_for_process(row: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    path = _text(_pick(row, "executable", "path", "image", "process_path"))
    cmd = _text(_pick(row, "command_line", "command", "cmdline", "args"))
    if path and SUSPICIOUS_PATH_RE.search(path):
        return "Med", f"Process executed from a user-writable or commonly abused directory: {path}"
    if POWERSHELL_RE.search(cmd) and (DOWNLOAD_SWITCH_RE.search(cmd) or BASE64_RE.search(cmd)):
        return "High", "PowerShell command contains encoded-command or download-oriented parameters"
    if BASE64_RE.search(cmd):
        try:
            token = BASE64_RE.search(cmd).group(0)
            decoded = base64.b64decode(token + "===", validate=False).decode("utf-16le", errors="ignore")
            if any(x in decoded.lower() for x in ("invoke-webrequest", "downloadstring", "powershell", "http://", "https://")):
                return "High", "Long Base64 token decodes to network/script-related PowerShell content"
        except Exception:
            pass
    return None


def _domain_or_ip(row: Dict[str, Any]) -> str:
    for key in ("domain", "remote_address", "remote_ip", "ip", "url", "source_url"):
        v = _text(_pick(row, key)).strip()
        if not v:
            continue
        m = URL_RE.search(v)
        if m:
            return m.group(1).lower()
        if DOMAIN_RE.search(v):
            return DOMAIN_RE.search(v).group(0).lower()
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
    return ""


def _load_indicators(indicators: Any) -> set[str]:
    if not indicators:
        return set()
    if isinstance(indicators, str) and os.path.exists(indicators):
        with open(indicators, "r", encoding="utf-8") as fh:
            indicators = fh.read()
    if isinstance(indicators, str):
        try:
            indicators = json.loads(indicators)
        except json.JSONDecodeError:
            indicators = re.split(r"[\s,;\n]+", indicators)
    if isinstance(indicators, dict):
        indicators = indicators.get("indicators", indicators.get("iocs", []))
    if not isinstance(indicators, (list, tuple, set)):
        return set()
    return {str(x).strip().lower() for x in indicators if str(x).strip()}


def investigate(data: Any, indicators: Any = None, max_timeline: int = 500) -> Dict[str, Any]:
    rows = parse_input(data)
    iocs = _load_indicators(indicators)
    timeline: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    normalized = []

    for idx, row in enumerate(rows):
        ts = _timestamp(row)
        typ = _event_type(row)
        source = _text(_pick(row, "source", "collector", "artifact_source", "datasource", default="UNKNOWN"))
        detail = _details(row)
        item = {"timestamp": ts, "source_artifact": source or typ or "UNKNOWN", "event_type": typ or "artifact", "details": detail, "raw_index": idx}
        normalized.append((row, item))
        timeline.append({**item, "risk_level": "Low"})

        if typ in {"process", "process_start", "execution", "process_execution", "running_process"} or any(k in row for k in ("command_line", "executable")):
            r = _risk_for_process(row)
            if r:
                risk, reason = r
                findings.append({"type": "Suspicious process execution", "risk": risk, "reason": reason, "timestamp": ts, "source": source, "details": detail})
                timeline[-1]["risk_level"] = risk

        indicator = _domain_or_ip(row)
        if indicator and indicator in iocs:
            findings.append({"type": "Indicator match", "risk": "High", "reason": f"Observed network/web indicator matches supplied IOC set: {indicator}", "timestamp": ts, "source": source, "indicator": indicator, "details": detail})
            timeline[-1]["risk_level"] = "High"

        if typ in {"usb", "usb_connect", "removable_media", "device_connect", "device_connected"} or "usb" in typ:
            timeline[-1]["event_type"] = "usb_connection"

    timeline.sort(key=lambda x: _parse_ts(x["timestamp"]) or datetime.max.replace(tzinfo=timezone.utc))

    # Correlate USB connection to nearby export/deletion events (24h window).
    usb_times = []
    for row, item in normalized:
        typ = item["event_type"]
        if typ == "usb_connection":
            dt = _parse_ts(item["timestamp"])
            if dt:
                usb_times.append(dt)
    for row, item in normalized:
        text = (_text(row).lower())
        if not any(word in text for word in ("export", "copy", "copied", "delete", "deleted", "archive", "zip")):
            continue
        dt = _parse_ts(item["timestamp"])
        if not dt or not usb_times:
            continue
        nearest = min(abs((dt - u).total_seconds()) for u in usb_times)
        if nearest <= 86400:
            findings.append({
                "type": "USB-adjacent file operation", "risk": "Med",
                "reason": f"File export/copy/deletion activity occurred {int(nearest // 60)} minutes from a recorded USB connection",
                "timestamp": item["timestamp"], "source": item["source_artifact"], "details": item["details"]
            })
            for t in timeline:
                if t.get("raw_index") == item.get("raw_index"):
                    t["risk_level"] = "Med"

    # Zone.Identifier/download + process proximity.
    downloads = []
    processes = []
    for row, item in normalized:
        typ = item["event_type"]
        dt = _parse_ts(item["timestamp"])
        if not dt:
            continue
        if typ in {"download", "browser_download", "zone_identifier", "zone_identifier_ads"} or "zone.identifier" in _text(row).lower():
            downloads.append((dt, item))
        if typ in {"process", "process_start", "execution", "process_execution"} or "command_line" in row:
            processes.append((dt, item))
    for dtime, d in downloads:
        nearby = [p for p in processes if abs((p[0] - dtime).total_seconds()) <= 600]
        for _, p in nearby:
            if "powershell" in p[1]["details"].lower() or "rundll32" in p[1]["details"].lower() or "mshta" in p[1]["details"].lower():
                findings.append({"type": "Download-to-execution correlation", "risk": "High", "reason": "A downloaded/Zone.Identifier artifact is temporally close to a script-capable process execution", "timestamp": p[1]["timestamp"], "source": p[1]["source_artifact"], "details": p[1]["details"]})
                p[1]["risk_level"] = "High"

    # Deduplicate findings while preserving first occurrence.
    seen = set(); clean = []
    for f in findings:
        key = (f.get("type"), f.get("timestamp"), f.get("reason"), f.get("details"))
        if key not in seen:
            seen.add(key); clean.append(f)
    findings = clean

    timeline = sorted(timeline, key=lambda x: SEVERITY_ORDER.get(x.get("risk_level", "Low"), 1), reverse=True)
    timeline = sorted(timeline[:max_timeline], key=lambda x: _parse_ts(x["timestamp"]) or datetime.max.replace(tzinfo=timezone.utc))

    high = sum(1 for f in findings if f.get("risk") == "High")
    med = sum(1 for f in findings if f.get("risk") == "Med")
    if high:
        disposition = "High-risk artifacts require investigator review and containment validation."
    elif med:
        disposition = "Potentially suspicious activity was identified; correlate with endpoint and case context."
    else:
        disposition = "No high-confidence suspicious pattern was identified from the supplied artifacts."

    summary = (
        f"Analyzed {len(rows)} artifact records and produced {len(timeline)} normalized timeline events. "
        f"Detected {high} high-risk and {med} medium-risk findings. {disposition} "
        "Analysis is metadata-only and does not rely on credentials, cookies, session tokens, or message contents."
    )
    summary = summary[:250]

    remediation = [
        "Preserve the original evidence and hashes; avoid modifying source artifacts during validation.",
        "For high-risk process findings, capture the parent/child process tree, executable path, signer metadata, and SHA-256 before remediation.",
        "Validate suspicious network indicators against your organization's approved threat-intelligence sources and case scope.",
        "If unauthorized execution is confirmed, isolate the affected endpoint according to the incident-response plan and preserve volatile evidence where appropriate.",
        "Review persistence locations, scheduled tasks/services, startup entries, and recent authentication/security events using authorized forensic procedures.",
        "Document containment actions and maintain chain-of-custody/audit records in the case database."
    ]

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "privacy_boundary": "host metadata, domains/IPs, timestamps, process trees, paths, hashes and command-line metadata only",
        "input_records": len(rows),
        "executive_summary": summary,
        "timeline": timeline,
        "findings": findings,
        "iocs_checked": sorted(iocs),
        "recommended_remediation": remediation,
    }


def render_markdown(result: Dict[str, Any]) -> str:
    lines = ["# JOCKY DFIR Investigation Report", "", "## 1. Executive Summary", result["executive_summary"], "", "## 2. Key Artifact Chronological Timeline", "", "| Timestamp (UTC) | Source Artifact | Event Type | Details/Command | Risk Level |", "|---|---|---|---|---|"]
    for e in result["timeline"]:
        detail = _text(e.get("details", "")).replace("|", "\\|")
        lines.append(f"| {e.get('timestamp','')} | {e.get('source_artifact','')} | {e.get('event_type','')} | {detail} | {e.get('risk_level','Low')} |")
    lines += ["", "## 3. Detected Suspicious Findings & IOCs", ""]
    if not result["findings"]:
        lines.append("No suspicious findings were generated from the supplied artifacts.")
    else:
        for i, f in enumerate(result["findings"], 1):
            lines.append(f"{i}. **[{f.get('risk','')}] {f.get('type','')}** — {f.get('reason','')} ({f.get('timestamp','')}).")
            if f.get("indicator"):
                lines.append(f"   - IOC: `{f['indicator']}`")
            if f.get("details"):
                lines.append(f"   - Evidence: `{f['details']}`")
    lines += ["", "## 4. Recommended Remediation & Containment Steps", ""]
    lines.extend(f"- {x}" for x in result["recommended_remediation"])
    return "\n".join(lines) + "\n"
