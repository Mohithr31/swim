"""
JOCKY Unified Forensic Timeline Engine

Normalizes and aggregates endpoint telemetry from all collectors into a
single chronological forensic timeline. Every entry carries:
  - timestamp / utc_timestamp
  - source (collector name)
  - event_type (normalized, from EventType constants)
  - description
  - severity
  - confidence
  - evidence_id
  - provenance metadata (user, device, pid, etc.)
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Re-use event-type constants from the correlation engine
try:
    from server.correlation import EventType, Severity, Confidence
except ImportError:
    class EventType:
        FAILED_LOGIN = "FAILED_LOGIN"; USER_LOGIN = "USER_LOGIN"
        PROCESS_START = "PROCESS_START"; NETWORK_CONNECTION = "NETWORK_CONNECTION"
        SECURITY_ALERT = "SECURITY_ALERT"; VULNERABLE_DRIVER = "VULNERABLE_DRIVER_DETECTED"
        KERNEL_MODULE_LOAD = "KERNEL_MODULE_LOAD"; SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS_INJECTION"
        API_ANOMALY = "API_INTEGRITY_ANOMALY"; POSTURE_DEGRADED = "SECURITY_POSTURE_DEGRADED"
        POSTURE_DISABLED = "SECURITY_CONTROL_DISABLED"; LIVE_EVENT = "LIVE_EVENT"
        BROWSER_ACTIVITY = "BROWSER_ACTIVITY"; FILE_ACCESS = "FILE_ACCESS"
    class Severity:
        CRITICAL="CRITICAL"; HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; INFORMATIONAL="INFORMATIONAL"
    class Confidence:
        HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"


_NOW_STR = lambda: datetime.now(timezone.utc).isoformat()


def _entry(
    timestamp: str,
    source: str,
    event_type: str,
    description: str,
    severity: str = Severity.INFORMATIONAL,
    confidence: str = Confidence.HIGH,
    evidence_id: str = "",
    user: str = "Unknown",
    device: str = "LocalDevice",
    **extra: Any,
) -> Dict[str, Any]:
    """Build a normalized timeline entry."""
    ts = timestamp or _NOW_STR()
    return {
        "timestamp": ts,
        "utc_timestamp": ts,
        "source": source,
        "event_type": event_type,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "evidence_id": evidence_id,
        "user": user,
        "device": device,
        **extra,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Per-source normalizers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_logins(
    logins: List[Dict[str, Any]], evidence_id: str, now: str
) -> List[Dict[str, Any]]:
    out = []
    for login in logins:
        success = login.get("status", "").upper() in ("SUCCESS", "SUCCESSFUL")
        out.append(_entry(
            timestamp=login.get("timestamp", now),
            source="AUTHENTICATION / EVENT LOG",
            event_type=EventType.USER_LOGIN if success else EventType.FAILED_LOGIN,
            description=(
                f"User '{login.get('username', 'Unknown')}' logon via "
                f"{login.get('source_ip', 'local')} — {login.get('status', 'UNKNOWN')}"
            ),
            severity=Severity.INFORMATIONAL if success else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence_id=evidence_id,
            user=login.get("username", "Unknown"),
            device=login.get("source_workstation", "LocalDevice"),
            status=login.get("status"),
            source_ip=login.get("source_ip"),
        ))
    return out


def _normalize_processes(
    processes: List[Dict[str, Any]], evidence_id: str, now: str, limit: int = 50
) -> List[Dict[str, Any]]:
    out = []
    for p in processes[:limit]:
        out.append(_entry(
            timestamp=p.get("created") or p.get("start_time") or now,
            source="PROCESS_TELEMETRY",
            event_type=EventType.PROCESS_START,
            description=(
                f"Process '{p.get('name', '?')}' (PID {p.get('pid', '?')}) "
                f"started under '{p.get('user', 'System')}' "
                f"[{p.get('executable', '')}]"
            ),
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            evidence_id=evidence_id,
            user=p.get("user", "System"),
            device="LocalDevice",
            pid=p.get("pid"),
            ppid=p.get("ppid"),
            executable=p.get("executable", ""),
            command_line=p.get("command_line", ""),
            executable_sha256=p.get("executable_sha256"),
        ))
    return out


def _normalize_network(
    network: List[Dict[str, Any]], evidence_id: str, now: str, limit: int = 50
) -> List[Dict[str, Any]]:
    out = []
    for n in network[:limit]:
        state = n.get("state", "")
        remote = n.get("remote_address", "").strip()
        if not remote or remote in ("0.0.0.0", "*", "::", ""):
            continue
        port = n.get("remote_port", "")
        common_ports = {"80", "443", "22", "53", "25", "587"}
        sev = (
            Severity.MEDIUM if str(port) not in common_ports
            else Severity.INFORMATIONAL
        )
        out.append(_entry(
            timestamp=now,
            source="NETWORK_FORENSICS",
            event_type=EventType.NETWORK_CONNECTION,
            description=(
                f"{n.get('protocol', 'TCP')} connection to "
                f"{remote}:{port} (state={state}, PID={n.get('pid', '?')})"
            ),
            severity=sev,
            confidence=Confidence.MEDIUM,
            evidence_id=evidence_id,
            user="Network",
            device="LocalDevice",
            remote_address=remote,
            remote_port=port,
            local_address=n.get("local_address"),
            local_port=n.get("local_port"),
            state=state,
            pid=n.get("pid"),
        ))
    return out


def _normalize_defenders(
    defender_events: List[Dict[str, Any]], evidence_id: str, now: str
) -> List[Dict[str, Any]]:
    out = []
    for d in defender_events:
        out.append(_entry(
            timestamp=d.get("timestamp", now),
            source="DEFENDER_EDR_TELEMETRY",
            event_type=EventType.SECURITY_ALERT,
            description=(
                f"[{d.get('product', 'EDR')}] {d.get('detection_name', '')} "
                f"— Action: {d.get('action_taken', 'unknown')}"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence_id=evidence_id,
            user="System",
            device="LocalDevice",
            detection_name=d.get("detection_name"),
            action_taken=d.get("action_taken"),
            provider=d.get("product"),
        ))
    return out


def _normalize_drivers(
    drivers: List[Dict[str, Any]], evidence_id: str, now: str
) -> List[Dict[str, Any]]:
    out = []
    for drv in drivers:
        if drv.get("suspicious_name"):
            out.append(_entry(
                timestamp=drv.get("assessment_timestamp", now),
                source="KERNEL_INTEGRITY",
                event_type=EventType.KERNEL_MODULE_LOAD,
                description=(
                    f"Kernel module with suspicious name: '{drv.get('driver_name', '?')}' "
                    f"[{drv.get('path', 'NOT_RESOLVED')}]"
                ),
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                evidence_id=evidence_id,
                user="Kernel",
                device="LocalDevice",
                module_name=drv.get("driver_name"),
                sha256=drv.get("sha256"),
                suspicious_name=True,
            ))
        if drv.get("is_vulnerable"):
            out.append(_entry(
                timestamp=drv.get("assessment_timestamp", now),
                source="DRIVER_FORENSICS",
                event_type=EventType.VULNERABLE_DRIVER,
                description=(
                    f"Vulnerable driver '{drv.get('driver_name', '?')}' detected "
                    f"({drv.get('cve', 'N/A')}) — Risk: {drv.get('risk_level', 'N/A')}"
                ),
                severity=Severity.CRITICAL if drv.get("risk_level") == "CRITICAL" else Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence_id=evidence_id,
                user="Kernel",
                device="LocalDevice",
                driver_name=drv.get("driver_name"),
                cve=drv.get("cve"),
                risk_level=drv.get("risk_level"),
                remediation=drv.get("remediation"),
                mitre_technique=drv.get("mitre_technique"),
            ))
    return out


def _normalize_browser(
    browser: List[Dict[str, Any]], evidence_id: str, now: str, limit: int = 20
) -> List[Dict[str, Any]]:
    out = []
    for b in browser[:limit]:
        url = b.get("url", "")
        out.append(_entry(
            timestamp=b.get("timestamp", now),
            source="BROWSER_FORENSICS",
            event_type=EventType.BROWSER_ACTIVITY,
            description=f"[{b.get('browser', '?')}] {url[:120]}",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            evidence_id=evidence_id,
            user="User",
            device="LocalDevice",
            url=url,
            title=b.get("title", ""),
            browser=b.get("browser"),
        ))
    return out


def _normalize_live_events(
    live_events: List[Dict[str, Any]], evidence_id: str, now: str
) -> List[Dict[str, Any]]:
    out = []
    for le in live_events:
        p = le.get("payload", {}) if isinstance(le.get("payload"), dict) else {}
        cat = le.get("category", "LIVE")
        etype = le.get("event_type", EventType.LIVE_EVENT)
        desc = (
            p.get("description") or
            f"[{cat}] {etype}: "
            f"{p.get('process_name') or p.get('url') or p.get('query') or 'Live Event'}"
        )
        out.append(_entry(
            timestamp=le.get("timestamp", now),
            source=f"LIVE_MONITOR ({cat})",
            event_type=etype,
            description=desc,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            evidence_id=evidence_id,
            user=p.get("user", "System"),
            device=le.get("agent_id", "LocalDevice"),
            category=cat,
        ))
    return out


def _normalize_process_injection(
    injection_report: Dict[str, Any], evidence_id: str, now: str
) -> List[Dict[str, Any]]:
    """Translate process injection assessment results into timeline entries."""
    out = []
    for proc in injection_report.get("suspicious_processes", []):
        level = proc.get("risk_level", "LOW")
        if level == "CLEAN":
            continue
        sev = (
            Severity.CRITICAL if level == "HIGH" else
            Severity.MEDIUM if level == "MEDIUM" else
            Severity.LOW
        )
        indicators = proc.get("indicators", [])
        out.append(_entry(
            timestamp=now,
            source="PROCESS_INJECTION_DETECTOR",
            event_type=EventType.SUSPICIOUS_PROCESS,
            description=(
                f"Injection indicators in PID {proc.get('pid')} "
                f"('{proc.get('process_name', '?')}'): "
                f"{'; '.join(indicators[:3])}"
            ),
            severity=sev,
            confidence=Confidence.MEDIUM,
            evidence_id=evidence_id,
            user="System",
            device="LocalDevice",
            pid=proc.get("pid"),
            process_name=proc.get("process_name"),
            injection_score=proc.get("injection_score"),
            risk_level=level,
            indicators=indicators,
        ))
    return out


def _normalize_api_integrity(
    api_report: Dict[str, Any], evidence_id: str, now: str
) -> List[Dict[str, Any]]:
    """Translate API integrity anomalies into timeline entries."""
    out = []
    for lib in api_report.get("library_integrity", []):
        if lib.get("risk_level") != "HIGH":
            continue
        out.append(_entry(
            timestamp=now,
            source="API_INTEGRITY_ASSESSMENT",
            event_type=EventType.API_ANOMALY,
            description=(
                f"Suspicious executable sections in '{lib.get('path', '?')}': "
                f"{lib.get('suspicious_exec_sections', [])}"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            evidence_id=evidence_id,
            user="System",
            device="LocalDevice",
            affected_library=lib.get("path"),
            sha256=lib.get("sha256"),
            suspicious_sections=lib.get("suspicious_exec_sections"),
        ))
    for proc in api_report.get("process_api_map_anomalies", []):
        if proc.get("anonymous_executable_regions", 0) < 1:
            continue
        sev = Severity.HIGH if proc.get("risk_level") == "HIGH" else Severity.MEDIUM
        out.append(_entry(
            timestamp=now,
            source="API_INTEGRITY_ASSESSMENT",
            event_type=EventType.API_ANOMALY,
            description=(
                f"PID {proc.get('pid')} ('{proc.get('process_name', '?')}') has "
                f"{proc.get('anonymous_executable_regions')} anonymous executable "
                f"memory region(s) — possible API hook / in-memory injection."
            ),
            severity=sev,
            confidence=Confidence.MEDIUM,
            evidence_id=evidence_id,
            user="System",
            device="LocalDevice",
            pid=proc.get("pid"),
            process_name=proc.get("process_name"),
        ))
    return out


def _normalize_security_posture(
    posture_report: Dict[str, Any], evidence_id: str, now: str
) -> List[Dict[str, Any]]:
    """Translate security posture findings into timeline entries."""
    out = []
    for indicator in posture_report.get("risk_indicators", []):
        status = indicator.get("status", "")
        etype = (
            EventType.POSTURE_DISABLED if status == "DISABLED"
            else EventType.POSTURE_DEGRADED
        )
        sev = (
            Severity.HIGH if status == "DISABLED"
            else Severity.MEDIUM
        )
        out.append(_entry(
            timestamp=now,
            source="SECURITY_POSTURE_ASSESSMENT",
            event_type=etype,
            description=indicator.get("note", f"Security control {status.lower()}: {indicator.get('label', '?')}"),
            severity=sev,
            confidence=Confidence.HIGH,
            evidence_id=evidence_id,
            user="System",
            device="LocalDevice",
            control_name=indicator.get("control"),
            control_label=indicator.get("label"),
        ))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Main engine
# ─────────────────────────────────────────────────────────────────────────────

class TimelineEngine:
    """
    Builds a unified chronological forensic timeline from all JOCKY collectors.

    Every entry is normalized, severity-rated, and linked to its evidence_id
    for chain-of-custody.
    """

    @staticmethod
    def generate_timeline(
        logins: Optional[List[Dict[str, Any]]] = None,
        processes: Optional[List[Dict[str, Any]]] = None,
        network: Optional[List[Dict[str, Any]]] = None,
        defender_events: Optional[List[Dict[str, Any]]] = None,
        drivers: Optional[List[Dict[str, Any]]] = None,
        browser: Optional[List[Dict[str, Any]]] = None,
        live_events: Optional[List[Dict[str, Any]]] = None,
        # New assessment inputs
        process_injection_report: Optional[Dict[str, Any]] = None,
        api_integrity_report: Optional[Dict[str, Any]] = None,
        security_posture_report: Optional[Dict[str, Any]] = None,
        evidence_id: str = "",
    ) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []
        now = _NOW_STR()

        if logins:
            timeline.extend(_normalize_logins(logins, evidence_id, now))
        if processes:
            timeline.extend(_normalize_processes(processes, evidence_id, now))
        if network:
            timeline.extend(_normalize_network(network, evidence_id, now))
        if defender_events:
            timeline.extend(_normalize_defenders(defender_events, evidence_id, now))
        if drivers:
            timeline.extend(_normalize_drivers(drivers, evidence_id, now))
        if browser:
            timeline.extend(_normalize_browser(browser, evidence_id, now))
        if live_events:
            timeline.extend(_normalize_live_events(live_events, evidence_id, now))
        if process_injection_report:
            timeline.extend(_normalize_process_injection(process_injection_report, evidence_id, now))
        if api_integrity_report:
            timeline.extend(_normalize_api_integrity(api_integrity_report, evidence_id, now))
        if security_posture_report:
            timeline.extend(_normalize_security_posture(security_posture_report, evidence_id, now))

        # Sort chronologically
        timeline.sort(key=lambda x: str(x.get("timestamp", "")))
        return timeline
