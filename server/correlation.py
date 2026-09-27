"""
JOCKY Forensic Evidence Correlation Engine

Cross-correlates normalized forensic timeline events to generate evidence-
backed findings with severity, confidence, MITRE ATT&CK mappings, and
explicit evidence references.

All rules are defensive detection rules; no offensive logic is present.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Normalized event schema constants
# ─────────────────────────────────────────────────────────────────────────────

# Canonical event_type values used across all collectors
class EventType:
    FAILED_LOGIN         = "FAILED_LOGIN"
    USER_LOGIN           = "USER_LOGIN"
    PROCESS_START        = "PROCESS_START"
    NETWORK_CONNECTION   = "NETWORK_CONNECTION"
    SECURITY_ALERT       = "SECURITY_ALERT"
    VULNERABLE_DRIVER    = "VULNERABLE_DRIVER_DETECTED"
    KERNEL_MODULE_LOAD   = "KERNEL_MODULE_LOAD"
    SUSPICIOUS_PROCESS   = "SUSPICIOUS_PROCESS_INJECTION"
    API_ANOMALY          = "API_INTEGRITY_ANOMALY"
    POSTURE_DEGRADED     = "SECURITY_POSTURE_DEGRADED"
    POSTURE_DISABLED     = "SECURITY_CONTROL_DISABLED"
    LIVE_EVENT           = "LIVE_EVENT"
    BROWSER_ACTIVITY     = "BROWSER_ACTIVITY"
    FILE_ACCESS          = "FILE_ACCESS"


class Severity:
    CRITICAL      = "CRITICAL"
    HIGH          = "HIGH"
    MEDIUM        = "MEDIUM"
    LOW           = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence:
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Finding ID generator
# ─────────────────────────────────────────────────────────────────────────────

def _finding_id(prefix: str, *parts: str) -> str:
    blob = "-".join(str(p) for p in parts)
    short = hashlib.sha256(blob.encode()).hexdigest()[:8].upper()
    return f"{prefix}-{short}"


# ─────────────────────────────────────────────────────────────────────────────
# Individual correlation rules
# ─────────────────────────────────────────────────────────────────────────────

def _rule_brute_force(
    events: List[Dict[str, Any]], evidence_id: str
) -> Optional[Dict[str, Any]]:
    """Rule 1: Multiple failed logins (brute-force / credential stuffing)."""
    failed = [e for e in events if e.get("event_type") == EventType.FAILED_LOGIN]
    if not failed:
        return None
    affected_users = list({e.get("user", "Unknown") for e in failed})
    source_ips = list({e.get("source_ip", "") for e in failed if e.get("source_ip")})
    timestamps = sorted(e.get("timestamp", "") for e in failed)
    return {
        "finding_id": _finding_id("FIND-AUTH", evidence_id),
        "title": "Authentication Anomaly — Multiple Failed Logons Observed",
        "severity": Severity.HIGH if len(failed) >= 5 else Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "description": (
            f"Observed {len(failed)} failed logon attempt(s) across "
            f"{len(affected_users)} account(s). "
            f"Source IP(s): {', '.join(source_ips) or 'local'}. "
            f"First attempt: {timestamps[0] if timestamps else 'unknown'}."
        ),
        "evidence_references": [evidence_id],
        "affected_users": affected_users,
        "event_count": len(failed),
        "mitre_technique": "T1110 – Brute Force",
        "recommendation": (
            "Review security audit event 4625 (Windows) / auth.log (Linux). "
            "Enforce account lockout policies and MFA. "
            "Investigate source IP(s) for further suspicious activity."
        ),
        "source_events": len(failed),
        "timestamp": timestamps[-1] if timestamps else "",
    }


def _rule_byovd(
    events: List[Dict[str, Any]], evidence_id: str
) -> List[Dict[str, Any]]:
    """Rule 2: Known vulnerable kernel driver detected (BYOVD attack surface)."""
    vuln_drivers = [e for e in events if e.get("event_type") == EventType.VULNERABLE_DRIVER]
    findings = []
    for vd in vuln_drivers:
        findings.append({
            "finding_id": _finding_id("FIND-BYOVD", vd.get("description", ""), evidence_id),
            "title": f"Vulnerable Kernel Driver Detected: {vd.get('driver_name', 'unknown')}",
            "severity": Severity.CRITICAL,
            "confidence": Confidence.HIGH,
            "description": (
                f"Driver '{vd.get('driver_name', 'unknown')}' matched the BYOVD "
                f"vulnerability catalogue. {vd.get('description', '')} "
                f"CVE: {vd.get('cve', 'N/A')}. Risk: {vd.get('risk_level', 'N/A')}."
            ),
            "evidence_references": [evidence_id],
            "affected_component": vd.get("driver_name", "unknown"),
            "cve": vd.get("cve", "N/A"),
            "mitre_technique": vd.get("mitre_technique", "T1068 – Exploitation for Privilege Escalation"),
            "recommendation": (
                vd.get("remediation") or
                "Block driver via WDAC policy. Enable HVCI. "
                "Review https://www.loldrivers.io for guidance."
            ),
            "timestamp": vd.get("timestamp", ""),
        })
    return findings


def _rule_security_alert(
    events: List[Dict[str, Any]], evidence_id: str
) -> Optional[Dict[str, Any]]:
    """Rule 3: Defender / EDR security alert escalation."""
    sec_alerts = [
        e for e in events
        if e.get("source") in ("DEFENDER_EDR_TELEMETRY",) or
           e.get("event_type") == EventType.SECURITY_ALERT
    ]
    if not sec_alerts:
        return None
    products = list({e.get("provider", "EDR") for e in sec_alerts})
    descriptions = [
        e.get("description", "") for e in sec_alerts[:5]
    ]
    timestamps = sorted(e.get("timestamp", "") for e in sec_alerts)
    return {
        "finding_id": _finding_id("FIND-SEC", evidence_id),
        "title": "Endpoint Security Alert(s) Detected",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "description": (
            f"{len(sec_alerts)} security alert(s) from {', '.join(products)}. "
            f"Alerts: {'; '.join(d for d in descriptions if d)}"
        ),
        "evidence_references": [evidence_id],
        "affected_products": products,
        "event_count": len(sec_alerts),
        "mitre_technique": "T1562 – Impair Defenses (possible indicator)",
        "recommendation": (
            "Inspect process memory snapshots and quarantine affected binaries. "
            "Review full EDR alert timeline and initiate IR playbook."
        ),
        "timestamp": timestamps[-1] if timestamps else "",
    }


def _rule_process_injection(
    events: List[Dict[str, Any]], evidence_id: str
) -> Optional[Dict[str, Any]]:
    """Rule 4: Process injection / hollowing indicators."""
    inj_events = [
        e for e in events
        if e.get("event_type") == EventType.SUSPICIOUS_PROCESS
    ]
    if not inj_events:
        return None
    high_risk = [e for e in inj_events if e.get("risk_level") == "HIGH"]
    pids = list({e.get("pid") for e in inj_events})
    names = list({e.get("process_name", "") for e in inj_events if e.get("process_name")})
    return {
        "finding_id": _finding_id("FIND-INJ", evidence_id),
        "title": "Process Injection / Hollowing Indicators Detected",
        "severity": Severity.CRITICAL if high_risk else Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "description": (
            f"{len(inj_events)} process(es) with injection indicators "
            f"({len(high_risk)} high-risk). "
            f"Affected PIDs: {pids[:10]}. Processes: {names[:10]}."
        ),
        "evidence_references": [evidence_id],
        "affected_pids": pids[:20],
        "affected_processes": names[:20],
        "event_count": len(inj_events),
        "mitre_technique": (
            "T1055 – Process Injection; T1055.012 – Process Hollowing; "
            "T1055.001 – Dynamic-link Library Injection"
        ),
        "recommendation": (
            "Capture process memory dumps for forensic analysis (read-only). "
            "Inspect /proc/<pid>/maps for anomalous RWX / anonymous executable regions. "
            "Correlate with network connections from flagged PIDs."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _rule_api_integrity(
    events: List[Dict[str, Any]], evidence_id: str
) -> Optional[Dict[str, Any]]:
    """Rule 5: API integrity anomalies (hooks / patching indicators)."""
    api_events = [
        e for e in events
        if e.get("event_type") == EventType.API_ANOMALY
    ]
    if not api_events:
        return None
    libs = list({e.get("affected_library", "") for e in api_events if e.get("affected_library")})
    return {
        "finding_id": _finding_id("FIND-API", evidence_id),
        "title": "API Integrity Anomaly — Possible Hook / Patching Detected",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "description": (
            f"API integrity assessment detected {len(api_events)} anomalie(s). "
            f"Affected libraries: {libs or ['see details']}."
        ),
        "evidence_references": [evidence_id],
        "affected_libraries": libs,
        "event_count": len(api_events),
        "mitre_technique": "T1055.001 – DLL Injection; T1562.001 – Disable or Modify Tools",
        "recommendation": (
            "Compare SHA-256 hashes of flagged libraries against trusted baselines. "
            "Check for LD_PRELOAD environment variable injections. "
            "Inspect anonymous executable memory regions in affected processes."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _rule_security_posture(
    events: List[Dict[str, Any]], evidence_id: str
) -> List[Dict[str, Any]]:
    """Rule 6: Security controls disabled or degraded."""
    findings = []
    disabled = [e for e in events if e.get("event_type") == EventType.POSTURE_DISABLED]
    degraded = [e for e in events if e.get("event_type") == EventType.POSTURE_DEGRADED]

    if disabled:
        controls = [e.get("control_name", "unknown") for e in disabled]
        findings.append({
            "finding_id": _finding_id("FIND-CTRL-OFF", evidence_id),
            "title": "Security Control(s) Disabled",
            "severity": Severity.HIGH,
            "confidence": Confidence.HIGH,
            "description": (
                f"{len(disabled)} security control(s) are disabled: "
                f"{', '.join(controls)}."
            ),
            "evidence_references": [evidence_id],
            "affected_controls": controls,
            "mitre_technique": "T1562.001 – Disable or Modify Tools",
            "recommendation": (
                "Re-enable and verify all listed security controls. "
                "Investigate who/what disabled them and when."
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    if degraded:
        controls = [e.get("control_name", "unknown") for e in degraded]
        findings.append({
            "finding_id": _finding_id("FIND-CTRL-DEG", evidence_id),
            "title": "Security Control(s) in Degraded State",
            "severity": Severity.MEDIUM,
            "confidence": Confidence.HIGH,
            "description": (
                f"{len(degraded)} security control(s) are in a degraded or "
                f"permissive state: {', '.join(controls)}."
            ),
            "evidence_references": [evidence_id],
            "affected_controls": controls,
            "mitre_technique": "T1562.006 – Indicator Blocking",
            "recommendation": (
                "Review control configuration and restore to enforcing/active state. "
                "Audit recent configuration changes."
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    return findings


def _rule_lateral_movement(
    events: List[Dict[str, Any]], evidence_id: str
) -> Optional[Dict[str, Any]]:
    """Rule 7: Suspicious outbound network connections correlated with process events."""
    net_events = [
        e for e in events
        if e.get("event_type") == EventType.NETWORK_CONNECTION
    ]
    proc_events = [
        e for e in events
        if e.get("event_type") == EventType.PROCESS_START
    ]
    if not net_events or not proc_events:
        return None

    # Flag if unusual ports appear (e.g. not 80/443/22)
    common_ports = {"80", "443", "22", "53", "25", "587"}
    unusual = [
        n for n in net_events
        if str(n.get("remote_port", "")) not in common_ports
        and n.get("remote_address", "").strip() not in ("", "0.0.0.0", "::", "*")
    ]
    if len(unusual) < 2:
        return None

    dest_ips = list({n.get("remote_address") for n in unusual})
    dest_ports = list({str(n.get("remote_port")) for n in unusual})
    return {
        "finding_id": _finding_id("FIND-NET", evidence_id),
        "title": "Unusual Outbound Network Connections Detected",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "description": (
            f"{len(unusual)} connection(s) to non-standard ports. "
            f"Destinations: {dest_ips[:10]}. Ports: {dest_ports[:10]}."
        ),
        "evidence_references": [evidence_id],
        "destination_ips": dest_ips[:20],
        "destination_ports": dest_ports[:20],
        "mitre_technique": "T1071 – Application Layer Protocol; T1095 – Non-Standard Port",
        "recommendation": (
            "Capture full network packet trace if authorized. "
            "Correlate destination IPs with threat intelligence. "
            "Review process owning each connection."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _rule_kernel_module_anomaly(
    events: List[Dict[str, Any]], evidence_id: str
) -> Optional[Dict[str, Any]]:
    """Rule 8: Suspicious kernel module loaded."""
    km_events = [
        e for e in events
        if e.get("event_type") == EventType.KERNEL_MODULE_LOAD
        and e.get("suspicious_name")
    ]
    if not km_events:
        return None
    names = [e.get("module_name", "") for e in km_events]
    return {
        "finding_id": _finding_id("FIND-KM", evidence_id),
        "title": "Suspicious Kernel Module(s) Detected",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "description": (
            f"{len(km_events)} kernel module(s) with suspicious names loaded: "
            f"{', '.join(names)}."
        ),
        "evidence_references": [evidence_id],
        "affected_modules": names,
        "mitre_technique": "T1014 – Rootkit; T1547.006 – Kernel Modules and Extensions",
        "recommendation": (
            "Inspect module path and hash immediately. "
            "Run rkhunter / chkrootkit. "
            "Consider booting into a trusted environment for deeper analysis."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _rule_baseline(
    events: List[Dict[str, Any]], evidence_id: str,
    existing_finding_count: int
) -> Dict[str, Any]:
    """Rule 9: Baseline telemetry summary (always emitted for chain-of-custody)."""
    event_count = len(events)
    successful_logins = [
        e for e in events
        if e.get("event_type") == EventType.USER_LOGIN
        and e.get("status") == "SUCCESS"
    ]
    login_info = f"{len(successful_logins)} successful login(s) observed." if successful_logins else ""
    return {
        "finding_id": _finding_id("FIND-BASE", evidence_id),
        "title": "Forensic Baseline Telemetry Summary",
        "severity": Severity.INFORMATIONAL,
        "confidence": Confidence.HIGH,
        "description": (
            f"Correlation engine processed {event_count} timeline event(s). "
            f"{login_info} "
            f"{existing_finding_count} actionable finding(s) generated above."
        ).strip(),
        "evidence_references": [evidence_id],
        "event_count": event_count,
        "mitre_technique": "N/A",
        "recommendation": "Retain telemetry for the investigation record and chain of custody.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main correlation engine
# ─────────────────────────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Analyzes normalized timeline events and produces evidence-backed findings.

    Each finding includes:
     - finding_id: stable hash-based ID
     - severity: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
     - confidence: HIGH / MEDIUM / LOW
     - mitre_technique: ATT&CK technique reference
     - evidence_references: list of evidence IDs from the evidence store
     - recommendation: specific remediation guidance
     - timestamp: when the correlation was generated
    """

    @staticmethod
    def correlate_evidence(
        timeline_events: List[Dict[str, Any]],
        evidence_id: str = "",
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # ── Apply all rules ────────────────────────────────────────────────
        f = _rule_brute_force(timeline_events, evidence_id)
        if f:
            findings.append(f)

        findings.extend(_rule_byovd(timeline_events, evidence_id))

        f = _rule_security_alert(timeline_events, evidence_id)
        if f:
            findings.append(f)

        f = _rule_process_injection(timeline_events, evidence_id)
        if f:
            findings.append(f)

        f = _rule_api_integrity(timeline_events, evidence_id)
        if f:
            findings.append(f)

        findings.extend(_rule_security_posture(timeline_events, evidence_id))

        f = _rule_lateral_movement(timeline_events, evidence_id)
        if f:
            findings.append(f)

        f = _rule_kernel_module_anomaly(timeline_events, evidence_id)
        if f:
            findings.append(f)

        # Baseline always last
        findings.append(
            _rule_baseline(timeline_events, evidence_id, len(findings))
        )

        # Sort by severity
        _sev_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFORMATIONAL: 4,
        }
        findings.sort(key=lambda x: _sev_order.get(x.get("severity", "INFORMATIONAL"), 9))
        return findings
