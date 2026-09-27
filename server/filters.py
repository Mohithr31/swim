"""
JOCKY Investigator Filters

Provides filter/search helpers for the dashboard and REST API.
Supports filtering by: device, time range, severity, confidence,
event_type, process, user, evidence source.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional


_SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
    "LOW": 3, "INFORMATIONAL": 4,
}


def filter_timeline(
    events: List[Dict[str, Any]],
    device_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    severity: Optional[str] = None,
    min_severity: Optional[str] = None,
    event_type: Optional[str] = None,
    process_name: Optional[str] = None,
    user: Optional[str] = None,
    evidence_source: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
) -> Dict[str, Any]:
    """
    Filter and paginate a list of normalized timeline events.

    All parameters are optional and cumulative (AND logic).
    min_severity filters events at or above the given severity level.
    search performs a case-insensitive substring match on description.
    """
    out = events

    if device_id:
        out = [e for e in out if e.get("device") == device_id or
               e.get("agent_id") == device_id]
    if since:
        out = [e for e in out if str(e.get("timestamp", "")) >= since]
    if until:
        out = [e for e in out if str(e.get("timestamp", "")) <= until]
    if severity:
        out = [e for e in out if e.get("severity", "").upper() == severity.upper()]
    if min_severity:
        threshold = _SEVERITY_ORDER.get(min_severity.upper(), 99)
        out = [e for e in out
               if _SEVERITY_ORDER.get(e.get("severity", "").upper(), 99) <= threshold]
    if event_type:
        out = [e for e in out if e.get("event_type", "").upper() == event_type.upper()]
    if process_name:
        q = process_name.lower()
        out = [e for e in out if q in str(e.get("process_name", "")).lower()
               or q in str(e.get("description", "")).lower()]
    if user:
        out = [e for e in out if e.get("user", "").lower() == user.lower()]
    if evidence_source:
        out = [e for e in out if evidence_source.lower() in
               str(e.get("source", "")).lower()]
    if search:
        q = search.lower()
        out = [e for e in out if q in str(e.get("description", "")).lower()
               or q in str(e.get("message", "")).lower()]

    total = len(out)
    page = max(1, page)
    page_size = min(max(1, page_size), 500)
    start = (page - 1) * page_size
    paginated = out[start:start + page_size]

    return {
        "events": paginated,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "applied_filters": {
            "device_id": device_id, "since": since, "until": until,
            "severity": severity, "min_severity": min_severity,
            "event_type": event_type, "process_name": process_name,
            "user": user, "evidence_source": evidence_source, "search": search,
        },
    }


def filter_findings(
    findings: List[Dict[str, Any]],
    severity: Optional[str] = None,
    min_severity: Optional[str] = None,
    confidence: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    since: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> Dict[str, Any]:
    """Filter and paginate correlation findings."""
    out = findings
    if severity:
        out = [f for f in out if f.get("severity","").upper() == severity.upper()]
    if min_severity:
        threshold = _SEVERITY_ORDER.get(min_severity.upper(), 99)
        out = [f for f in out
               if _SEVERITY_ORDER.get(f.get("severity","").upper(), 99) <= threshold]
    if confidence:
        out = [f for f in out if f.get("confidence","").upper() == confidence.upper()]
    if mitre_technique:
        q = mitre_technique.upper()
        out = [f for f in out if q in str(f.get("mitre_technique","")).upper()]
    if since:
        out = [f for f in out if str(f.get("timestamp","")) >= since]
    if search:
        q = search.lower()
        out = [f for f in out if q in str(f.get("title","")).lower()
               or q in str(f.get("description","")).lower()]

    total = len(out)
    page = max(1, page)
    page_size = min(max(1, page_size), 200)
    start = (page - 1) * page_size
    return {
        "findings": out[start:start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


def filter_evidence(
    evidence_list: List[Dict[str, Any]],
    device_id: Optional[str] = None,
    case_id: Optional[str] = None,
    source_collector: Optional[str] = None,
    since: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> Dict[str, Any]:
    """Filter evidence items for investigator queries."""
    out = evidence_list
    if device_id:
        out = [e for e in out if e.get("device_id") == device_id
               or e.get("agent_id") == device_id]
    if case_id:
        out = [e for e in out if e.get("case_id") == case_id]
    if source_collector:
        out = [e for e in out if source_collector.lower() in
               str(e.get("source_collector","")).lower()]
    if since:
        out = [e for e in out if str(e.get("uploaded_at","")) >= since]
    total = len(out)
    page = max(1, page)
    page_size = min(max(1, page_size), 200)
    start = (page - 1) * page_size
    return {
        "evidence": out[start:start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }
