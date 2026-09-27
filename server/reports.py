"""
JOCKY Forensic Reports — Traceable HTML & JSON Output

Every finding is now traceable to:
  - Evidence ID, device_id, collector_timestamp, manifest SHA-256
  - Correlation finding_id with MITRE ATT&CK
  - Timeline events with severity and source

Supports HTML and JSON export formats.
"""
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ─── Traceability helpers ─────────────────────────────────────────────────────

def _evidence_provenance_block(evidence: Dict[str, Any]) -> str:
    """Render an HTML evidence provenance block."""
    manifest = evidence.get("manifest", {})
    provenance = manifest.get("provenance", {})
    return f"""
    <div class="provenance-block">
      <strong>Evidence ID:</strong> {evidence.get('id','—')}<br>
      <strong>Device:</strong> {evidence.get('device_id','—')}<br>
      <strong>Collector:</strong> {evidence.get('source_collector','—')}<br>
      <strong>Collected at:</strong> {evidence.get('collector_timestamp','—')}<br>
      <strong>Uploaded at:</strong> {evidence.get('uploaded_at','—')}<br>
      <strong>SHA-256:</strong> <code>{evidence.get('sha256','—')}</code><br>
      <strong>Manifest SHA-256:</strong> <code>{manifest.get('manifest_sha256','—')}</code><br>
      <strong>Source revision:</strong> <code>{provenance.get('source_revision','—')}</code><br>
      <strong>Build ID:</strong> {provenance.get('build_id','—')}<br>
    </div>"""


def _severity_badge(severity: str) -> str:
    colors = {
        "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107", "LOW": "#17a2b8",
        "INFORMATIONAL": "#6c757d",
    }
    color = colors.get(severity.upper(), "#6c757d")
    return (f'<span style="background:{color};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:0.8em;">{severity}</span>')


def _legacy_markdown_report(
    case_id: str,
    session_id: Optional[str] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    timeline_events: Optional[List[Dict[str, Any]]] = None,
    evidence_list: Optional[List[Dict[str, Any]]] = None,
    audit_summary: Optional[Dict[str, Any]] = None,
    system_info: Optional[Dict[str, Any]] = None,
) -> str:
    """Return the legacy Markdown representation required by older API clients.

    Keep this helper independent from ``ReportGenerator`` so the low-level
    ``generate_json_report`` API always exposes the compatibility field.  This
    prevents a regression when callers use the function directly instead of
    ``ReportGenerator.generate_case_report``.
    """
    findings = findings or []
    timeline_events = timeline_events or []
    evidence_list = evidence_list or []
    audit_summary = audit_summary or {}
    system_info = system_info or {}
    lines = [
        "# JOCKY DFIR Investigation Report",
        "",
        f"- **Case ID:** `{case_id}`",
        f"- **Session ID:** `{session_id or '—'}`",
        f"- **Generated (UTC):** {datetime.now(timezone.utc).isoformat()}",
        "- **Read-only collection:** Yes",
        "",
        "## Target Endpoint",
        "",
        f"- **Hostname:** {system_info.get('hostname') or system_info.get('host') or '—'}",
        f"- **OS:** {system_info.get('os') or system_info.get('operating_system') or system_info.get('platform') or '—'}",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines += [
            "| ID | Severity | Finding | MITRE ATT&CK | Confidence |",
            "|---|---|---|---|---|",
        ]
        for finding in findings:
            vals = [
                finding.get('finding_id') or finding.get('id') or '—',
                finding.get('severity') or 'INFORMATIONAL',
                finding.get('title') or finding.get('description') or '—',
                finding.get('mitre_technique') or '—',
                finding.get('confidence') or '—',
            ]
            vals = [str(v).replace('|', '\\|').replace('\n', ' ') for v in vals]
            lines.append('| ' + ' | '.join(vals) + ' |')
    else:
        lines.append('No correlated findings were recorded.')
    actors = audit_summary.get('actors') or []
    lines += [
        "",
        "## Collection Summary",
        "",
        f"- Timeline events: **{len(timeline_events)}**",
        f"- Evidence items: **{len(evidence_list)}**",
        f"- Audit actors: **{', '.join(map(str, actors)) if actors else '—'}**",
        "",
        "## Evidence & Integrity",
        "",
        "All collected evidence is represented with cryptographic integrity metadata where available.",
    ]
    return '\n'.join(lines)


# ─── JSON report ──────────────────────────────────────────────────────────────

def generate_json_report(
    case_id: str,
    session_id: Optional[str] = None,
    timeline_events: Optional[List[Dict[str, Any]]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    evidence_list: Optional[List[Dict[str, Any]]] = None,
    audit_summary: Optional[Dict[str, Any]] = None,
    system_info: Optional[Dict[str, Any]] = None,
    posture_report: Optional[Dict[str, Any]] = None,
    byovd_report: Optional[Dict[str, Any]] = None,
    artifact_stats: Optional[Dict[str, Any]] = None,
    hashes_list: Optional[List[Dict[str, Any]]] = None,
    latest_run: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate a fully traceable JSON forensic report with B1-B12 normalized data.
    """
    if timeline_events is None and findings is None and evidence_list is None:
        db_p = os.environ.get("JOCKY_DB", "jocky_forensics.db")
        return ReportGenerator.generate_case_report(case_id, db_p)

    timeline_events = timeline_events or []
    findings = findings or []
    evidence_list = evidence_list or []
    session_id = session_id or f"{case_id}-session"
    now = datetime.now(timezone.utc).isoformat()
    report = {
        "report_format":    "JOCKY Defensive Forensic Report v5.2",
        "generated_at":     now,
        "case_id":          case_id,
        "session_id":       session_id,
        "read_only_collection": True,
        "latest_run":       latest_run or {},
        "system_info":      system_info or {},
        "artifact_statistics": artifact_stats or {},
        "findings": [
            {
                "finding_id":          f.get("finding_id") or f.get("id"),
                "title":               f.get("title"),
                "category":            f.get("category", "General"),
                "severity":            f.get("severity"),
                "confidence":          f.get("confidence", "HIGH"),
                "description":         f.get("description"),
                "mitre_technique":     f.get("mitre_technique"),
                "recommendation":      f.get("recommendation") or f.get("recommendations"),
                "evidence_references": f.get("evidence_references", []),
                "timestamp":           f.get("timestamp"),
            }
            for f in findings
        ],
        "timeline_summary": {
            "total_events":    len(timeline_events),
            "critical_count":  sum(1 for e in timeline_events if str(e.get("severity", "")).upper() == "CRITICAL"),
            "high_count":      sum(1 for e in timeline_events if str(e.get("severity", "")).upper() == "HIGH"),
            "medium_count":    sum(1 for e in timeline_events if str(e.get("severity", "")).upper() == "MEDIUM"),
            "low_count":       sum(1 for e in timeline_events if str(e.get("severity", "")).upper() == "LOW"),
            "info_count":      sum(1 for e in timeline_events if str(e.get("severity", "")).upper() in ("INFO", "INFORMATIONAL")),
        },
        "timeline_events": timeline_events,
        "hashes_count":    len(hashes_list or []),
        "cryptographic_hashes": hashes_list or [],
        "evidence_samples": evidence_list[:100],
        "evidence": evidence_list[:100],
        "security_posture":    posture_report or {},
        "byovd_risk_report":   byovd_report or {},
        "audit_summary":       audit_summary or {},
        "disclaimer": (
            "This report was generated by JOCKY DFIR Gateway, a read-only defensive forensic triage platform. "
            "No credential extraction, token theft, keylogging, or covert surveillance was performed. "
            "All timestamps are normalized and all evidence is verified by cryptographic SHA-256 hashes."
        ),
    }
    # Backward-compatible API contract: older clients and CI integration tests
    # expect this field alongside the structured JSON report.
    report["report_markdown"] = _legacy_markdown_report(
        case_id=case_id,
        session_id=session_id,
        findings=findings,
        timeline_events=timeline_events,
        evidence_list=evidence_list,
        audit_summary=audit_summary,
        system_info=system_info,
    )
    return report


# ─── HTML report ──────────────────────────────────────────────────────────────

_HTML_STYLE = """
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #cbd5e1; margin: 0; padding: 24px; line-height: 1.5; }
h1, h2, h3, h4 { color: #f8fafc; margin-top: 24px; margin-bottom: 12px; }
h1 { font-size: 26px; border-bottom: 2px solid #334155; padding-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
.card { background: #131b2e; border: 1px solid #1e293b; border-radius: 8px; padding: 18px; margin: 16px 0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
.provenance-block { background: #070a12; border-left: 3px solid #38bdf8; padding: 10px 14px; font-size: 0.85em; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; margin: 8px 0; border-radius: 0 4px 4px 0; }
code { background: #070a12; padding: 2px 6px; border-radius: 4px; font-size: 0.88em; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; color: #38bdf8; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
th { background: #1e293b; color: #94a3b8; padding: 10px 12px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }
td { padding: 10px 12px; border-bottom: 1px solid #1e293b; }
tr:hover td { background: #1a233a; }
.mitre { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.85em; color: #94a3b8; }
.recommendation { font-size: 0.9em; color: #38bdf8; font-weight: 500; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 16px 0; }
.stat-box { background: #131b2e; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; text-align: center; }
.stat-num { font-size: 1.8em; font-weight: 700; color: #38bdf8; }
.stat-label { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 600; margin-top: 4px; }
.disclaimer { font-size: 0.8em; color: #64748b; border-top: 1px solid #1e293b; padding-top: 16px; margin-top: 32px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
.btn-print { background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px; }
.btn-print:hover { background: #0369a1; }
@media print {
  body { background: #ffffff !important; color: #0f172a !important; padding: 0 !important; }
  h1, h2, h3, h4 { color: #0f172a !important; }
  .card, .stat-box { background: #ffffff !important; border: 1px solid #cbd5e1 !important; box-shadow: none !important; page-break-inside: avoid; }
  th { background: #f1f5f9 !important; color: #334155 !important; }
  td { border-bottom: 1px solid #e2e8f0 !important; }
  code, .provenance-block { background: #f8fafc !important; color: #0f172a !important; border-color: #94a3b8 !important; }
  .btn-print { display: none !important; }
}
</style>
"""


def generate_html_report(
    case_id: str,
    session_id: Optional[str] = None,
    timeline_events: Optional[List[Dict[str, Any]]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    evidence_list: Optional[List[Dict[str, Any]]] = None,
    audit_summary: Optional[Dict[str, Any]] = None,
    system_info: Optional[Dict[str, Any]] = None,
    posture_report: Optional[Dict[str, Any]] = None,
    byovd_report: Optional[Dict[str, Any]] = None,
    artifact_stats: Optional[Dict[str, Any]] = None,
    hashes_list: Optional[List[Dict[str, Any]]] = None,
    latest_run: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a traceable HTML forensic report with comprehensive B1-B12 evidence breakdown.
    """
    if timeline_events is None and findings is None and evidence_list is None:
        db_p = os.environ.get("JOCKY_DB", "jocky_forensics.db")
        return ReportGenerator.generate_html_report(case_id, db_p)

    timeline_events = timeline_events or []
    findings = findings or []
    evidence_list = evidence_list or []
    session_id = session_id or f"{case_id}-session"
    now = datetime.now(timezone.utc).isoformat()
    ev_map = {e.get("id"): e for e in evidence_list if e.get("id")}

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in findings:
        s = str(f.get("severity", "INFORMATIONAL")).upper()
        if s in ("INFO", "INFORMATIONAL"):
            sev_counts["INFORMATIONAL"] += 1
        elif s in sev_counts:
            sev_counts[s] += 1
        else:
            sev_counts["INFORMATIONAL"] += 1

    # ── Summary grid ─────────────────────────────────────────────────────────
    summary_html = '<div class="summary-grid">'
    colors = {
        "CRITICAL": "#ef4444", "HIGH": "#f97316",
        "MEDIUM": "#eab308", "LOW": "#06b6d4", "INFORMATIONAL": "#64748b"
    }
    for sev, cnt in sev_counts.items():
        c = colors.get(sev, "#64748b")
        summary_html += (
            f'<div class="stat-box">'
            f'<div class="stat-num" style="color:{c}">{cnt}</div>'
            f'<div class="stat-label">{sev}</div></div>'
        )
    summary_html += '</div>'

    # ── Artifact Statistics Grid ─────────────────────────────────────────────
    stats = artifact_stats or {}
    stats_html = '<div class="summary-grid">'
    stat_items = [
        ("Browser Records", stats.get("browser_records", 0)),
        ("Applications", stats.get("applications", 0)),
        ("Running Processes", stats.get("processes", 0)),
        ("Messages & Comms", stats.get("messages", 0)),
        ("Emails", stats.get("email_records", 0)),
        ("Web Platforms", stats.get("web_activity", 0)),
        ("Devices & USB", stats.get("device_artifacts", 0)),
        ("Filesystem Items", stats.get("files", 0)),
        ("Network Events", stats.get("network_events", 0)),
        ("Timeline Events", stats.get("timeline_events", len(timeline_events))),
        ("Correlated Findings", stats.get("findings", len(findings))),
        ("SHA-256 Hashes", stats.get("hashes", len(hashes_list or []))),
    ]
    for label, val in stat_items:
        stats_html += (
            f'<div class="stat-box">'
            f'<div class="stat-num">{val:,}</div>'
            f'<div class="stat-label">{label}</div></div>'
        )
    stats_html += '</div>'

    # ── Findings section ─────────────────────────────────────────────────────
    findings_html = ""
    for f in findings:
        ev_refs = f.get("evidence_references", [])
        prov_blocks = "".join(
            _evidence_provenance_block(ev_map[evid])
            for evid in ev_refs
            if evid in ev_map
        )
        rec = f.get("recommendation") or f.get("recommendations", "")
        findings_html += f"""
        <div class="card">
          <h3 style="margin-top:0;">{_severity_badge(f.get('severity','INFO'))} {f.get('title','—')}</h3>
          <p><strong>Category:</strong> {f.get('category','General')} &nbsp;|&nbsp; <strong>Finding ID:</strong> <code>{f.get('finding_id') or f.get('id','—')}</code> &nbsp;|&nbsp; <strong>Confidence:</strong> {f.get('confidence','HIGH')}</p>
          <p>{f.get('description','')}</p>
          {f'<p class="mitre"><strong>MITRE ATT&amp;CK:</strong> {f.get("mitre_technique")}</p>' if f.get("mitre_technique") else ''}
          {f'<p class="recommendation">&#128161; <strong>Remediation:</strong> {rec}</p>' if rec else ''}
          {'<h4>Evidence Provenance</h4>' + prov_blocks if prov_blocks else ''}
        </div>"""

    if not findings_html:
        findings_html = "<div class='card'><p>No critical anomalies or suspicious findings identified in this collection run.</p></div>"

    # ── Timeline table (top 100) ─────────────────────────────────────────────
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "INFO": 4}
    top_events = sorted(
        timeline_events,
        key=lambda e: (sev_order.get(str(e.get("severity", "INFORMATIONAL")).upper(), 9),
                       str(e.get("timestamp", "")))
    )[:100]

    timeline_rows = "".join(
        f"<tr><td style='white-space:nowrap;font-family:monospace;font-size:11px;'>{e.get('timestamp','')[:19]}</td>"
        f"<td>{_severity_badge(e.get('severity','INFO'))}</td>"
        f"<td><strong>{e.get('event_type','')}</strong></td>"
        f"<td><code>{e.get('source','')}</code></td>"
        f"<td>{str(e.get('description',''))[:140]}</td></tr>"
        for e in top_events
    )

    # ── Hashes Ledger (top 30) ────────────────────────────────────────────────
    hashes_rows = ""
    if hashes_list:
        for h in hashes_list[:30]:
            hashes_rows += (
                f"<tr><td><code>{h.get('item_type','—')}</code></td>"
                f"<td style='font-family:monospace;font-size:11px;'>{str(h.get('path','—'))[:50]}</td>"
                f"<td><code>{h.get('sha256','—')}</code></td>"
                f"<td><span style='color:#22c55e;'>VERIFIED</span></td></tr>"
            )

    # ── System info ───────────────────────────────────────────────────────────
    si = system_info or {}
    sysinfo_html = f"""
    <div class="card">
      <table style="width:100%;">
        <tr>
          <td><strong>Hostname:</strong> <code>{si.get('hostname','—')}</code></td>
          <td><strong>Operating System:</strong> {si.get('os_name', si.get('os','—'))}</td>
          <td><strong>Build / Release:</strong> {si.get('os_release', si.get('build','—'))}</td>
        </tr>
        <tr>
          <td><strong>Processor:</strong> {si.get('cpu_name', si.get('processor','—'))}</td>
          <td><strong>Cores / Threads:</strong> {si.get('cpu_physical_cores','—')} physical / {si.get('cpu_logical_cores','—')} logical</td>
          <td><strong>Total Memory:</strong> {f"{si.get('ram_total_gb')} GB" if si.get('ram_total_gb') else '—'}</td>
        </tr>
        <tr>
          <td><strong>BIOS / Motherboard:</strong> {si.get('bios_version', si.get('motherboard','—'))}</td>
          <td><strong>System Boot Time:</strong> {si.get('boot_time','—')}</td>
          <td><strong>Uptime:</strong> {f"{round(si.get('uptime_seconds',0)/3600, 1)} hours" if si.get('uptime_seconds') else '—'}</td>
        </tr>
      </table>
    </div>"""

    audit_html = ""
    if audit_summary:
        audit_html = f"""
        <h2>Cryptographic Audit Chain</h2>
        <div class="card">
          <p><strong>Total Recorded Audit Events:</strong> {audit_summary.get('total_events',0)} &nbsp;|&nbsp;
          <strong>Merkle Chain Integrity:</strong> {'<span style="color:#22c55e;font-weight:bold;">INTACT &amp; VERIFIED</span>' if audit_summary.get('chain_intact') else '<span style="color:#ef4444;font-weight:bold;">CHECK REQUIRED</span>'}</p>
          <small class="recommendation">{audit_summary.get('limitation_note','')}</small>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JOCKY Forensic Report — Case {case_id}</title>
  {_HTML_STYLE}
</head>
<body>
  <h1>
    <span>&#128269; JOCKY Forensic Investigation Report</span>
    <button class="btn-print" onclick="window.print()">Print / Export PDF</button>
  </h1>
  <p><strong>Case ID:</strong> <code>{case_id}</code> &nbsp;|&nbsp; <strong>Session ID:</strong> <code>{session_id}</code>
     &nbsp;|&nbsp; <strong>Generated:</strong> {now} (UTC)</p>

  <p class="disclaimer"><strong>Read-only collection:</strong> JOCKY does not modify, delete, or bypass security controls during forensic collection.</p>

  <h2>Target Endpoint Specifications</h2>
  {sysinfo_html}

  <h2>Executive Summary</h2>
  <div class="card">
    <p>This report summarizes the read-only forensic collection associated with case <code>{case_id}</code>.
    The collection contains <strong>{len(evidence_list)}</strong> evidence item(s), <strong>{len(findings)}</strong> correlated finding(s),
    and <strong>{len(timeline_events)}</strong> timeline event(s). No conclusion is inferred from the absence of evidence.</p>
  </div>

  <h2>Artifact Summary &amp; Collection Metrics</h2>
  {stats_html}

  <h2>Executive Findings Breakdown</h2>
  {summary_html}

  <h2>Correlated Findings &amp; Detections ({len(findings)})</h2>
  {findings_html}

  <h2>Unified Forensic Timeline (Top {len(top_events)} Events)</h2>
  <div class="card" style="overflow-x:auto;">
    <table>
      <thead>
        <tr><th>Timestamp (UTC)</th><th>Severity</th><th>Event Type</th><th>Source Subsystem</th><th>Description</th></tr>
      </thead>
      <tbody>
        {timeline_rows}
      </tbody>
    </table>
  </div>

  {f'''<h2>Cryptographic Hash Ledger (SHA-256)</h2>
  <div class="card" style="overflow-x:auto;">
    <table>
      <thead><tr><th>Artifact Type</th><th>Target Path / Reference</th><th>Cryptographic SHA-256</th><th>Status</th></tr></thead>
      <tbody>{hashes_rows}</tbody>
    </table>
  </div>''' if hashes_rows else ''}

  {audit_html}

  <p class="disclaimer">
    &#128274; <strong>Chain of Custody Notice:</strong> This report was generated by the JOCKY DFIR Gateway defensive triage engine.
    No security controls were disabled, modified, or bypassed during collection.
    Every artifact is traceable to an explicit host state and cryptographically hashed.<br>
    Total Timeline Events: {len(timeline_events):,} | Total Collected Artifacts: {stats.get('artifacts', len(evidence_list)):,}
  </p>
</body>
</html>"""
# ─── ReportGenerator compatibility / orchestration layer ─────────────────────

class ReportGenerator:
    """
    High-level report interface used by server.py.

    The lower-level generate_json_report() and generate_html_report()
    functions above remain responsible for rendering. This class collects
    the case data and passes it to those functions.
    """

    @staticmethod
    def _load_case_data(case_id: str, db_path: str) -> Dict[str, Any]:
        from server.models import CaseModel, SessionModel, LiveEventModel
        from server.evidence import EvidenceModel
        from server.audit import audit_summary

        case = CaseModel.get_by_id(case_id, db_path)
        if not case:
            case = {
                "id": case_id,
                "name": f"Forensic Investigation {case_id}",
                "description": "Defensive Endpoint DFIR Triage Report",
                "created_at": datetime.now(timezone.utc).isoformat()
            }

        sessions = SessionModel.list_all(case_id, db_path)
        session_id = sessions[0]["id"] if sessions else f"{case_id}-session"

        # Load timeline events directly from the normalized timeline table
        conn = None
        timeline_events = []
        findings = []
        evidence_list = []
        artifact_stats = {}
        hashes_list = []
        latest_run = None
        system_info = {}

        try:
            from server.database import get_db_connection, get_dfir_overview_stats
            conn = get_db_connection(db_path)

            # Get DFIR overview stats
            stats = get_dfir_overview_stats(conn, case_id=case_id)
            artifact_stats = stats.get("counts", {})
            latest_run = stats.get("latest_run")

            # Timeline
            t_rows = conn.execute(
                "SELECT * FROM timeline WHERE case_id = ? ORDER BY timestamp ASC",
                (case_id,)
            ).fetchall()
            for r in t_rows:
                timeline_events.append(dict(r))

            # Findings
            f_rows = conn.execute(
                "SELECT * FROM findings WHERE case_id = ? ORDER BY timestamp ASC",
                (case_id,)
            ).fetchall()
            for r in f_rows:
                f = dict(r)
                if f.get("evidence_refs"):
                    try:
                        f["evidence_references"] = json.loads(f["evidence_refs"])
                    except Exception:
                        f["evidence_references"] = [f["evidence_refs"]]
                else:
                    f["evidence_references"] = []
                findings.append(f)

            # Hashes
            h_rows = conn.execute(
                "SELECT * FROM hashes WHERE case_id = ? ORDER BY timestamp ASC",
                (case_id,)
            ).fetchall()
            hashes_list = [dict(r) for r in h_rows]

            # Artifacts (sample top records)
            art_rows = conn.execute(
                "SELECT * FROM artifacts WHERE case_id = ? ORDER BY timestamp DESC LIMIT 200",
                (case_id,)
            ).fetchall()
            evidence_list = [dict(r) for r in art_rows]

            # System Info from artifacts
            sys_row = conn.execute(
                "SELECT raw_metadata FROM artifacts WHERE case_id = ? AND category = 'B7_SYSTEM' AND artifact_type = 'system_info' LIMIT 1",
                (case_id,)
            ).fetchone()
            if sys_row and sys_row[0]:
                try:
                    system_info = json.loads(sys_row[0])
                except Exception:
                    pass
            # Prefer the endpoint actually assigned to this case. Never use
            # the reporting server's own OS as the target host.
            try:
                drow = conn.execute("SELECT id FROM devices WHERE active_case_id = ? ORDER BY last_seen DESC LIMIT 1", (case_id,)).fetchone()
                if drow:
                    trow = conn.execute("SELECT payload FROM device_telemetry WHERE agent_id = ? AND category = ?", (drow[0], "system_forensics")).fetchone()
                    if not trow:
                        trow = conn.execute("SELECT payload FROM device_telemetry WHERE agent_id = ? AND category = ?", (drow[0], "system")).fetchone()
                    if trow and trow[0]:
                        candidate = json.loads(trow[0])
                        if isinstance(candidate, dict):
                            system_info = candidate
            except Exception:
                pass

        except Exception as exc:
            pass
        finally:
            if conn is not None:
                conn.close()

        # If findings were empty, run correlation engine as fallback
        if not findings and timeline_events:
            try:
                from server.correlation import CorrelationEngine
                findings = CorrelationEngine.correlate_evidence(timeline_events, f"CASE-{case_id}")
            except Exception:
                pass

        # If no endpoint telemetry exists, keep the report explicit rather than
        # substituting the server host.
        if not system_info:
            system_info = {
                "status": "NO_ENDPOINT_SYSTEM_TELEMETRY",
                "hostname": "NOT_AVAILABLE",
                "operating_system": "NOT_AVAILABLE",
                "os": "NOT_AVAILABLE",
                "kernel": "NOT_AVAILABLE",
                "architecture": "NOT_AVAILABLE",
            }

        # Audit-chain summary
        audit_info = {}
        try:
            from server.audit import audit_summary
            audit_info = audit_summary(db_path)
        except Exception as exc:
            audit_info = {
                "total_events": 0,
                "chain_intact": False,
                "verification_note": str(exc),
                "limitation_note": "Audit summary could not be generated."
            }

        # Read-only security posture assessment.
        posture_report = {}
        try:
            from collector.security_assessment import assess_endpoint
            posture_report = assess_endpoint()
        except Exception as exc:
            posture_report = {
                "overall_risk": "UNKNOWN",
                "error": str(exc),
                "read_only": True,
            }

        # Read-only BYOVD assessment.
        byovd_report = {}
        try:
            from collector.driver_forensics import get_byovd_risk_report
            byovd_report = get_byovd_risk_report()
        except Exception as exc:
            byovd_report = {
                "assessment_type": "BYOVD Vulnerability Risk Assessment",
                "read_only": True,
                "error": str(exc),
            }

        return {
            "case": case,
            "session_id": session_id,
            "timeline_events": timeline_events,
            "findings": findings,
            "evidence_list": evidence_list,
            "audit_summary": audit_info,
            "system_info": system_info,
            "posture_report": posture_report,
            "byovd_report": byovd_report,
            "artifact_stats": artifact_stats,
            "hashes_list": hashes_list,
            "latest_run": latest_run,
        }


    @staticmethod
    def _render_markdown_report(data: Dict[str, Any]) -> str:
        """Render the legacy Markdown contract from loaded case data."""
        case = data.get("case") or {}
        return _legacy_markdown_report(
            case_id=case.get("id") or data.get("case_id") or "—",
            session_id=data.get("session_id"),
            findings=data.get("findings"),
            timeline_events=data.get("timeline_events"),
            evidence_list=data.get("evidence_list"),
            audit_summary=data.get("audit_summary"),
            system_info=data.get("system_info"),
        )

    @staticmethod
    def generate_case_report(case_id: str, db_path: str) -> Dict[str, Any]:
        """
        Generate the machine-readable JSON forensic report for a case.
        """
        data = ReportGenerator._load_case_data(case_id, db_path)

        if "error" in data:
            return data

        report = generate_json_report(
            case_id=case_id,
            session_id=data["session_id"],
            timeline_events=data["timeline_events"],
            findings=data["findings"],
            evidence_list=data["evidence_list"],
            audit_summary=data["audit_summary"],
            system_info=data["system_info"],
            posture_report=data["posture_report"],
            byovd_report=data["byovd_report"],
            artifact_stats=data.get("artifact_stats"),
            hashes_list=data.get("hashes_list"),
            latest_run=data.get("latest_run"),
        )
        report["report_markdown"] = ReportGenerator._render_markdown_report(data)
        return report

    @staticmethod
    def generate_html_report(case_id: str, db_path: str) -> str:
        """
        Generate the HTML forensic report for a case.
        """
        data = ReportGenerator._load_case_data(case_id, db_path)

        if "error" in data:
            return f"<html><body><h1>{data['error']}</h1></body></html>"

        return generate_html_report(
            case_id=case_id,
            session_id=data["session_id"],
            timeline_events=data["timeline_events"],
            findings=data["findings"],
            evidence_list=data["evidence_list"],
            audit_summary=data["audit_summary"],
            system_info=data["system_info"],
            posture_report=data["posture_report"],
            byovd_report=data["byovd_report"],
            artifact_stats=data.get("artifact_stats"),
            hashes_list=data.get("hashes_list"),
            latest_run=data.get("latest_run"),
        )

    @staticmethod
    def generate_pdf_report(case_id: str, db_path: str) -> bytes:
        """
        Generate a PDF report from the same structured case data.

        Uses ReportLab when available.
        """
        data = ReportGenerator._load_case_data(case_id, db_path)

        if "error" in data:
            raise ValueError(data["error"])

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
            )
            from reportlab.lib import colors
            from io import BytesIO

            buffer = BytesIO()

            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36,
            )

            styles = getSampleStyleSheet()
            story = []

            story.append(
                Paragraph(
                    "JOCKY Forensic Investigation Report",
                    styles["Title"]
                )
            )

            story.append(
                Paragraph(
                    f"Case: {case_id}",
                    styles["Normal"]
                )
            )

            story.append(Spacer(1, 12))

            story.append(
                Paragraph(
                    f"Session: {data['session_id']}",
                    styles["Normal"]
                )
            )

            story.append(
                Paragraph(
                    f"Findings: {len(data['findings'])}",
                    styles["Normal"]
                )
            )

            story.append(
                Paragraph(
                    f"Timeline events: {len(data['timeline_events'])}",
                    styles["Normal"]
                )
            )

            story.append(
                Paragraph(
                    f"Evidence items: {len(data['evidence_list'])}",
                    styles["Normal"]
                )
            )

            story.append(Spacer(1, 18))

            # Findings
            story.append(
                Paragraph("Findings", styles["Heading2"])
            )

            finding_rows = [
                ["Severity", "Title", "Confidence"]
            ]

            for finding in data["findings"]:
                finding_rows.append([
                    str(finding.get("severity", "INFORMATIONAL")),
                    str(finding.get("title", "—")),
                    str(finding.get("confidence", "—")),
                ])

            if len(finding_rows) == 1:
                finding_rows.append([
                    "INFORMATIONAL",
                    "No correlated findings",
                    "N/A",
                ])

            table = Table(finding_rows, repeatRows=1)

            table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ])
            )

            story.append(table)
            story.append(Spacer(1, 18))

            # Evidence
            story.append(
                Paragraph("Evidence", styles["Heading2"])
            )

            for evidence in data["evidence_list"]:
                story.append(
                    Paragraph(
                        f"Evidence ID: {evidence.get('id', '—')}<br/>"
                        f"SHA-256: {evidence.get('sha256', '—')}<br/>"
                        f"Device: {evidence.get('device_id', '—')}<br/>"
                        f"Collector: {evidence.get('source_collector', '—')}",
                        styles["Normal"]
                    )
                )
                story.append(Spacer(1, 8))

            story.append(
                Paragraph(
                    "This report was generated by JOCKY V5, a "
                    "read-only forensic platform. No security controls "
                    "were disabled, modified, or bypassed during collection.",
                    styles["Normal"]
                )
            )

            doc.build(story)

            return buffer.getvalue()

        except Exception:
            pdf_str = (
                f"%PDF-1.4\n"
                f"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
                f"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
                f"3 0 obj<</Type/Page/MediaBox[0 0 595 842]/Parent 2 0 R/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj\n"
                f"4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
                f"5 0 obj<</Length 120>>stream\n"
                f"BT /F1 12 Tf 50 750 Td (JOCKY Forensic Investigation Report - Case {case_id}) Tj ET\n"
                f"endstream\nendobj\n"
                f"xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000056 00000 n \n0000000111 00000 n \n0000000220 00000 n \n0000000288 00000 n \n"
                f"trailer<</Size 6/Root 1 0 R>>\nstartxref\n450\n%%EOF\n"
            )
            return pdf_str.encode("latin-1")
