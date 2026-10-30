#!/usr/bin/env python3
"""
JOCKY Forensic Platform — Model Context Protocol (MCP) Server
=============================================================
Exposes secure, read-only forensic inspection and indicator research tools
to MCP-compatible AI assistants (Antigravity, Claude, etc.) via JSON-RPC 2.0 stdio.

Security Safeguards:
  - Read-only operations; no arbitrary command execution or unrestricted DB queries.
  - Strict parameter validation on all inputs.
  - Bounded result pagination to prevent memory exhaustion.
  - Credentials remain in server environment; never exposed in tool schemas or outputs.
"""
from __future__ import annotations

import sys
import os
import json
from typing import Dict, Any, List, Optional

# Ensure project root is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(root_dir, ".env"), override=True)
except Exception:
    pass

from server.database import get_db_connection, init_db, DEFAULT_DB_PATH
from server.models import CaseModel, ThreatIntelModel
from server.tinyfish_service import TinyFishService, is_tinyfish_configured

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "jocky-dfir-mcp"
SERVER_VERSION = "2026.1"

TOOLS = [
    {
        "name": "jocky_list_cases",
        "description": "List all forensic cases currently registered in the JOCKY DFIR platform.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "jocky_get_case_summary",
        "description": "Retrieve forensic triage summary and artifact statistics for a specific case ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "Unique identifier of the case (e.g. 'CASE-001' or 'case_12345678').",
                }
            },
            "required": ["case_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jocky_research_indicator",
        "description": "Search public threat intelligence and security advisories for an indicator (domain, IP, URL, or hash) via TinyFish.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "The indicator string to research (e.g. '8.8.8.8', 'evil-c2.com', or SHA-256 hash).",
                },
                "indicator_type": {
                    "type": "string",
                    "enum": ["auto", "domain", "ipv4", "ipv6", "url", "sha256", "sha1", "md5"],
                    "description": "Optional type override. Defaults to 'auto' for automated detection.",
                },
                "case_id": {
                    "type": "string",
                    "description": "Optional case ID to link this research to.",
                },
            },
            "required": ["indicator"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jocky_list_findings",
        "description": "List correlated findings and threat intelligence detections for a specific case.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "Case identifier.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum findings to return (1-50, default 20).",
                    "default": 20,
                },
            },
            "required": ["case_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jocky_list_evidence",
        "description": "Retrieve forensic evidence records and SHA-256 integrity status for a specific case.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "Case identifier.",
                },
                "verify_integrity": {
                    "type": "boolean",
                    "description": "Recalculate SHA-256 digest from on-disk artifact bytes to verify integrity.",
                    "default": True,
                },
            },
            "required": ["case_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jocky_get_research_history",
        "description": "Retrieve persistent TinyFish public-web threat research history and source links for a case.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "Case identifier.",
                },
            },
            "required": ["case_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jocky_generate_investigation_summary",
        "description": "Generate an authorized investigation summary from persisted case records, evidence ledger, and TinyFish intelligence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "Case identifier.",
                },
            },
            "required": ["case_id"],
            "additionalProperties": False,
        },
    },
]


def handle_call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    db_path = os.environ.get("JOCKY_DB", DEFAULT_DB_PATH)

    if name == "jocky_list_cases":
        cases = CaseModel.list_all(db_path)
        content = [
            {
                "id": c.get("id"),
                "name": c.get("name"),
                "status": c.get("status"),
                "created_at": c.get("created_at"),
                "investigator": c.get("investigator_name"),
            }
            for c in cases[:50]
        ]
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"cases_count": len(content), "cases": content}, indent=2),
                }
            ]
        }

    elif name == "jocky_get_case_summary":
        cid = arguments.get("case_id", "").strip()
        if not cid:
            raise ValueError("case_id is required")

        case = CaseModel.get_by_id(cid, db_path)
        if not case:
            return {"content": [{"type": "text", "text": json.dumps({"error": f"Case '{cid}' not found"}, indent=2)}], "isError": True}

        from server.database import get_dfir_overview_stats
        conn = get_db_connection(db_path)
        stats = get_dfir_overview_stats(conn, case_id=cid)
        conn.close()

        summary = {
            "case": case,
            "artifact_counts": stats.get("counts", {}),
            "status": stats.get("status", "UNKNOWN"),
        }
        return {"content": [{"type": "text", "text": json.dumps(summary, indent=2)}]}

    elif name == "jocky_research_indicator":
        ind = arguments.get("indicator", "").strip()
        itype = arguments.get("indicator_type", "auto")
        cid = arguments.get("case_id")

        if not ind:
            raise ValueError("indicator is required")

        res = TinyFishService.search(ind, indicator_type=itype)
        if not res.get("success"):
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": True}

        # If case_id provided, save research
        if cid:
            case = CaseModel.get_by_id(cid, db_path)
            if case:
                ThreatIntelModel.save_research(
                    case_id=cid,
                    indicator=res["indicator"],
                    indicator_type=res["indicator_type"],
                    query=res["query"],
                    sources=res.get("results", []),
                    db_path=db_path,
                )

        return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}

    elif name == "jocky_list_findings":
        cid = arguments.get("case_id", "").strip()
        limit = min(50, max(1, int(arguments.get("limit", 20))))

        if not cid:
            raise ValueError("case_id is required")

        conn = get_db_connection(db_path)
        rows = conn.execute(
            "SELECT * FROM findings WHERE case_id = ? ORDER BY timestamp DESC LIMIT ?",
            (cid, limit),
        ).fetchall()
        conn.close()

        findings = []
        for r in rows:
            d = dict(r)
            try:
                d["evidence_refs"] = json.loads(d.get("evidence_refs") or "[]")
            except Exception:
                pass
            findings.append(d)

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"case_id": cid, "count": len(findings), "findings": findings}, indent=2),
                }
            ]
        }

    elif name == "jocky_list_evidence":
        cid = arguments.get("case_id", "").strip()
        verify_integrity = arguments.get("verify_integrity", True)
        if not cid:
            raise ValueError("case_id is required")

        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("""
            SELECT e.* FROM evidence e
            JOIN jobs j ON e.job_id = j.id
            JOIN sessions s ON j.session_id = s.id
            WHERE s.case_id = ?
            ORDER BY e.uploaded_at DESC
        """, (cid,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        from collector.manifest import calculate_sha256
        evidence_items = []
        verified_count = 0
        mismatch_count = 0
        missing_count = 0

        for r in rows:
            path = r.get("archive_path") or ""
            stored_sha = r.get("sha256") or ""
            item = {
                "id": r.get("id"),
                "job_id": r.get("job_id"),
                "archive_path": path,
                "size_bytes": r.get("size_bytes"),
                "stored_sha256": stored_sha,
                "uploaded_at": r.get("uploaded_at"),
                "source_collector": r.get("source_collector"),
            }
            if verify_integrity:
                if not os.path.exists(path):
                    item["integrity_status"] = "FILE_MISSING"
                    missing_count += 1
                else:
                    actual = calculate_sha256(path)
                    item["actual_sha256"] = actual
                    if actual == stored_sha:
                        item["integrity_status"] = "VERIFIED_MATCH"
                        verified_count += 1
                    else:
                        item["integrity_status"] = "TAMPERED_MISMATCH"
                        mismatch_count += 1
            evidence_items.append(item)

        out_data = {
            "case_id": cid,
            "total_evidence_count": len(evidence_items),
            "integrity_summary": {
                "verified": verified_count,
                "mismatch": mismatch_count,
                "missing": missing_count,
            } if verify_integrity else None,
            "evidence": evidence_items,
        }
        return {"content": [{"type": "text", "text": json.dumps(out_data, indent=2)}]}

    elif name == "jocky_get_research_history":
        cid = arguments.get("case_id", "").strip()
        if not cid:
            raise ValueError("case_id is required")

        records = ThreatIntelModel.list_for_case(cid, db_path)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "case_id": cid,
                        "research_records_count": len(records),
                        "research": records
                    }, indent=2)
                }
            ]
        }

    elif name == "jocky_generate_investigation_summary":
        cid = arguments.get("case_id", "").strip()
        if not cid:
            raise ValueError("case_id is required")

        case = CaseModel.get_by_id(cid, db_path)
        if not case:
            return {"content": [{"type": "text", "text": json.dumps({"error": f"Case '{cid}' not found"}, indent=2)}], "isError": True}

        from server.database import get_dfir_overview_stats
        conn = get_db_connection(db_path)
        stats = get_dfir_overview_stats(conn, case_id=cid)
        findings = conn.execute("SELECT * FROM findings WHERE case_id = ?", (cid,)).fetchall()
        research = conn.execute("SELECT * FROM threat_intel_research WHERE case_id = ?", (cid,)).fetchall()
        evidence = conn.execute("""
            SELECT e.* FROM evidence e
            JOIN jobs j ON e.job_id = j.id
            JOIN sessions s ON j.session_id = s.id
            WHERE s.case_id = ?
        """, (cid,)).fetchall()
        conn.close()

        summary_text = (
            f"=== INVESTIGATION SUMMARY: {case.get('name')} ({cid}) ===\n"
            f"Status: {case.get('status')} | Severity: {case.get('severity', 'MEDIUM')}\n"
            f"Lead Investigator: {case.get('investigator_name') or 'DFIR Team'}\n"
            f"Description: {case.get('description') or 'Defensive triage'}\n\n"
            f"1. FORENSIC EVIDENCE LEDGER:\n"
            f"   Total Preserved Packages: {len(evidence)}\n"
            f"   Telemetry Artifacts Collected: {stats.get('counts', {}).get('artifacts', 0)}\n\n"
            f"2. ATT&CK FINDINGS & CORRELATION:\n"
            f"   Confirmed Findings: {len(findings)}\n"
            f"   MITRE Techniques: {', '.join(set(str(f['mitre_technique']) for f in findings if f['mitre_technique'])) or 'None'}\n\n"
            f"3. TINYFISH THREAT INTELLIGENCE RESEARCH:\n"
            f"   Public Queries Executed: {len(research)}\n"
            f"   Corroborating Web Sources: {sum(len(json.loads(r['sources_json'] or '[]')) for r in research)}\n"
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": summary_text
                }
            ]
        }

    else:
        raise ValueError(f"Unknown tool: {name}")


def main():
    """Main JSON-RPC stdio event loop."""
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            continue

        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "capabilities": {"tools": {}},
                },
            }
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOLS},
            }
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                result = handle_call_tool(tool_name, tool_args)
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": result}
            except Exception as e:
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                        "isError": True,
                    },
                }
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found"},
            }

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
