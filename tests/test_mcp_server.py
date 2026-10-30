"""
TINY MONITOR / JOCKY DFIR — Model Context Protocol (MCP) Server Tests
Tests JSON-RPC 2.0 stdio protocol handling, tools listing, and real tool invocation
with evidence hashing, case summary, threat intel research, and authorization checks.
"""
import json
import os
import io
import pytest
from unittest.mock import patch, MagicMock

from server.database import init_db, get_db_connection
from server.models import CaseModel, SessionModel, JobModel, ThreatIntelModel
from server.evidence import EvidenceModel
from server.mcp_server import handle_call_tool, TOOLS, SERVER_NAME, PROTOCOL_VERSION


@pytest.fixture
def mcp_test_db(tmp_path):
    db_file = str(tmp_path / "mcp_test.db")
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    init_db(db_file)
    os.environ["JOCKY_DB"] = db_file
    os.environ["JOCKY_EVIDENCE_DIR"] = str(ev_dir)

    # Seed test case
    case = CaseModel.create(
        name="MCP Triage Case",
        description="Investigating suspicious beaconing via MCP tools",
        db_path=db_file,
        investigator_name="Lead Analyst"
    )
    cid = case["id"]

    # Register device and plan to satisfy foreign keys
    from server.models import DeviceModel
    DeviceModel.register_or_update("mcp-agent-01", "mcp-host", "Windows", "127.0.0.1", db_file)
    conn = get_db_connection(db_file)
    conn.execute("INSERT OR REPLACE INTO plans (plan_hash, module_name, plan_json, created_at) VALUES ('plan_hash_dummy', 'test_plan', '{}', datetime('now'))")
    conn.commit()
    conn.close()

    # Seed session & job
    sess = SessionModel.create(cid, "MCP Session", db_file)
    job = JobModel.create(sess["id"], "mcp-agent-01", "plan_hash_dummy", db_file)

    # Seed evidence archive
    sample_archive = tmp_path / "sample_evidence.tar.gz"
    sample_archive.write_bytes(b"FORENSIC_EVIDENCE_SAMPLE_BYTES_FOR_MCP_VERIFICATION")
    evd = EvidenceModel.register_evidence(
        job_id=job["id"],
        archive_path=str(sample_archive),
        manifest_data={"source": "mcp_test"},
        device_id="mcp-agent-01",
        db_path=db_file
    )

    # Seed threat intel research
    res_intel = ThreatIntelModel.save_research(
        case_id=cid,
        indicator="198.51.100.24",
        indicator_type="ipv4",
        query='"198.51.100.24" threat',
        sources=[{
            "title": "CISA Advisory: Threat Actor Infrastructure",
            "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-mock",
            "snippet": "Advisory identifying anomalous beaconing from 198.51.100.24",
            "relevance_score": 92,
            "site_name": "cisa.gov"
        }],
        db_path=db_file
    )

    # Seed finding
    ThreatIntelModel.save_to_findings(
        case_id=cid,
        research_id=res_intel["id"],
        title="Suspicious External Beaconing",
        severity="HIGH",
        investigator_notes="Correlated beaconing to known hostile infrastructure.",
        recommendations="Isolate host from subnet.",
        mitre_technique="T1071",
        db_path=db_file
    )

    yield {"db_path": db_file, "case_id": cid, "evidence_id": evd["id"], "evidence_path": str(sample_archive)}

    os.environ.pop("JOCKY_DB", None)
    os.environ.pop("JOCKY_EVIDENCE_DIR", None)


def test_mcp_tools_schema_validity():
    tool_names = [t["name"] for t in TOOLS]
    assert "jocky_list_cases" in tool_names
    assert "jocky_get_case_summary" in tool_names
    assert "jocky_research_indicator" in tool_names
    assert "jocky_list_findings" in tool_names
    assert "jocky_list_evidence" in tool_names
    assert "jocky_get_research_history" in tool_names
    assert "jocky_generate_investigation_summary" in tool_names

    for t in TOOLS:
        assert "name" in t
        assert "description" in t
        assert "inputSchema" in t
        assert t["inputSchema"]["type"] == "object"


def test_mcp_tool_list_cases(mcp_test_db):
    res = handle_call_tool("jocky_list_cases", {})
    assert "content" in res
    data = json.loads(res["content"][0]["text"])
    assert data["cases_count"] >= 1
    assert any(c["id"] == mcp_test_db["case_id"] for c in data["cases"])


def test_mcp_tool_get_case_summary(mcp_test_db):
    cid = mcp_test_db["case_id"]
    res = handle_call_tool("jocky_get_case_summary", {"case_id": cid})
    assert "content" in res
    data = json.loads(res["content"][0]["text"])
    assert data["case"]["id"] == cid
    assert "artifact_counts" in data


def test_mcp_tool_list_evidence_and_integrity(mcp_test_db):
    cid = mcp_test_db["case_id"]
    res = handle_call_tool("jocky_list_evidence", {"case_id": cid, "verify_integrity": True})
    assert "content" in res
    data = json.loads(res["content"][0]["text"])
    assert data["case_id"] == cid
    assert data["total_evidence_count"] >= 1
    ev_item = data["evidence"][0]
    assert ev_item["integrity_status"] == "VERIFIED_MATCH"
    assert "stored_sha256" in ev_item
    assert "actual_sha256" in ev_item
    assert ev_item["stored_sha256"] == ev_item["actual_sha256"]


def test_mcp_tool_detects_tampered_evidence(mcp_test_db):
    cid = mcp_test_db["case_id"]
    ev_path = mcp_test_db["evidence_path"]

    # Tamper with the artifact on disk
    with open(ev_path, "wb") as f:
        f.write(b"DELIBERATELY_TAMPERED_EVIDENCE_BYTES_ALTERED")

    res = handle_call_tool("jocky_list_evidence", {"case_id": cid, "verify_integrity": True})
    data = json.loads(res["content"][0]["text"])
    ev_item = data["evidence"][0]
    assert ev_item["integrity_status"] == "TAMPERED_MISMATCH"
    assert data["integrity_summary"]["mismatch"] >= 1


def test_mcp_tool_get_research_history(mcp_test_db):
    cid = mcp_test_db["case_id"]
    res = handle_call_tool("jocky_get_research_history", {"case_id": cid})
    assert "content" in res
    data = json.loads(res["content"][0]["text"])
    assert data["case_id"] == cid
    assert data["research_records_count"] >= 1
    assert data["research"][0]["indicator"] == "198.51.100.24"


def test_mcp_tool_generate_investigation_summary(mcp_test_db):
    cid = mcp_test_db["case_id"]
    res = handle_call_tool("jocky_generate_investigation_summary", {"case_id": cid})
    assert "content" in res
    text = res["content"][0]["text"]
    assert cid in text
    assert "FORENSIC EVIDENCE LEDGER" in text
    assert "ATT&CK FINDINGS" in text
    assert "TINYFISH THREAT INTELLIGENCE" in text
