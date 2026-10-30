"""
TINY MONITOR — Evidence-to-Context Graph Verification Tests
Tests the relational graph API backed by persisted database records:
Case -> Devices -> Jobs -> Evidence -> Hashes -> TinyFish Research -> Sources -> Findings.
"""
import json
import os
import io
import pytest

from server.server import app, init_db, get_db_path, get_evidence_dir
import server.server as srv
from server.models import CaseModel, SessionModel, JobModel, DeviceModel, ThreatIntelModel
from server.evidence import EvidenceModel


@pytest.fixture
def graph_test_client(tmp_path):
    test_db = str(tmp_path / "graph_test.db")
    test_evd = str(tmp_path / "evidence")
    os.makedirs(test_evd, exist_ok=True)
    init_db(test_db)

    old_db = os.environ.get("JOCKY_DB")
    old_evd = os.environ.get("JOCKY_EVIDENCE_DIR")
    os.environ["JOCKY_DB"] = test_db
    os.environ["JOCKY_EVIDENCE_DIR"] = test_evd
    srv.DB_PATH = test_db
    srv.EVIDENCE_DIR = test_evd

    app.config["TESTING"] = True

    # 1. Seed Case
    case = CaseModel.create(
        name="Graph Verification Operation",
        description="Verifying relational Evidence-to-Context graph backing",
        db_path=test_db,
        investigator_name="Investigator Alpha"
    )
    cid = case["id"]

    # 2. Seed Device & Plan
    dev = DeviceModel.register_or_update("graph-ep-01", "workstation-01", "Windows", "10.0.1.55", test_db)
    DeviceModel.assign_case("graph-ep-01", cid, test_db)

    conn = srv.get_db_connection(test_db)
    conn.execute("INSERT OR REPLACE INTO plans (plan_hash, module_name, plan_json, created_at) VALUES ('plan_graph_01', 'graph_plan', '{}', datetime('now'))")
    conn.commit()
    conn.close()

    # 3. Seed Session & Job
    sess = SessionModel.create(cid, "Graph Triage Session", test_db)
    job = JobModel.create(sess["id"], "graph-ep-01", "plan_graph_01", test_db)

    # 4. Seed Evidence Archive
    ev_file = tmp_path / "evidence_vault.tar.gz"
    ev_file.write_bytes(b"FORENSIC_MEMORY_PROCESS_DUMP_STREAM_GRAPH_TEST")
    evd = EvidenceModel.register_evidence(
        job_id=job["id"],
        archive_path=str(ev_file),
        manifest_data={"evidence_name": "vault.tar.gz"},
        device_id="graph-ep-01",
        db_path=test_db
    )

    # 5. Seed TinyFish Threat Intel Research
    res_ti = ThreatIntelModel.save_research(
        case_id=cid,
        indicator="c2-beacon.darknet.org",
        indicator_type="domain",
        query='"c2-beacon.darknet.org" threat',
        sources=[
            {
                "title": "US-CERT Alert: Threat Actor Infrastructure C2",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-c2",
                "domain": "cisa.gov",
                "site_name": "US Cybersecurity and Infrastructure Security Agency",
                "relevance_score": 96,
                "snippet": "Active exploitation observed communicating with c2-beacon.darknet.org"
            },
            {
                "title": "VirusTotal Domain Graph Report",
                "url": "https://www.virustotal.com/gui/domain/c2-beacon.darknet.org",
                "domain": "virustotal.com",
                "site_name": "VirusTotal",
                "relevance_score": 90,
                "snippet": "14 security vendors flagged domain as malicious."
            }
        ],
        db_path=test_db
    )

    # 6. Seed Finding linked to research
    ThreatIntelModel.save_to_findings(
        case_id=cid,
        research_id=res_ti["id"],
        title="Host Communicating with Identified C2 Domain",
        severity="CRITICAL",
        investigator_notes="Process sockets confirm outbound DNS resolution to c2-beacon.darknet.org.",
        recommendations="Sinkhole domain and revoke device token.",
        mitre_technique="T1071.001",
        db_path=test_db
    )

    with app.test_client() as client:
        yield {
            "client": client,
            "case_id": cid,
            "device_id": "graph-ep-01",
            "job_id": job["id"],
            "evidence_id": evd["id"],
            "evidence_path": str(ev_file),
            "threat_intel_id": res_ti["id"]
        }

    if old_db:
        os.environ["JOCKY_DB"] = old_db
    else:
        os.environ.pop("JOCKY_DB", None)
    if old_evd:
        os.environ["JOCKY_EVIDENCE_DIR"] = old_evd
    else:
        os.environ.pop("JOCKY_EVIDENCE_DIR", None)


def test_case_graph_retrieval_and_node_types(graph_test_client):
    client = graph_test_client["client"]
    cid = graph_test_client["case_id"]

    res = client.get(f"/api/cases/{cid}/graph")
    assert res.status_code == 200
    data = res.get_json()

    assert data["case_id"] == cid
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data

    nodes = data["nodes"]
    node_types = set(n["type"] for n in nodes)
    assert "case" in node_types
    assert "device" in node_types
    assert "job" in node_types
    assert "evidence" in node_types
    assert "hash" in node_types
    assert "threat_intel" in node_types
    assert "source" in node_types
    assert "finding" in node_types

    # Verify categories
    categories = set(n["category"] for n in nodes)
    assert "INVESTIGATION_ROOT" in categories
    assert "ORIGINAL_EVIDENCE" in categories
    assert "EXTERNAL_INTELLIGENCE" in categories
    assert "ANALYST_CONCLUSION" in categories

    # Verify edges exist and connect nodes
    node_id_map = {n["id"]: n for n in nodes}
    for e in data["edges"]:
        assert e["source"] in node_id_map, f"Missing source node: {e['source']}"
        assert e["target"] in node_id_map, f"Missing target node: {e['target']}"
        assert "relation" in e


def test_case_graph_tamper_detection(graph_test_client):
    client = graph_test_client["client"]
    cid = graph_test_client["case_id"]
    ev_path = graph_test_client["evidence_path"]

    # Deliberately tamper with stored evidence bytes
    with open(ev_path, "wb") as f:
        f.write(b"CORRUPTED_TAMPERED_FORENSIC_BYTES_MISMATCH")

    res = client.get(f"/api/cases/{cid}/graph")
    assert res.status_code == 200
    data = res.get_json()

    evidence_nodes = [n for n in data["nodes"] if n["type"] == "evidence"]
    assert len(evidence_nodes) >= 1
    ev_node = evidence_nodes[0]
    assert ev_node["status"] == "TAMPERED_MISMATCH"
    assert ev_node["details"]["verified"] is False


def test_graph_endpoint_fallback(graph_test_client):
    client = graph_test_client["client"]
    cid = graph_test_client["case_id"]

    res = client.get(f"/api/graph?case_id={cid}")
    assert res.status_code == 200
    assert res.get_json()["case_id"] == cid
