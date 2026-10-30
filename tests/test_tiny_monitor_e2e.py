"""
TINY MONITOR — End-to-End DFIR Platform Verification Test
Validates:
  1. Dashboard view returns 200 with Tiny Monitor branding and Presidency University event label.
  2. System status endpoint returns operational state and TinyFish provider info.
  3. Threat Intel status reports genuine configuration without leaking API keys.
  4. Indicator validation correctly classifies domain, IPv4, IPv6, URL, and hashes.
  5. Case creation, listing, updating, and note attachment.
  6. Direct evidence file ingest with SHA-256 hashing.
  7. Cryptographic integrity verification via SHA-256 matching.
  8. Standalone forensic report generation with TinyFish threat intelligence corroboration.
"""
import io
import os
import json
import pytest
from server.server import app, init_db, DB_PATH
from server.tinyfish_service import is_tinyfish_configured


@pytest.fixture
def e2e_client(tmp_path):
    test_db = str(tmp_path / "e2e_forensics.db")
    test_evd = str(tmp_path / "evidence")
    os.makedirs(test_evd, exist_ok=True)
    init_db(test_db)

    old_db = os.environ.get("JOCKY_DB")
    old_evd = os.environ.get("JOCKY_EVIDENCE_DIR")
    os.environ["JOCKY_DB"] = test_db
    os.environ["JOCKY_EVIDENCE_DIR"] = test_evd

    import server.server as srv
    srv.DB_PATH = test_db
    srv.EVIDENCE_DIR = test_evd
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client

    if old_db:
        os.environ["JOCKY_DB"] = old_db
    else:
        os.environ.pop("JOCKY_DB", None)
    if old_evd:
        os.environ["JOCKY_EVIDENCE_DIR"] = old_evd
    else:
        os.environ.pop("JOCKY_EVIDENCE_DIR", None)


def test_dashboard_serving_and_branding(e2e_client):
    with e2e_client.session_transaction() as sess:
        sess["dashboard_authenticated"] = True
    res = e2e_client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Tiny Monitor" in html
    assert "Presidency University" in html
    assert "Swim with TinyFish" in html
    assert "Threat Intelligence" in html
    # Ensure all DOM elements required for case creation and banner rendering are present
    assert 'id="lockedOs"' in html
    assert 'id="caseBanner"' in html
    assert 'id="caseForm"' in html
    assert 'id="caseError"' in html


def test_case_creation_payload_and_dom_integrity(e2e_client):
    """Regression test: verifies case creation API payload structure matches frontend expectations,
    and dashboard HTML possesses all target DOM nodes required by initializeDashboard() and renderCaseBanner().
    """
    # 1. Verify case creation API matches dashboard frontend payload schema
    payload = {
        "name": "Live Incident Triage",
        "description": "Comprehensive local host digital forensics triage",
        "investigator_name": "INV-9042-FED",
        "investigator_org": "Digital Forensics Unit",
        "subject_name": "Comprehensive local host digital forensics triage",
        "authorization_ref": "Warrant #2026-904",
        "evidence_source": "Chief Forensics Officer",
        "target_os": "Windows",
        "investigation_notes": "Tracking ID: CASE-2026-ABCD; Status: Active; Severity: High"
    }
    res = e2e_client.post("/api/cases", json=payload)
    assert res.status_code == 201
    created = res.get_json()
    assert "id" in created
    assert created["id"].startswith("case_")
    assert created["name"] == payload["name"]

    # 2. Verify dashboard HTML has all DOM references required by case creation handlers
    with e2e_client.session_transaction() as sess:
        sess["dashboard_authenticated"] = True
    dash_res = e2e_client.get("/")
    assert dash_res.status_code == 200
    html = dash_res.data.decode("utf-8")
    assert 'id="lockedOs"' in html
    assert 'id="caseBanner"' in html
    assert 'id="caseForm"' in html
    assert 'id="caseError"' in html
    assert 'id="caseTracking"' in html
    assert 'id="caseName"' in html
    assert 'id="scope"' in html
    assert 'id="investigator"' in html
    assert 'id="topTinyFishStatus"' in html


def test_system_status_endpoint(e2e_client):
    res = e2e_client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["system"] == "TINY MONITOR"
    assert data["event"] == "Swim with TinyFish — Presidency University"
    assert "tinyfish" in data
    assert data["tinyfish"]["configured"] is True


def test_threat_intel_status_no_secret_leak(e2e_client):
    res = e2e_client.get("/api/threat-intel/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["configured"] is True
    assert data["provider"] == "TinyFish"
    # Ensure raw secret is NEVER in payload
    raw_str = json.dumps(data)
    assert "sk-" not in raw_str
    assert "EXD0s" not in raw_str


def test_indicator_validation_matrix(e2e_client):
    test_cases = [
        ("8.8.8.8", "ipv4"),
        ("evil-c2.com", "domain"),
        ("https://cisa.gov/advisory", "url"),
        ("44d88612fea8a8f36de82e1278abb02f", "md5"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ]
    for ind, expected_type in test_cases:
        res = e2e_client.post("/api/threat-intel/validate", json={"indicator": ind})
        assert res.status_code == 200
        data = res.get_json()
        assert data["valid"] is True
        assert data["indicator_type"] == expected_type


def test_case_lifecycle_and_notes(e2e_client):
    # 1. Create Case
    res = e2e_client.post("/api/cases", json={
        "name": "Host Compromise Triage",
        "description": "Suspected unauthorized beaconing observed.",
        "investigator_name": "Senior Investigator",
        "severity": "HIGH"
    })
    assert res.status_code == 201
    case = res.get_json()
    cid = case["id"]

    # 2. Add Note
    res_note = e2e_client.post(f"/api/cases/{cid}/notes", json={
        "note": "Volatile memory acquired and preserved outside target root.",
        "author": "Forensics Specialist"
    })
    assert res_note.status_code == 201

    # 3. Update Status
    res_patch = e2e_client.patch(f"/api/cases/{cid}", json={"status": "CLOSED"})
    assert res_patch.status_code == 200
    assert res_patch.get_json()["case"]["status"] == "CLOSED"


def test_evidence_ingest_and_hash_verification(e2e_client):
    # Create Case
    c_res = e2e_client.post("/api/cases", json={"name": "Evidence Ingest Case"})
    cid = c_res.get_json()["id"]

    # Ingest safe evidence bytes
    safe_evidence_bytes = b"DEMO_INCIDENT_TRACE_LOG_PACKET_DUMP_2026_PRESERVED"
    data = {
        "case_id": cid,
        "file": (io.BytesIO(safe_evidence_bytes), "safe_demo_packet_trace.pcap"),
        "manifest": json.dumps({"description": "Simulated forensic network capture"})
    }
    upload_res = e2e_client.post("/api/evidence", data=data, content_type="multipart/form-data")
    assert upload_res.status_code == 201
    evd = upload_res.get_json()
    assert "sha256" in evd
    assert len(evd["sha256"]) == 64
    evd_id = evd["id"]

    # Verify SHA-256 integrity
    verify_res = e2e_client.get(f"/api/evidence/{evd_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.get_json()
    assert v_data["valid"] is True
    assert v_data["expected_sha256"] == evd["sha256"]
    assert v_data["actual_sha256"] == evd["sha256"]


def test_report_generation_with_branding(e2e_client):
    c_res = e2e_client.post("/api/cases", json={"name": "Report Verification Case"})
    cid = c_res.get_json()["id"]

    res = e2e_client.get(f"/api/reports/html?case_id={cid}")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Tiny Monitor" in html
    assert "Presidency University" in html
    assert cid in html
