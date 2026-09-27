"""
JOCKY Stage 17/18 Comprehensive DFIR Test Suite & Security Audit
Verifies Honest Location Model, Driver BYOVD Assessment, Defender Telemetry, Offline Forensics,
Unified Timeline, Correlation Engine, Secure Evidence Viewer, Encrypted Download, HTML & PDF Reports,
Tamper Detection, and API Authorization Boundaries.
"""
import os
import sys
import json
import io
import pytest
import tempfile

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.location import get_location_telemetry
from collector.driver_forensics import get_driver_forensics
from collector.security_telemetry import get_defender_security_telemetry
from collector.offline_forensics import OfflineForensicsParser, run_offline_analysis
from collector.windows_collector import (
    get_windows_browser_history,
    get_windows_login_events,
    get_windows_network_interfaces
)
from server.timeline import TimelineEngine
from server.correlation import CorrelationEngine
from server.reports import ReportGenerator
from server.server import app, init_db, DB_PATH, EVIDENCE_DIR
import server.server as srv


def test_location_honesty_scenarios():
    # Scenario 1: No GPS/device location available -> exact_location_available is False
    loc = get_location_telemetry()
    assert loc["exact_location_available"] is False
    assert "source" in loc
    assert "accuracy" in loc
    assert "confidence" in loc
    assert "honesty_note" in loc

    # Scenario 2: Public IP location available -> reported as approximate, never manufactured exact GPS
    if "Public IP" in loc["source"]:
        assert loc["confidence"] == "MEDIUM"
        assert "Approximate" in loc["accuracy"]

    # Scenario 3: Forced offline / No network source available -> returns System Timezone / Locale fallback
    loc_offline = get_location_telemetry(force_offline=True)
    assert loc_offline["exact_location_available"] is False
    assert loc_offline["confidence"] == "LOW"
    assert loc_offline["source"] == "System Timezone / Locale"
    assert "Exact GPS location UNAVAILABLE" in loc_offline["honesty_note"]



def test_driver_assessment():
    drivers = get_driver_forensics()
    assert isinstance(drivers, list)
    assert len(drivers) > 0
    first = drivers[0]
    assert "driver_name" in first
    assert "signature_status" in first
    assert "is_vulnerable" in first
    assert "risk_level" in first

    vulnerable_drivers = [d for d in drivers if d["is_vulnerable"]]
    if vulnerable_drivers:
        assert vulnerable_drivers[0]["cve"] != "N/A"


def test_defender_telemetry():
    sec_events = get_defender_security_telemetry()
    assert isinstance(sec_events, list)
    assert len(sec_events) > 0
    assert "product" in sec_events[0]
    assert "action_taken" in sec_events[0]


def test_offline_forensics():
    with tempfile.TemporaryDirectory() as tmpdir:
        res = run_offline_analysis(tmpdir)
        assert res["mode"] == "OFFLINE FORENSIC ANALYSIS"
        assert "registry_hives" in res
        assert "event_logs" in res
        assert "browser_artifacts" in res


def test_windows_extended_collectors():
    history = get_windows_browser_history()
    assert isinstance(history, list)
    logins = get_windows_login_events()
    assert isinstance(logins, list)
    interfaces = get_windows_network_interfaces()
    assert isinstance(interfaces, list)


def test_timeline_and_correlation():
    logins = get_windows_login_events()
    defender_events = get_defender_security_telemetry()
    drivers = get_driver_forensics()

    timeline = TimelineEngine.generate_timeline(
        logins=logins,
        processes=[],
        network=[],
        defender_events=defender_events,
        drivers=drivers,
        evidence_id="EVID-TEST"
    )
    assert isinstance(timeline, list)
    assert len(timeline) > 0

    findings = CorrelationEngine.correlate_evidence(timeline, "EVID-TEST")
    assert isinstance(findings, list)
    assert len(findings) > 0
    assert "evidence_references" in findings[0]
    assert "EVID-TEST" in findings[0]["evidence_references"]


def test_correlation_insufficient_evidence():
    # Verify correlation engine does NOT manufacture critical findings on benign/minimal telemetry
    minimal_timeline = [
        {
            "timestamp": "2026-09-08T12:00:00Z",
            "source": "AUTHENTICATION",
            "event_type": "USER_LOGIN",
            "status": "SUCCESS",
            "username": "StandardUser"
        }
    ]
    findings = CorrelationEngine.correlate_evidence(minimal_timeline, "EVID-MINIMAL")
    assert len(findings) == 1
    assert findings[0]["severity"] in ["INFORMATIONAL", "CLEAN"] or "Standard" in findings[0]["title"]


@pytest.fixture
def test_client():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = os.path.join(tmpdir, "dfir_stage17.db")
        evd_dir = os.path.join(tmpdir, "evidence")
        os.environ["JOCKY_DB"] = test_db
        os.environ["JOCKY_EVIDENCE_DIR"] = evd_dir
        srv.DB_PATH = test_db
        srv.EVIDENCE_DIR = evd_dir
        init_db(test_db)
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client


def test_stage17_18_api_endpoints(test_client):
    # Location
    res_loc = test_client.get("/api/cases/case_demo/location")
    assert res_loc.status_code == 200
    assert "accuracy" in res_loc.get_json()

    # Drivers
    res_drv = test_client.get("/api/cases/case_demo/drivers")
    assert res_drv.status_code == 200
    assert "drivers" in res_drv.get_json()

    # Security events
    res_sec = test_client.get("/api/cases/case_demo/security_events")
    assert res_sec.status_code == 200
    assert "defender_events" in res_sec.get_json()

    # Timeline
    res_tl = test_client.get("/api/cases/case_id/timeline")
    assert res_tl.status_code == 200
    assert "timeline" in res_tl.get_json()

    # Findings
    res_f = test_client.get("/api/cases/case_id/findings")
    assert res_f.status_code == 200
    assert "findings" in res_f.get_json()


def test_tamper_detection_and_integrity(test_client):
    # Register device, case, session, job
    test_client.post("/api/devices/register", json={"device_id": "audit_agent_01", "hostname": "HOST-01", "os": "Windows 11"})
    res_c = test_client.post("/api/cases", json={"name": "Tamper Test Case"})
    case_id = res_c.get_json()["id"]

    res_s = test_client.post("/api/sessions", json={"case_id": case_id, "name": "Integrity Session"})
    session_id = res_s.get_json()["id"]

    dsl = "module test { collect system }"
    res_comp = test_client.post("/api/compile", json={"source": dsl})
    plan_hash = res_comp.get_json()["plan"]["plan_hash"]

    res_j = test_client.post("/api/jobs", json={"session_id": session_id, "agent_id": "audit_agent_01", "plan_hash": plan_hash})
    job_id = res_j.get_json()["id"]

    # Upload evidence
    original_data = b"AUTHENTIC FORENSIC EVIDENCE CONTENT"
    res_up = test_client.post("/api/evidence", data={
        "job_id": job_id,
        "manifest": json.dumps({"files": []}),
        "file": (io.BytesIO(original_data), "archive.tar.gz")
    })
    assert res_up.status_code == 201
    evd_id = res_up.get_json()["id"]

    # Verify integrity (Original - MUST PASS)
    res_v1 = test_client.get(f"/api/evidence/{evd_id}/verify")
    assert res_v1.status_code == 200
    assert res_v1.get_json()["valid"] is True

    # Corrupt the evidence file on disk intentionally
    evd_record = srv.EvidenceModel.get_by_id(evd_id, srv.DB_PATH)
    archive_path = evd_record["archive_path"]
    with open(archive_path, "wb") as f:
        f.write(b"CORRUPTED TAMPERED DATA BY ATTACKER")

    # Verify integrity (Corrupted - MUST FAIL)
    res_v2 = test_client.get(f"/api/evidence/{evd_id}/verify")
    assert res_v2.status_code == 200
    assert res_v2.get_json()["valid"] is False
    assert res_v2.get_json()["status"] == "INTEGRITY FAILURE"


def test_api_authorization_and_isolation(test_client):
    # Invalid evidence query
    res_404 = test_client.get("/api/evidence/nonexistent_evd_12345/view")
    assert res_404.status_code == 404

    res_dl_404 = test_client.get("/api/evidence/nonexistent_evd_12345/download_encrypted")
    assert res_dl_404.status_code == 404


def test_reports_html_pdf(test_client):
    res_c = test_client.post("/api/cases", json={"name": "DFIR Investigation Report Test", "description": "Full Stage 17/18 test case"})
    case_id = res_c.get_json()["id"]

    res_html = test_client.get(f"/api/cases/{case_id}/report/html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.content_type
    assert b"JOCKY Forensic Investigation Report" in res_html.data
    assert b"Executive Summary" in res_html.data

    res_pdf = test_client.get(f"/api/cases/{case_id}/report/pdf")
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.content_type
