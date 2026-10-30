"""
TINY MONITOR — REST API Endpoints Integration Tests
Tests cases, evidence upload, verify, and report endpoints.
"""

import io
import json


def test_api_status_endpoint(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["system"] == "TINY MONITOR"
    assert "tinyfish" in data
    assert "metrics" in data


def test_api_cases_crud_workflow(client):
    # 1. Create Case
    res = client.post("/api/cases", json={
        "title": "API Test Incident",
        "investigator": "Agent Smith",
        "severity": "CRITICAL",
        "description": "API verification case."
    })
    assert res.status_code == 201
    case = res.get_json()["case"]
    case_id = case["id"]

    # 2. Get Case Details
    res2 = client.get(f"/api/cases/{case_id}")
    assert res2.status_code == 200
    assert res2.get_json()["case"]["title"] == "API Test Incident"

    # 3. Patch Case Status
    res3 = client.patch(f"/api/cases/{case_id}", json={
        "status": "CONTAINED",
        "severity": "HIGH"
    })
    assert res3.status_code == 200
    assert res3.get_json()["case"]["status"] == "CONTAINED"
    assert res3.get_json()["case"]["severity"] == "HIGH"

    # 4. Add Note
    res4 = client.post(f"/api/cases/{case_id}/notes", json={
        "note": "Containment procedures verified.",
        "author": "Agent Smith"
    })
    assert res4.status_code == 201


def test_api_evidence_upload_and_verify(client):
    # Create Case
    case_res = client.post("/api/cases", json={"title": "Evidence API Case", "investigator": "Investigator 1"})
    case_id = case_res.get_json()["case"]["id"]

    # Upload evidence file
    file_bytes = b"BINARY_EVIDENCE_STREAM_PACKET_TRACE"
    data = {
        "file": (io.BytesIO(file_bytes), "packet_trace.pcap"),
        "acquired_by": "Network Forensics Team",
        "description": "Raw pcap capture of suspect exfiltration"
    }
    upload_res = client.post(
        f"/api/cases/{case_id}/evidence",
        data=data,
        content_type="multipart/form-data"
    )
    assert upload_res.status_code == 201
    ev_data = upload_res.get_json()["evidence"]
    evidence_id = ev_data["id"]
    assert ev_data["filename"] == "packet_trace.pcap"
    assert ev_data["integrity_status"] == "VERIFIED_MATCH"

    # Recalculate and verify integrity on demand
    verify_res = client.post(f"/api/evidence/{evidence_id}/verify", json={"verified_by": "Lead Verifier"})
    assert verify_res.status_code == 200
    assert verify_res.get_json()["status"] == "VERIFIED_MATCH"
    assert verify_res.get_json()["sha256"] == ev_data["sha256_hash"]


def test_api_generate_and_download_report(client):
    case_res = client.post("/api/cases", json={"title": "Report API Case", "investigator": "Lead"})
    case_id = case_res.get_json()["case"]["id"]

    rep_res = client.post(f"/api/cases/{case_id}/report", json={"generated_by": "Examiner"})
    assert rep_res.status_code == 201
    rep_data = rep_res.get_json()["report"]
    filename = rep_data["filename"]

    # Download report
    dl_res = client.get(f"/api/reports/download/{filename}")
    assert dl_res.status_code == 200
    assert dl_res.headers["Content-Type"] == "application/pdf"
    assert dl_res.data.startswith(b"%PDF-")
