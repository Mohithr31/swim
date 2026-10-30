"""
JOCKY DFIR Platform — Victim 2 End-to-End Workflow & Forensic Integrity Test
Validates the full 12-step investigator and endpoint agent lifecycle:
  1. Investigator authenticates.
  2. Investigator creates and scopes a case.
  3. Endpoint (Victim 2 / VICTIM-02-WIN) registers with authorized credentials.
  4. Victim 2 is assigned to the investigator case.
  5. Investigator dispatches an authorized, allowlisted collection job.
  6. Endpoint agent polls and retrieves the pending job.
  7. Endpoint agent executes safe collection, bundles manifest.json with SHA-256 hashes, and uploads evidence.
  8. Endpoint agent marks the job as COMPLETED.
  9. Backend performs cryptographic SHA-256 verification (both clean match and intentional tamper detection).
 10. Investigator inspects timeline, alerts, and evidence ledger.
 11. Investigator enriches evidence indicator via TinyFish threat intelligence workflow.
 12. Investigator generates court-admissible forensic report with cryptographic provenance.
"""
import io
import os
import json
import tarfile
import uuid
import hashlib
import pytest
from datetime import datetime, timezone

from server.server import app, init_db, DB_PATH
from server.evidence import EvidenceModel, calculate_sha256
from server.database import get_db_connection


@pytest.fixture
def victim2_env(tmp_path):
    test_db = str(tmp_path / "victim2_forensics.db")
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
        yield {
            "client": client,
            "db_path": test_db,
            "evidence_dir": test_evd,
        }

    if old_db:
        os.environ["JOCKY_DB"] = old_db
    else:
        os.environ.pop("JOCKY_DB", None)
    if old_evd:
        os.environ["JOCKY_EVIDENCE_DIR"] = old_evd
    else:
        os.environ.pop("JOCKY_EVIDENCE_DIR", None)


def _make_dummy_tar_gz(files_dict: dict) -> bytes:
    """Build an in-memory tar.gz containing specified filename -> bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for fname, data in files_dict.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            ti = tarfile.TarInfo(name=fname)
            ti.size = len(data)
            ti.mtime = int(datetime.now(timezone.utc).timestamp())
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_victim2_complete_e2e_forensic_workflow(victim2_env):
    client = victim2_env["client"]
    db_path = victim2_env["db_path"]

    # -------------------------------------------------------------------------
    # STEP 1: Investigator Authentication
    # -------------------------------------------------------------------------
    from server.server import get_dashboard_credentials
    exp_user, exp_pwd, exp_otp = get_dashboard_credentials()
    auth_res = client.post("/login", data={
        "username": exp_user,
        "password": exp_pwd,
        "otp": exp_otp
    }, follow_redirects=True)
    assert auth_res.status_code == 200, f"Investigator auth failed: {auth_res.data}"

    status_res = client.get("/api/auth/status")
    assert status_res.status_code == 200
    assert status_res.get_json().get("authenticated") is True

    # -------------------------------------------------------------------------
    # STEP 2: Create and Scope Case
    # -------------------------------------------------------------------------
    case_payload = {
        "name": "Operation Blue Dawn — Victim 2 Triage",
        "description": "Defensive incident response and forensic analysis of unauthorized execution on Victim 2.",
        "severity": "High",
        "investigator_name": "INV-9042-FED",
        "investigation_notes": "Authorized DFIR acquisition under incident response procedure."
    }
    case_res = client.post("/api/cases", json=case_payload)
    assert case_res.status_code == 201, f"Failed to create case: {case_res.data}"
    case_data = case_res.get_json()
    case_id = case_data["id"]
    assert case_id.lower().startswith("case")

    # Verify case details endpoint
    detail_res = client.get(f"/api/cases/{case_id}")
    assert detail_res.status_code == 200
    assert detail_res.get_json()["name"] == case_payload["name"]

    # -------------------------------------------------------------------------
    # STEP 3: Register Authorized Endpoint (Victim 2)
    # -------------------------------------------------------------------------
    agent_id = "VICTIM-02-WIN"
    reg_payload = {
        "device_id": agent_id,
        "hostname": "VICTIM-02-DESKTOP",
        "os": "Windows 11 Enterprise (Build 22631)",
        "ip_address": "192.168.1.102",
        "case_id": case_id
    }
    reg_res = client.post("/api/devices/register", json=reg_payload)
    assert reg_res.status_code == 200, f"Victim 2 registration failed: {reg_res.data}"
    dev_info = reg_res.get_json()
    assert dev_info["id"] == agent_id
    assert dev_info["hostname"] == "VICTIM-02-DESKTOP"

    # Verify enrolled devices listing
    enrolled_res = client.get("/api/devices/enrolled")
    assert enrolled_res.status_code == 200
    enrolled = enrolled_res.get_json()
    assert any(d["id"] == agent_id for d in enrolled)

    # -------------------------------------------------------------------------
    # STEP 4: Associate Victim 2 with the Investigation Case
    # -------------------------------------------------------------------------
    assign_res = client.post(f"/api/cases/{case_id}/assign", json={"agent_id": agent_id})
    assert assign_res.status_code == 200, f"Case assignment failed: {assign_res.data}"
    assert assign_res.get_json()["status"] == "assigned"

    # -------------------------------------------------------------------------
    # STEP 5: Dispatch Authorized Collection Job to Victim 2
    # -------------------------------------------------------------------------
    job_payload = {
        "case_id": case_id,
        "agent_id": agent_id,
        "collection_type": "process_inventory",
        "options": {
            "rationale": "Collect active process inventory and network socket telemetry.",
            "collection_profile": "processes"
        }
    }
    job_res = client.post("/api/jobs", json=job_payload)
    assert job_res.status_code in (200, 201), f"Job dispatch failed: {job_res.data}"
    job_data = job_res.get_json()
    job_id = job_data["id"]
    assert job_data["agent_id"] == agent_id
    assert job_data["status"] == "PENDING"

    # -------------------------------------------------------------------------
    # STEP 6: Endpoint Agent Polls for Jobs
    # -------------------------------------------------------------------------
    poll_res = client.get(f"/api/agents/{agent_id}/jobs")
    assert poll_res.status_code == 200, f"Job polling failed: {poll_res.data}"
    queued_jobs = poll_res.get_json()
    assert len(queued_jobs) >= 1
    target_job = next((j for j in queued_jobs if j["id"] == job_id), None)
    assert target_job is not None, f"Dispatched job {job_id} not found in agent poll queue"
    assert target_job["status"] == "PENDING"

    # -------------------------------------------------------------------------
    # STEP 7: Endpoint Agent Executes Safe Collection & Uploads Evidence Package
    # -------------------------------------------------------------------------
    # Simulate defensive forensic telemetry collected from Victim 2
    system_log = json.dumps({
        "collector": "WindowsProcessCollector",
        "hostname": "VICTIM-02-DESKTOP",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "active_processes": [
            {"pid": 4, "name": "System", "path": "ntoskrnl.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {"pid": 412, "name": "suspicious_beacon.exe", "path": "C:\\Users\\Victim2\\AppData\\Local\\Temp\\suspicious_beacon.exe", "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
            {"pid": 880, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"}
        ],
        "network_sockets": [
            {"protocol": "TCP", "local_addr": "192.168.1.102:49812", "remote_addr": "104.244.42.1:443", "state": "ESTABLISHED", "pid": 412}
        ]
    }, indent=2)

    raw_files = {
        "processes.json": system_log,
        "audit_note.txt": f"Evidence acquired by JOCKY Agent from {agent_id} for Case {case_id}."
    }

    # Manifest with individual artifact hashes
    manifest_obj = {
        "collector_version": "5.2.0-DFIR-PRO",
        "case_id": case_id,
        "agent_id": agent_id,
        "job_id": job_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file_hashes": {
            fname: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for fname, content in raw_files.items()
        }
    }
    raw_files["manifest.json"] = json.dumps(manifest_obj, indent=2)

    archive_bytes = _make_dummy_tar_gz(raw_files)
    calculated_archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()

    # Upload evidence via POST /api/evidence
    upload_res = client.post(
        "/api/evidence",
        data={
            "file": (io.BytesIO(archive_bytes), "victim2_process_evidence.tar.gz"),
            "case_id": case_id,
            "job_id": job_id,
            "manifest": json.dumps(manifest_obj)
        },
        content_type="multipart/form-data"
    )
    assert upload_res.status_code == 201, f"Evidence upload failed: {upload_res.data}"
    evd_record = upload_res.get_json()
    evidence_id = evd_record["id"]
    assert evd_record["sha256"] == calculated_archive_sha256

    # -------------------------------------------------------------------------
    # STEP 8: Endpoint Agent Reports Job Status = COMPLETED
    # -------------------------------------------------------------------------
    status_update_res = client.post(f"/api/jobs/{job_id}/status", json={"status": "COMPLETED"})
    assert status_update_res.status_code == 200

    job_check = client.get(f"/api/jobs/{job_id}")
    assert job_check.status_code == 200
    assert job_check.get_json()["status"] == "COMPLETED"

    # -------------------------------------------------------------------------
    # STEP 9: Cryptographic SHA-256 Verification & Tamper Detection
    # -------------------------------------------------------------------------
    # A) Clean verification: On-disk bytes match ledger
    verify_res = client.get(f"/api/evidence/{evidence_id}/verify")
    assert verify_res.status_code == 200, f"Verification call failed: {verify_res.data}"
    v_clean = verify_res.get_json()
    assert v_clean["valid"] is True
    assert v_clean["actual_sha256"] == calculated_archive_sha256
    assert v_clean["stored_sha256"] == calculated_archive_sha256

    # B) Detailed evidence lookup endpoint
    evd_detail = client.get(f"/api/evidence/{evidence_id}")
    assert evd_detail.status_code == 200
    evd_info = evd_detail.get_json()
    assert evd_info["id"] == evidence_id
    assert evd_info["case_id"] == case_id
    assert evd_info["integrity_check"]["verified"] is True
    assert "file_hashes" in evd_info["manifest"]

    # C) Tamper Test: Modify 1 byte on disk and assert tamper detection
    archive_on_disk = evd_info["archive_path"]
    assert os.path.isfile(archive_on_disk), f"Archive not found on disk at {archive_on_disk}"

    with open(archive_on_disk, "r+b") as f:
        original_byte = f.read(1)
        f.seek(0)
        # Flip bit of the first byte
        f.write(bytes([original_byte[0] ^ 0xFF]))

    verify_tampered = client.get(f"/api/evidence/{evidence_id}/verify")
    assert verify_tampered.status_code == 200
    v_tampered = verify_tampered.get_json()
    assert v_tampered["valid"] is False, "Cryptographic integrity failed to detect byte tampering!"
    assert v_tampered["actual_sha256"] != calculated_archive_sha256

    # Restore byte to clean state
    with open(archive_on_disk, "r+b") as f:
        f.seek(0)
        f.write(original_byte)

    # Re-verify clean
    verify_restored = client.get(f"/api/evidence/{evidence_id}/verify")
    assert verify_restored.get_json()["valid"] is True

    # -------------------------------------------------------------------------
    # STEP 10: Investigator Reviews Case Evidence & Timeline
    # -------------------------------------------------------------------------
    case_evd_res = client.get(f"/api/cases/{case_id}/evidence")
    assert case_evd_res.status_code == 200
    evd_list = case_evd_res.get_json().get("evidence", [])
    assert any(e["id"] == evidence_id for e in evd_list)

    # Add a forensic timeline event linked to this evidence
    conn = get_db_connection(db_path)
    conn.execute(
        "INSERT INTO timeline (id, device_id, case_id, timestamp, event_type, category, severity, description, source, entity, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            f"tl_{uuid.uuid4().hex[:8]}",
            agent_id,
            case_id,
            datetime.now(timezone.utc).isoformat(),
            "PROCESS_EXECUTION",
            "Endpoint Telemetry",
            "High",
            "Suspicious process execution detected: suspicious_beacon.exe connecting to 104.244.42.1:443",
            "VICTIM-02-WIN",
            "suspicious_beacon.exe",
            "COLLECTED"
        )
    )
    conn.commit()
    conn.close()

    timeline_res = client.get(f"/api/timeline?case_id={case_id}")
    assert timeline_res.status_code == 200
    timeline_items = timeline_res.get_json().get("items", [])
    assert any("suspicious_beacon.exe" in item.get("entity", "") for item in timeline_items)

    # -------------------------------------------------------------------------
    # STEP 11: TinyFish Threat Intelligence Enrichment
    # -------------------------------------------------------------------------
    # Validate the remote C2 indicator extracted from Victim 2
    val_res = client.post("/api/threat-intel/validate", json={
        "indicator": "104.244.42.1",
        "indicator_type": "ipv4"
    })
    assert val_res.status_code == 200
    val_data = val_res.get_json()
    assert val_data["valid"] is True
    assert val_data["indicator_type"] == "ipv4"

    # Enrich via threat-intel research table
    conn = get_db_connection(db_path)
    conn.execute(
        """INSERT INTO threat_intel_research
           (id, case_id, indicator, indicator_type, query, sources_json, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            f"ti_{uuid.uuid4().hex[:8]}",
            case_id,
            "104.244.42.1",
            "ipv4",
            "104.244.42.1 malicious C2 threat intelligence",
            json.dumps([{"url": "https://threatpost.example.com/c2-report", "title": "Known Cobalt Strike IP", "snippet": "Observed in active campaigns."}]),
            "COMPLETED",
            datetime.now(timezone.utc).isoformat()
        )
    )
    conn.commit()
    conn.close()

    ti_history_res = client.get(f"/api/cases/{case_id}/threat-intel")
    assert ti_history_res.status_code == 200
    ti_records = ti_history_res.get_json().get("research_records", [])
    assert any(r["indicator"] == "104.244.42.1" for r in ti_records)

    # -------------------------------------------------------------------------
    # STEP 12: Final Court-Admissible Forensic Report Generation
    # -------------------------------------------------------------------------
    report_res = client.get(f"/api/cases/{case_id}/report")
    assert report_res.status_code == 200, f"Report generation failed: {report_res.data}"
    rep = report_res.get_json()
    assert rep["case_id"] == case_id
    assert rep["case"]["name"] == case_payload["name"]
    # Verify evidence item with SHA-256 is present in the report
    assert any(e["id"] == evidence_id for e in rep.get("evidence", []))
    assert any(e.get("sha256") == calculated_archive_sha256 for e in rep.get("evidence", []))
    # Verify Threat Intelligence section contains our corroborated findings
    assert "threat_intelligence" in rep
    assert len(rep["threat_intelligence"]) >= 1
    assert any(t["indicator"] == "104.244.42.1" for t in rep["threat_intelligence"])
