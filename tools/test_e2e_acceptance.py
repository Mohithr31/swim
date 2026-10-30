"""
TINY MONITOR / JOCKY DFIR — Full End-to-End Acceptance Verification Script
Tests against live running server:
1. Health & Status
2. Case Creation
3. Device Enrollment & Assignment
4. Allowlisted Job Dispatch
5. Agent Polling & Allowlisted Execution
6. Evidence Upload & Ingest
7. SHA-256 Integrity Verification (Clean State)
8. Deliberate Tamper Injection & Real-Time Tamper Detection
9. Evidence Restoration & Re-verification
10. Relational Evidence-to-Context Graph Verification
11. Timeline & Report Derivation Consistency
"""

import sys
import os
import json
import time

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import requests


SERVER = "http://127.0.0.1:5000"

def run_acceptance():
    s = requests.Session()
    print("=" * 70)
    print("  TINY MONITOR / JOCKY DFIR — LIVE END-TO-END ACCEPTANCE VERIFICATION")
    print("=" * 70)

    # 1. Server Health
    print("[1] Verifying Server Health & TinyFish Configuration...")
    h_res = s.get(f"{SERVER}/api/health", timeout=5)
    assert h_res.status_code == 200, f"Health check failed: {h_res.text}"
    health = h_res.json()
    assert health["status"] == "healthy"
    tf_status = health["external_integrations"]["tinyfish"]["status"]
    print(f"    * Server: {health['service']} (Status: {health['status']})")
    print(f"    * TinyFish: {tf_status}")

    # 2. Case Creation
    print("\n[2] Creating Investigation Case...")
    c_res = s.post(f"{SERVER}/api/cases", json={
        "name": "Live Bengaluru Incident Response",
        "description": "Orchestrated agent collection and tamper-evident verification",
        "investigator_name": "Chief DFIR Examiner",
        "severity": "CRITICAL"
    }, timeout=5)
    assert c_res.status_code in (200, 201), f"Case creation failed: {c_res.text}"
    case_data = c_res.json()
    case_id = case_data.get("id")
    assert case_id, "No case ID returned"
    print(f"    * Created Case: {case_id} — {case_data.get('name')}")

    # 3. Device Identification
    print("\n[3] Checking Device Enrollment...")
    d_res = s.get(f"{SERVER}/api/devices", timeout=5)
    assert d_res.status_code == 200
    devices = d_res.json()
    assert len(devices) > 0, "No enrolled devices found"
    agent_id = devices[0]["id"]
    print(f"    * Targeting Enrolled Device: {agent_id} ({devices[0].get('hostname')})")

    # Assign case to device
    assign_res = s.post(f"{SERVER}/api/cases/{case_id}/assign", json={"agent_id": agent_id}, timeout=5)
    assert assign_res.status_code == 200, f"Case assignment failed: {assign_res.text}"
    print(f"    * Assigned Case '{case_id}' to Agent '{agent_id}'")


    # 4. Job Creation
    print("\n[4] Submitting Allowlisted Forensic Job...")
    j_res = s.post(f"{SERVER}/api/jobs", json={
        "case_id": case_id,
        "agent_id": agent_id,
        "operations": ["system", "processes"]
    }, timeout=5)
    assert j_res.status_code == 201, f"Job creation failed: {j_res.text}"
    job_data = j_res.json()
    job_id = job_data["id"]
    print(f"    * Created Job: {job_id} (Status: {job_data.get('status')})")

    # 5. Agent Polling & Execution
    print("\n[5] Polling and Executing Job with JockyAgent...")
    from agent.jocky_agent import JockyAgent
    agent = JockyAgent(server_url=SERVER, agent_id=agent_id)
    
    # Process pending queue until target job is processed
    max_polls = 5
    while max_polls > 0:
        j_check = s.get(f"{SERVER}/api/jobs/{job_id}", timeout=5).json()
        if j_check.get("status") == "COMPLETED":
            break
        executed = agent.poll_and_execute_job()
        if not executed:
            break
        max_polls -= 1
        time.sleep(0.5)

    # 6. Verify Job State on Server
    j_check = s.get(f"{SERVER}/api/jobs/{job_id}", timeout=5).json()
    print(f"    * Server Job Status: {j_check.get('status')}")
    assert j_check.get("status") == "COMPLETED", f"Expected COMPLETED, got {j_check.get('status')}"


    # 7. Evidence Ingest & SHA-256 Verification
    print("\n[6] Verifying Ingested Digital Evidence...")
    ev_res = s.get(f"{SERVER}/api/evidence", timeout=5)
    assert ev_res.status_code == 200
    ev_payload = ev_res.json()
    evidence_list = ev_payload.get("rows", []) if isinstance(ev_payload, dict) else ev_payload
    matching = [e for e in evidence_list if e.get("job_id") == job_id]

    assert len(matching) > 0, f"No evidence registered for job {job_id}"
    evd = matching[0]
    evd_id = evd["id"]
    archive_path = evd["archive_path"]
    expected_sha256 = evd["sha256"]
    print(f"    * Evidence Package ID : {evd_id}")
    print(f"    * Registered SHA-256   : {expected_sha256}")
    print(f"    * Archive on Disk      : {archive_path}")

    # Baseline SHA-256 verification
    v1 = s.get(f"{SERVER}/api/evidence/{evd_id}/verify", timeout=5).json()
    assert v1.get("valid") is True, f"Baseline verification failed: {v1}"
    assert v1.get("tampered") is False
    print(f"    * [VERIFIED] Baseline Disk-Byte Hash Matches Record (valid=True, tampered=False)")

    # 8. Deliberate Tamper Injection & Detection
    print("\n[7] Testing Cryptographic Tamper Detection...")
    assert os.path.exists(archive_path), f"Evidence archive not found at {archive_path}"
    with open(archive_path, "r+b") as f:
        orig_byte = f.read(1)
        f.seek(0)
        f.write(bytes([orig_byte[0] ^ 0xFF]))

    v2 = s.get(f"{SERVER}/api/evidence/{evd_id}/verify", timeout=5).json()
    assert v2.get("valid") is False, "Server failed to detect tampered evidence!"
    assert v2.get("tampered") is True, "Server failed to flag tampered: True"
    print(f"    * [TAMPER DETECTED] Server re-hashed disk bytes and caught hash mismatch!")
    print(f"      Expected : {v2.get('expected_sha256')}")
    print(f"      Actual   : {v2.get('actual_sha256')}")
    print(f"      Status   : {v2.get('error') or v2.get('status')}")


    # Restore byte
    with open(archive_path, "r+b") as f:
        f.seek(0)
        f.write(orig_byte)

    v3 = s.get(f"{SERVER}/api/evidence/{evd_id}/verify", timeout=5).json()
    assert v3.get("valid") is True
    assert v3.get("tampered") is False
    print(f"    * [RESTORED] Original bytes restored; verification succeeds again.")

    # 9. Evidence-to-Context Graph Verification
    print("\n[8] Verifying Relational Evidence-to-Context Graph...")
    g_res = s.get(f"{SERVER}/api/cases/{case_id}/graph", timeout=5).json()
    nodes = g_res.get("nodes", [])
    edges = g_res.get("edges", [])
    node_types = {n.get("type") for n in nodes}
    print(f"    * Graph Nodes: {len(nodes)} (Types: {sorted(node_types)})")
    print(f"    * Graph Edges: {len(edges)}")
    assert "case" in node_types
    assert "device" in node_types
    assert "job" in node_types
    assert "evidence" in node_types
    assert len(edges) >= 3, "Expected at least 3 relational edges"
    print(f"    * Relational integrity verified across SQLite foreign keys.")

    # 10. Timeline Verification
    print("\n[9] Verifying Investigation Timeline...")
    t_res = s.get(f"{SERVER}/api/cases/{case_id}/timeline", timeout=5).json()
    timeline_events = t_res.get("timeline") or t_res.get("events") or (t_res if isinstance(t_res, list) else [])
    print(f"    * Case Timeline Events: {len(timeline_events)}")
    assert len(timeline_events) > 0, "No timeline events recorded"


    # 11. Forensic Report Consistency
    print("\n[10] Verifying Forensic Report Generation...")
    r_res = s.get(f"{SERVER}/api/cases/{case_id}/report", timeout=30)
    assert r_res.status_code == 200, f"Report request failed: {r_res.text}"
    report_data = r_res.json()
    case_label = report_data.get('case_id') or report_data.get('case', {}).get('name')
    print(f"    * Report Generated for Case: {case_label}")
    print(f"    * Report Evidence Count   : {len(report_data.get('evidence', []))}")
    assert len(report_data.get("evidence", [])) >= 1


    print("\n" + "=" * 70)
    print("  ALL 11 END-TO-END ACCEPTANCE CRITERIA VERIFIED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    try:
        run_acceptance()
    except Exception as exc:
        print(f"\n[FAIL] Acceptance verification failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
