#!/usr/bin/env python3
"""
JOCKY Forensic Platform — Deterministic Demo Scenario Seeder
============================================================
Seeds a realistic, completely safe synthetic incident response case for
the hackathon demonstration.

Scenario:
  Case ID: CASE-2026-TINYFISH
  Title: Incident Triage — Outbound C2 Beaconing & Lateral Movement
  Investigator: Det. Alex Vance (Cyber Incident Response Team)
  Authorization: W-2026-PRESIDENCY-HACKATHON
"""
from __future__ import annotations

import os
import sys
import json
import uuid
from datetime import datetime, timezone, timedelta

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from server.database import get_db_connection, init_db, DEFAULT_DB_PATH
from server.models import CaseModel, DeviceModel


def seed_demo(db_path: str = None) -> str:
    db = db_path or os.environ.get("JOCKY_DB", DEFAULT_DB_PATH)
    init_db(db)
    conn = get_db_connection(db)
    cur = conn.cursor()

    case_id = "CASE-2026-TINYFISH"
    now = datetime.now(timezone.utc)
    t0 = (now - timedelta(minutes=45)).isoformat()
    t1 = (now - timedelta(minutes=30)).isoformat()
    t2 = (now - timedelta(minutes=15)).isoformat()
    t3 = now.isoformat()

    # 1. Device
    device_id = "WS-ENG-042"
    cur.execute("""
        INSERT OR REPLACE INTO devices (id, hostname, os, ip_address, status, last_seen, active_case_id)
        VALUES (?, 'ENG-WORKSTATION-42', 'Windows 11 Pro 23H2', '10.0.4.15', 'ACTIVE', ?, ?)
    """, (device_id, t3, case_id))

    # 2. Case
    cur.execute("""
        INSERT OR REPLACE INTO cases (id, name, description, created_at, status, investigator_name, investigator_org, subject_name, authorization_ref, evidence_source)
        VALUES (?, 'Incident Triage — Outbound C2 Beaconing', 'Synthetic investigation into suspicious outbound beaconing and untrusted payload staging.', ?, 'OPEN', 'Det. Alex Vance', 'Presidency University Cyber Lab', 'Host WS-ENG-042', 'W-2026-PRESIDENCY-HACKATHON', 'Live Endpoint Triage Agent')
    """, (case_id, t0))

    # 3. Network Events
    cur.execute("""
        INSERT OR REPLACE INTO network_events (id, device_id, case_id, event_type, protocol, local_address, local_port, remote_address, remote_port, state, pid, process_name, interface_name, details, timestamp, source, status)
        VALUES
        ('net_001', ?, ?, 'SOCKET_CONNECT', 'TCP', '10.0.4.15', '52341', '198.51.100.23', '443', 'ESTABLISHED', 4892, 'powershell.exe', 'Ethernet0', 'Outbound beacon to suspected external C2 gateway', ?, 'Socket Monitor', 'NORMALIZED'),
        ('net_002', ?, ?, 'SOCKET_CONNECT', 'TCP', '10.0.4.15', '52344', '93.184.216.34', '80', 'TIME_WAIT', 4892, 'curl.exe', 'Ethernet0', 'HTTP staging request for secondary script', ?, 'Socket Monitor', 'NORMALIZED')
    """, (device_id, case_id, t1, device_id, case_id, t2))

    # 4. Browser History
    cur.execute("""
        INSERT OR REPLACE INTO browser_history (id, device_id, case_id, browser, profile, url, title, visit_count, typed_count, timestamp, source, status, sha256, domain)
        VALUES
        ('bhist_001', ?, ?, 'Google Chrome', 'Default', 'https://www.cisa.gov/news-events/cybersecurity-advisories', 'Cybersecurity Alerts & Advisories | CISA', 3, 1, ?, 'Chrome History SQLite', 'NORMALIZED', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'cisa.gov'),
        ('bhist_002', ?, ?, 'Google Chrome', 'Default', 'https://github.com/tinyfish-io', 'TinyFish Infrastructure | GitHub', 1, 0, ?, 'Chrome History SQLite', 'NORMALIZED', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'github.com')
    """, (device_id, case_id, t1, device_id, case_id, t2))

    # 5. Hashes (EICAR standard benign test hash)
    eicar_md5 = "44d88612fea8a8f36de82e1278abb02f"
    eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    cur.execute("""
        INSERT OR REPLACE INTO hashes (id, device_id, case_id, item_type, item_id, path, md5, sha1, sha256, verified, timestamp, status)
        VALUES
        ('hash_001', ?, ?, 'FILE', 'f_eicar_01', 'C:\\Users\\Public\\Downloads\\test_payload.tmp', ?, '3395856ce81f2b7382dee72602f798b642f14140', ?, 1, ?, 'VERIFIED')
    """, (device_id, case_id, eicar_md5, eicar_sha256, t2))

    # 6. Timeline Events
    cur.execute("""
        INSERT OR REPLACE INTO timeline (id, device_id, case_id, timestamp, severity, category, event_type, source, description, process, network_endpoint, raw_reference, status)
        VALUES
        ('time_001', ?, ?, ?, 'HIGH', 'PROCESS', 'PROCESS_CREATE', 'Endpoint Agent', 'powershell.exe spawned with encoded command arguments', 'powershell.exe (PID 4892)', NULL, NULL, 'NORMALIZED'),
        ('time_002', ?, ?, ?, 'CRITICAL', 'NETWORK', 'NETWORK_CONNECT', 'Socket Monitor', 'Established connection to external remote address 198.51.100.23:443', 'powershell.exe (PID 4892)', '198.51.100.23:443', NULL, 'NORMALIZED'),
        ('time_003', ?, ?, ?, 'MEDIUM', 'FILE', 'FILE_WRITE', 'Filesystem Monitor', 'Created suspicious temporary file test_payload.tmp with MD5 44d88612fea8a8f36de82e1278abb02f', 'powershell.exe', NULL, 'C:\\Users\\Public\\Downloads\\test_payload.tmp', 'NORMALIZED')
    """, (device_id, case_id, t1, device_id, case_id, t2, device_id, case_id, t3))

    conn.commit()
    conn.close()
    print(f"[DEMO-SEED] Case '{case_id}' successfully seeded into '{db}'.")
    print(f"  - Target Case: {case_id}")
    print(f"  - Hostname: ENG-WORKSTATION-42 ({device_id})")
    print(f"  - Safe Indicators available for live TinyFish research:")
    print(f"    * Safe Test Hash: {eicar_md5} (EICAR test signature)")
    print(f"    * Public IP: 8.8.8.8 or 198.51.100.23")
    print(f"    * Domain: cisa.gov or evil-c2.com")
    return case_id


if __name__ == "__main__":
    seed_demo()
