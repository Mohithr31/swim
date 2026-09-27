"""
JOCKY Windows Forensic Platform Test Suite
Exhaustive unit and integration tests verifying Windows collection, plan validation,
agent execution, evidence SHA-256 integrity, audit hash chaining, REST APIs, and End-to-End workflow.
"""
import os
import sys
import json
import pytest
import tempfile
import threading
import time
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.windows_collector import (
    get_windows_system_info,
    get_windows_processes,
    get_windows_network,
    get_windows_users,
    get_windows_services,
    get_windows_filesystem,
    get_windows_storage,
    get_windows_software,
    get_windows_scheduled_tasks,
    get_windows_environment,
    get_windows_logs,
)
from src.parser import parse_jocky_source
from src.plan import compile_plan_from_ast, validate_forensic_plan
from server.server import app, init_db, DB_PATH, EVIDENCE_DIR
import server.server as srv
from agent.jocky_agent import JockyAgent
from client.jocky_client import JockyClient
from collector.verify import verify_manifest_and_evidence, calculate_sha256
from server.audit import verify_audit_chain


def test_windows_system():
    sys_info = get_windows_system_info()
    assert "hostname" in sys_info
    assert "operating_system" in sys_info
    assert "architecture" in sys_info
    assert isinstance(sys_info["hostname"], str)


def test_windows_processes():
    procs = get_windows_processes()
    assert isinstance(procs, list)
    assert len(procs) > 0
    first_proc = procs[0]
    assert "pid" in first_proc
    assert "name" in first_proc


def test_windows_network():
    conns = get_windows_network()
    assert isinstance(conns, list)
    if len(conns) > 0:
        assert "protocol" in conns[0]
        assert "local_address" in conns[0]


def test_windows_users():
    users = get_windows_users()
    assert isinstance(users, list)
    assert len(users) > 0
    assert "username" in users[0]


def test_windows_services():
    services = get_windows_services()
    assert isinstance(services, list)
    if len(services) > 0:
        assert "service_name" in services[0]


def test_windows_filesystem():
    fs = get_windows_filesystem("C:\\Windows" if os.name == "nt" else os.getcwd())
    assert isinstance(fs, list)
    assert len(fs) > 0
    assert "filename" in fs[0]
    assert "type" in fs[0]


def test_windows_storage():
    storage = get_windows_storage()
    assert isinstance(storage, list)
    assert len(storage) > 0
    assert "drive" in storage[0]
    assert "capacity_gb" in storage[0]


def test_windows_software():
    sw = get_windows_software()
    assert isinstance(sw, list)


def test_windows_scheduled_tasks():
    tasks = get_windows_scheduled_tasks()
    assert isinstance(tasks, list)


def test_windows_environment():
    env = get_windows_environment()
    assert isinstance(env, dict)
    assert "SECRET" not in env
    assert "PASS" not in env


def test_windows_logs():
    logs = get_windows_logs()
    assert isinstance(logs, list)
    assert len(logs) > 0
    assert "channel" in logs[0]


def test_windows_reference_telemetry_contract():
    browser = __import__("collector.windows_collector", fromlist=["get_windows_browser_history"])
    assert isinstance(browser.get_windows_browser_history(), list)
    assert isinstance(browser.get_windows_login_events(), list)
    assert isinstance(browser.get_windows_network_interfaces(), list)

    dashboard = Path(__file__).parents[1] / "server" / "dashboard.html"
    source = dashboard.read_text(encoding="utf-8")
    for field in ("display_name", "startup_type", "application_name", "install_location", "next_run", "visit_count"):
        assert field in source


def test_email_and_single_file_dashboard_contract():
    from collector.email_forensics import get_email_forensics

    artifacts = get_email_forensics()
    assert isinstance(artifacts, list)
    assert all("path" in item for item in artifacts)

    dashboard = Path(__file__).parents[1] / "server" / "dashboard.html"
    source = dashboard.read_text(encoding="utf-8")
    assert 'data-cat="email"' in source
    assert 'data-cat="removable_media"' in source
    assert "/downloads/agent/windows" in source
    assert "/downloads/agent/linux" in source
    assert "/downloads/agent/windows.exe" not in source


def test_removable_media_collector_is_metadata_only():
    from collector.removable_media import get_removable_media_forensics

    rows = get_removable_media_forensics()
    assert isinstance(rows, list)
    for row in rows:
        assert "device" in row
        assert "evidence_type" in row
        assert "activity_summary" in row
        assert "file_content" not in row


def test_email_headers_are_collected_without_body(monkeypatch, tmp_path):
    import collector.email_forensics as email_forensics

    message = tmp_path / "evidence.eml"
    message.write_text(
        "From: sender@example.test\nTo: receiver@example.test\n"
        "Subject: Test artifact\nDate: Sat, 13 Sep 2026 10:00:00 +0000\n"
        "Message-ID: <test@example.test>\n\nPrivate body\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(email_forensics, "_roots", lambda: [tmp_path])
    monkeypatch.setattr(email_forensics, "_get_webmail_browser_artifacts", lambda: [])
    rows = email_forensics.get_email_forensics()
    headers = next(row for row in rows if row.get("path") == str(message))
    assert headers["subject"] == "Test artifact"
    assert headers["body_collected"] is False
    assert "Private body" not in headers


def test_browser_history_reads_sqlite_fixture(monkeypatch, tmp_path):
    import sqlite3
    import collector.windows_collector as windows_collector

    profile = tmp_path / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    profile.mkdir(parents=True)
    history = profile / "History"
    conn = sqlite3.connect(history)
    conn.execute("CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
    conn.execute("INSERT INTO urls VALUES (?, ?, ?, ?)", ("https://example.test", "Fixture page", 3, 11644473600000000))
    conn.commit()
    conn.close()
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    rows = windows_collector.get_windows_browser_history()
    assert any(row.get("url") == "https://example.test" for row in rows)


def test_filesystem_request_completion_and_dashboard_history(test_client):
    test_client.post("/api/devices/register", json={"device_id": "remote_test", "hostname": "REMOTE-VM", "os": "Windows 11"})
    srv.FILE_REQUESTS["fs_test"] = {"request_id": "fs_test", "device_id": "remote_test", "kind": "content", "path": "C:\\Windows\\test.log", "status": "pending"}
    response = test_client.post("/api/agents/remote_test/filesystem/requests/fs_test", json={"path": "C:\\Windows\\test.log", "content": "read-only", "read_only": True})
    assert response.status_code == 200
    assert srv.FILE_REQUESTS["fs_test"]["status"] == "complete"
    source = (Path(__file__).parents[1] / "server" / "dashboard.html").read_text(encoding="utf-8")
    assert "LAST CONNECTED DEVICES" in source
    assert "RECENT ACTIVITY" in source


def test_windows_plan():
    dsl = """
    module win_triage {
        collect system
        collect processes
        collect network
        collect users
        collect services
        collect filesystem
        collect software
        collect disk_usage
        collect scheduled_tasks
        collect environment
        collect logs
    }
    """
    ast = parse_jocky_source(dsl)
    plan = compile_plan_from_ast(ast)
    assert plan["module"] == "win_triage"
    assert len(plan["operations"]) == 11
    assert validate_forensic_plan(plan) is True

    # Test tampering rejection
    tampered_plan = dict(plan)
    tampered_plan["operations"].append({"type": "malicious_op"})
    assert validate_forensic_plan(tampered_plan) is False


def test_windows_agent():
    agent = JockyAgent(server_url="http://127.0.0.1:5000", agent_id="test_agent_win")
    assert agent.agent_id == "test_agent_win"
    assert agent.hostname is not None


@pytest.fixture
def test_client():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = os.path.join(tmpdir, "win_test.db")
        evd_dir = os.path.join(tmpdir, "evidence")
        os.environ["JOCKY_DB"] = test_db
        os.environ["JOCKY_EVIDENCE_DIR"] = evd_dir
        srv.DB_PATH = test_db
        srv.EVIDENCE_DIR = evd_dir
        init_db(test_db)
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client


def test_windows_server(test_client):
    res = test_client.get("/api/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "healthy"


def test_windows_dashboard_api(test_client):
    res_dev = test_client.post("/api/devices/register", json={
        "device_id": "win_desktop_01",
        "hostname": "DESKTOP-WIN11",
        "os": "Windows 11 Pro"
    })
    assert res_dev.status_code == 200

    res_list = test_client.get("/api/devices")
    assert res_list.status_code == 200
    devices = res_list.get_json()
    assert len(devices) == 1
    assert devices[0]["hostname"] == "DESKTOP-WIN11"

    # Query telemetry endpoint
    res_telem = test_client.get("/api/devices/win_desktop_01/telemetry/system")
    assert res_telem.status_code == 200
    telem = res_telem.get_json()
    assert telem["category"] == "system"


def test_windows_evidence_and_integrity(test_client):
    # Register device, case, session, plan, job
    test_client.post("/api/devices/register", json={"device_id": "agent_win_01", "hostname": "WIN-HOST", "os": "Windows 10"})
    res_c = test_client.post("/api/cases", json={"name": "Windows Malware Case"})
    case_id = res_c.get_json()["id"]

    res_s = test_client.post("/api/sessions", json={"case_id": case_id, "name": "Initial Memory Sweep"})
    session_id = res_s.get_json()["id"]

    dsl = "module triage { collect system collect processes }"
    res_comp = test_client.post("/api/compile", json={"source": dsl})
    plan_hash = res_comp.get_json()["plan"]["plan_hash"]

    res_job = test_client.post("/api/jobs", json={"session_id": session_id, "agent_id": "agent_win_01", "plan_hash": plan_hash})
    job_id = res_job.get_json()["id"]

    import io
    res_upload = test_client.post("/api/evidence", data={
        "job_id": job_id,
        "manifest": json.dumps({"version": "1.0", "files": []}),
        "file": (io.BytesIO(b"MOCK EVIDENCE DATA FOR WINDOWS"), "archive.tar.gz")
    })
    assert res_upload.status_code == 201
    evd_data = res_upload.get_json()
    assert "sha256" in evd_data

    # Verify integrity API
    res_verify = test_client.get(f"/api/evidence/{evd_data['id']}/verify")
    assert res_verify.status_code == 200
    assert res_verify.get_json()["valid"] is True


def test_windows_audit(test_client):
    res = test_client.get("/api/audit/verify")
    assert res.status_code == 200
    assert res.get_json()["valid"] is True


def test_windows_end_to_end():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:

        db_path = os.path.join(tmpdir, "win_e2e.db")
        evidence_dir = os.path.join(tmpdir, "evidence")
        os.environ["JOCKY_DB"] = db_path
        os.environ["JOCKY_EVIDENCE_DIR"] = evidence_dir
        srv.DB_PATH = db_path
        srv.EVIDENCE_DIR = evidence_dir
        init_db(db_path)

        port = 5088
        server_thread = threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
            daemon=True
        )
        server_thread.start()
        time.sleep(1.2)

        client = JockyClient(server_url=f"http://127.0.0.1:{port}")
        assert client.health()["status"] == "healthy"

        # Agent Registration
        agent = JockyAgent(server_url=f"http://127.0.0.1:{port}", agent_id="win_e2e_agent")
        assert agent.register() is True

        # Case & Session Creation
        case = client.create_case("Windows E2E Case", "Full E2E test")
        session = client.create_session(case["id"], "Full Sweep Session")

        # Compile JOCKY DSL
        c_res = client.compile_dsl_file("examples/full_forensic.jky")
        plan_hash = c_res["plan"]["plan_hash"]

        # Submit Job
        job = client.submit_job(session["id"], "win_e2e_agent", plan_hash)
        assert job["status"] == "PENDING"

        # Agent executes job
        executed = agent.poll_and_execute_job()
        assert executed is True

        # Verify evidence
        evd_list = client.list_evidence()
        assert len(evd_list) == 1

        # Audit Chain Verification
        audit_res = client.verify_audit()
        assert audit_res["valid"] is True

        # Report Generation
        report = client.generate_report(case["id"])
        assert "report_markdown" in report


def test_windows_process_schema_includes_live_memory_fields():
    import collector.windows_collector as wc
    rows = wc.get_windows_processes() if wc.sys.platform == "win32" else []
    if rows:
        assert "memory_kb" in rows[0]
        assert "threads" in rows[0]


def test_windows_logs_schema_is_dashboard_compatible():
    import collector.windows_collector as wc
    rows = wc.get_windows_logs()
    assert isinstance(rows, list)
    if rows:
        assert "source" in rows[0]
        assert "line" in rows[0]


# ─── Mirror of test_linux_collectors.py for the Windows platform ────────────

@pytest.mark.skipif(sys.platform != "win32", reason="Windows-native collectors require win32 APIs (winreg, ctypes.windll)")
def test_windows_collector_functions_return_serializable_data():
    """Every Windows collector function must return JSON-serializable data.
    Mirrors test_linux_collector_functions_return_serializable_data from test_linux_collectors.py.
    """
    from collector.windows_collector import (
        get_windows_system_info,
        get_windows_processes,
        get_windows_network,
        get_windows_users,
        get_windows_services,
        get_windows_filesystem,
        get_windows_storage,
        get_windows_software,
        get_windows_scheduled_tasks,
        get_windows_environment,
        get_windows_logs,
        get_windows_browser_history,
        get_windows_login_events,
        get_windows_network_interfaces,
        get_windows_memory_telemetry,
    )
    funcs = [
        get_windows_system_info,
        get_windows_processes,
        get_windows_network,
        get_windows_users,
        get_windows_services,
        lambda: get_windows_filesystem("C:\\Windows"),
        get_windows_storage,
        get_windows_software,
        get_windows_scheduled_tasks,
        get_windows_environment,
        get_windows_logs,
        get_windows_browser_history,
        get_windows_login_events,
        get_windows_network_interfaces,
        get_windows_memory_telemetry,
    ]
    for fn in funcs:
        value = fn()
        # Must be JSON-serializable — no datetime objects, no non-serializable types
        json.dumps(value)


def test_every_allowlisted_operation_has_windows_agent_dispatch():
    """Every allowlisted DSL operation must have a corresponding dispatch handler in the agent.
    Mirrors test_every_allowlisted_operation_has_agent_dispatch from test_linux_collectors.py.
    """
    from agent.jocky_agent import COLLECTOR_DISPATCH
    from src.parser import ALLOWLISTED_OPERATIONS
    assert ALLOWLISTED_OPERATIONS.issubset(COLLECTOR_DISPATCH.keys()), (
        f"Missing dispatch for: {ALLOWLISTED_OPERATIONS - COLLECTOR_DISPATCH.keys()}"
    )
