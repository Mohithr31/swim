"""
Unit & Integration Tests for JOCKY Master Rebuild
Tests Terminal Engine, Deleted File Recovery Workflow, Memory Forensics, REST Endpoints, and Chain of Custody.
"""
import os
import json
import tempfile
import pytest
from datetime import datetime, timezone

from collector.recovery import DeletedFileRecoveryEngine, scan_deleted_files, recover_deleted_file
from collector.memory import get_live_memory_statistics, analyze_memory_dump_image
from server.terminal import JockyTerminalEngine
from server.database import init_db
from server.models import RecoveryModel, MemoryModel
import server.server as srv
from server.server import app


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    init_db(db_path)
    old_env = os.environ.get("JOCKY_DB")
    old_srv_db = srv.DB_PATH
    os.environ["JOCKY_DB"] = db_path
    srv.DB_PATH = db_path
    yield db_path
    if old_env is not None:
        os.environ["JOCKY_DB"] = old_env
    else:
        os.environ.pop("JOCKY_DB", None)
    srv.DB_PATH = old_srv_db
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass


def test_terminal_engine_commands():
    # Test help
    res_help = JockyTerminalEngine.execute_command("help", case_id="case_test", agent_id="agent_test")
    assert res_help["status"] == "SUCCESS"
    assert "JOCKY Forensic Terminal Engine" in res_help["output"]

    # Test device command
    res_dev = JockyTerminalEngine.execute_command("device", case_id="case_test", agent_id="agent_test")
    assert res_dev["status"] == "SUCCESS"
    assert "operating_system" in res_dev["output"]

    # Test processes command
    res_ps = JockyTerminalEngine.execute_command("processes", case_id="case_test", agent_id="agent_test")
    assert res_ps["status"] == "SUCCESS"
    assert isinstance(res_ps["output"], list)

    # Test recover command
    res_rec = JockyTerminalEngine.execute_command("recover C:\\Windows\\System32\\notepad.exe", case_id="case_test", agent_id="agent_test")
    assert res_rec["status"] == "SUCCESS"
    assert res_rec["evidence_id"] is not None


def test_deleted_file_recovery_workflow():
    candidates = scan_deleted_files("C:\\")
    assert isinstance(candidates, list)
    assert len(candidates) >= 1

    cand = candidates[0]
    with tempfile.TemporaryDirectory() as tmp_out:
        res = recover_deleted_file(cand["candidate_id"], cand["original_path"], output_dir=tmp_out)
        assert res["status"] == "SUCCESSFULLY RECOVERED TO SEPARATE EVIDENCE STORE"
        assert res["evidence_id"].startswith("EVID-REC-")
        assert res["sha256"] != "UNKNOWN"
        assert os.path.exists(res["destination_path"])


def test_memory_statistics():
    mem = get_live_memory_statistics()
    assert mem["assessment_type"] == "LIVE_MEMORY_STATISTICS"
    assert mem["total_ram_gb"] > 0
    assert mem["used_ram_gb"] >= 0

    dump_res = analyze_memory_dump_image("non_existent_dump.dmp")
    assert dump_res["status"] == "NOT_AVAILABLE"


def test_master_rebuild_api_endpoints(temp_db):
    app.config["TESTING"] = True
    with app.test_client() as client:
        # Terminal execute API
        res_term = client.post("/api/terminal/execute", json={"command": "device", "case_id": "case_test_rebuild"})
        assert res_term.status_code == 200
        assert res_term.get_json()["status"] == "SUCCESS"

        # Recovery scan API
        res_scan = client.post("/api/cases/case_test_rebuild/recovery/scan", json={"volume": "C:\\"})
        assert res_scan.status_code == 200
        assert "candidates" in res_scan.get_json()

        # Memory API
        res_mem = client.get("/api/cases/case_test_rebuild/memory")
        assert res_mem.status_code == 200
        assert "total_ram_gb" in res_mem.get_json()["memory"]

        # Device API
        res_dev = client.get("/api/cases/case_test_rebuild/device")
        assert res_dev.status_code == 200
        assert "device" in res_dev.get_json()

        # Filesystem API
        res_files = client.get("/api/cases/case_test_rebuild/files?path=C:\\Windows")
        assert res_files.status_code == 200
        assert "files" in res_files.get_json()
