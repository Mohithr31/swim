import pytest
import os
import tempfile
import json
from server.server import app, DB_PATH, init_db


@pytest.fixture
def client():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = os.path.join(tmpdir, "test_server.db")
        init_db(test_db)
        app.config["TESTING"] = True
        
        # Patch server DB_PATH
        import server.server
        server.server.DB_PATH = test_db

        with app.test_client() as client:
            yield client


def test_health_check(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"


def test_device_registration(client):
    payload = {
        "device_id": "test_agent_01",
        "hostname": "test-host",
        "os": "Linux"
    }
    res = client.post("/api/devices/register", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["id"] == "test_agent_01"

    res_list = client.get("/api/devices")
    assert res_list.status_code == 200
    devices = res_list.get_json()
    assert len(devices) == 1


def test_case_session_lifecycle(client):
    # Create Case
    res_c = client.post("/api/cases", json={"name": "Test Incident Investigation"})
    assert res_c.status_code == 201
    case = res_c.get_json()
    assert "id" in case

    # Create Session
    res_s = client.post("/api/sessions", json={"case_id": case["id"], "name": "Initial Triage"})
    assert res_s.status_code == 201
    sess = res_s.get_json()
    assert sess["case_id"] == case["id"]


def test_compile_dsl_endpoint(client):
    dsl_source = """
    module triage {
        collect system
        collect processes
    }
    """
    res = client.post("/api/compile", json={"source": dsl_source})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "plan" in data
    assert data["plan"]["module"] == "triage"


def test_live_ingest_requires_case_and_agent_ids(stable_db):
    app.config["TESTING"] = True
    with app.test_client() as client:
        os.environ["JOCKY_DB"] = stable_db
        base = {"events": []}
        res = client.post("/api/live/ingest", json=base)
        assert res.status_code == 400
        assert res.get_json()["error"] == "agent_id is required"

        res = client.post("/api/live/ingest", json={"agent_id": "agent_test", "events": []})
        assert res.status_code == 400
        assert res.get_json()["error"] == "case_id is required"


def test_terminal_execute_requires_case_and_agent_ids(stable_db):
    app.config["TESTING"] = True
    with app.test_client() as client:
        os.environ["JOCKY_DB"] = stable_db
        res = client.post("/api/terminal/execute", json={"command": "help"})
        assert res.status_code == 400
        assert res.get_json()["error"] == "case_id is required"

        res = client.post("/api/terminal/execute", json={"command": "help", "case_id": "case_test"})
        assert res.status_code == 400
        assert res.get_json()["error"] == "agent_id is required"
