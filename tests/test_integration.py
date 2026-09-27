import pytest
import os
import tempfile
import time
import threading
from server.server import app, init_db
import server.server as srv
from src.parser import parse_jocky_source
from src.plan import compile_plan_from_ast
from agent.jocky_agent import JockyAgent
from client.jocky_client import JockyClient


def test_full_integration_flow():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_integration.db")
        evidence_dir = os.path.join(tmpdir, "evidence")
        init_db(db_path)
        
        os.environ["JOCKY_DB"] = db_path
        os.environ["JOCKY_EVIDENCE_DIR"] = evidence_dir
        srv.DB_PATH = db_path
        srv.EVIDENCE_DIR = evidence_dir

        port = 5066
        server_thread = threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
            daemon=True
        )
        server_thread.start()
        time.sleep(1.2)

        client = JockyClient(server_url=f"http://127.0.0.1:{port}")
        
        # 1. Health check
        assert client.health()["status"] == "healthy"

        # 2. Agent registration
        agent = JockyAgent(server_url=f"http://127.0.0.1:{port}", agent_id="agent_test_int")
        assert agent.register() is True

        # 3. Create Case & Session
        case = client.create_case("Integration Case", "Testing full workflow")
        session = client.create_session(case["id"], "Full Triage Session")

        # 4. Compile DSL
        c_res = client.compile_dsl_file("examples/full_forensic.jky")
        plan_hash = c_res["plan"]["plan_hash"]

        # 5. Submit job
        job = client.submit_job(session["id"], "agent_test_int", plan_hash)
        assert job["status"] == "PENDING"

        # 6. Agent polls & executes
        executed = agent.poll_and_execute_job()
        assert executed is True

        # 7. Check evidence
        evidence_list = client.list_evidence()
        assert len(evidence_list) == 1
        assert evidence_list[0]["job_id"] == job["id"]

        # 8. Verify audit
        audit_res = client.verify_audit()
        assert audit_res["valid"] is True

        # 9. Generate report
        report_res = client.generate_report(case["id"])
        assert "report_markdown" in report_res
