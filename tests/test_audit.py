import pytest
import tempfile
import os
from server.database import init_db
from server.audit import record_audit_event, get_audit_events, verify_audit_chain


def test_audit_chain():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_audit.db")
        init_db(db_path)

        # Record 3 events
        evt1 = record_audit_event("investigator_1", "CREATE_CASE", "case_001", {"name": "Test Case"}, db_path=db_path)
        evt2 = record_audit_event("system_agent", "REGISTER_DEVICE", "dev_001", {"os": "Linux"}, db_path=db_path)
        evt3 = record_audit_event("investigator_1", "SUBMIT_JOB", "job_001", {"plan": "system_triage"}, db_path=db_path)

        assert evt2["prev_hash"] == evt1["curr_hash"]
        assert evt3["prev_hash"] == evt2["curr_hash"]

        valid, msg, violations = verify_audit_chain(db_path=db_path)
        assert valid is True
        assert len(violations) == 0

        # Tamper with an audit entry in DB
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE audit_events SET action = 'MALICIOUS_EDIT' WHERE event_id = ?", (evt2["event_id"],))
        conn.commit()
        conn.close()

        valid_tampered, msg_tampered, violations_tampered = verify_audit_chain(db_path=db_path)
        assert valid_tampered is False
        assert len(violations_tampered) > 0
