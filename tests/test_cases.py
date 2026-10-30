"""
TINY MONITOR — Case Management Unit Tests
Tests case creation, validation, status transitions, severity updates, and notes.
"""

import pytest
from app.services.case_service import CaseService


def test_create_case_success(app):
    with app.app_context():
        case = CaseService.create_case(
            title="Suspicious C2 Beaconing Detected",
            investigator="Forensics Lead",
            severity="HIGH",
            description="Beaconing observed to external anomalous domain."
        )
        assert case["id"] is not None
        assert case["case_number"].startswith("TM-")
        assert case["title"] == "Suspicious C2 Beaconing Detected"
        assert case["severity"] == "HIGH"
        assert case["status"] == "OPEN"
        assert case["investigator"] == "Forensics Lead"


def test_create_case_empty_title_raises_error(app):
    with app.app_context():
        with pytest.raises(ValueError, match="Case title cannot be empty"):
            CaseService.create_case(title="", investigator="Lead")


def test_case_status_transition_to_closed_sets_timestamp(app):
    with app.app_context():
        case = CaseService.create_case(title="Ransomware Outbreak", investigator="Analyst A")
        assert case["closed_at"] is None

        updated = CaseService.update_case(case_id=case["id"], status="CLOSED")
        assert updated["status"] == "CLOSED"
        assert updated["closed_at"] is not None

        # Reopening clears closed_at
        reopened = CaseService.update_case(case_id=case["id"], status="INVESTIGATING")
        assert reopened["status"] == "INVESTIGATING"
        assert reopened["closed_at"] is None


def test_add_and_retrieve_investigator_notes(app):
    with app.app_context():
        case = CaseService.create_case(title="Phishing Investigation", investigator="Analyst B")
        note = CaseService.add_note(
            case_id=case["id"],
            author="Analyst B",
            note="Extracted macro dropper from malicious attachment."
        )
        assert note["id"] is not None
        assert note["case_id"] == case["id"]

        notes = CaseService.get_notes(case["id"])
        assert len(notes) == 1
        assert "macro dropper" in notes[0]["note"]


def test_dashboard_metrics(app):
    with app.app_context():
        CaseService.create_case(title="Case 1", investigator="A", severity="CRITICAL")
        CaseService.create_case(title="Case 2", investigator="B", severity="LOW")
        metrics = CaseService.get_dashboard_metrics()
        assert metrics["total_cases"] >= 2
        assert metrics["open_cases"] >= 2
