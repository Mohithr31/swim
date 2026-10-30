"""
TINY MONITOR — Forensic Report Compilation Tests
Tests PDF report building, structural integrity, and anti-path traversal downloads.
"""

import io
from pathlib import Path
from app.config import Config
from app.services.case_service import CaseService
from app.services.evidence_service import EvidenceService
from app.services.report_service import ReportService
from app.services.timeline_service import TimelineService


def test_pdf_report_compilation(app):
    with app.app_context():
        # Setup complete case with evidence, threat lookups, and notes
        case = CaseService.create_case(
            title="Dossier Test Case",
            investigator="Chief Forensic Examiner",
            severity="HIGH",
            description="Complete end-to-end incident dossier test."
        )

        # Attach evidence
        EvidenceService.store_evidence(
            case_id=case["id"],
            file_stream=io.BytesIO(b"LOG_ENTRY: Unauthorized login detected from external subnet"),
            original_filename="auth.log",
            acquired_by="Chief Forensic Examiner"
        )

        # Attach threat intel lookup
        TimelineService.save_threat_lookup(
            case_id=case["id"],
            indicator="198.51.100.24",
            indicator_type="ip",
            query='"198.51.100.24" malicious',
            purpose="C2 IP triage",
            status="SUCCESS",
            results_count=1,
            results=[{
                "position": 1,
                "title": "Advisory on APT Subnet",
                "site_name": "cert.europa.eu",
                "url": "https://cert.europa.eu/advisory-123",
                "snippet": "Report detailing 198.51.100.24 in malware campaign."
            }],
            error_message=None,
            investigator="Chief Forensic Examiner"
        )

        # Attach analyst note
        CaseService.add_note(
            case_id=case["id"],
            author="Chief Forensic Examiner",
            note="Confirmed external attribution correlates with European CERT advisory."
        )

        # Generate PDF report
        report_meta = ReportService.generate_case_pdf(
            case_id=case["id"],
            generated_by="Chief Forensic Examiner"
        )

        assert report_meta["filename"].endswith(".pdf")
        assert report_meta["file_size"] > 500

        pdf_path = Path(report_meta["file_path"])
        assert pdf_path.exists()
        # Verify valid PDF header bytes
        with open(pdf_path, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"


def test_download_report_path_traversal_protection(client, app):
    # Attempting to access arbitrary files via download endpoint should fail
    resp = client.get("/api/reports/download/../../app/config.py")
    assert resp.status_code in (400, 404)
