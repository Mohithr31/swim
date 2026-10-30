"""
TINY MONITOR — Digital Evidence & Integrity Baseline Unit Tests
Tests streaming SHA-256 hashing, path traversal defenses, and cryptographic mismatch detection.
"""

import io
import hashlib
from pathlib import Path
import pytest

from app.config import Config
from app.services.case_service import CaseService
from app.services.evidence_service import EvidenceService


def test_stream_sha256_calculation():
    test_bytes = b"Digital Forensics Bitstream Integrity Verification Test 2026"
    expected_hash = hashlib.sha256(test_bytes).hexdigest()

    stream = io.BytesIO(test_bytes)
    calculated_hash, size = EvidenceService.calculate_stream_sha256(stream)

    assert calculated_hash == expected_hash
    assert size == len(test_bytes)
    assert stream.tell() == 0  # Verify stream was rewound


def test_evidence_storage_and_integrity_verification(app):
    with app.app_context():
        case = CaseService.create_case(title="Memory Extraction Case", investigator="Forensics Specialist")
        evidence_content = b"SUSPECT_PROCESS_MEMORY_DUMP_0x00400000"
        expected_hash = hashlib.sha256(evidence_content).hexdigest()

        stream = io.BytesIO(evidence_content)
        ev = EvidenceService.store_evidence(
            case_id=case["id"],
            file_stream=stream,
            original_filename="memdump.raw",
            acquired_by="Forensics Specialist",
            description="Process memory slice containing beacon",
            mime_type="application/octet-stream"
        )

        assert ev["id"] is not None
        assert ev["sha256_hash"] == expected_hash
        assert ev["file_size"] == len(evidence_content)
        assert ev["integrity_status"] == "VERIFIED_MATCH"

        # Verify on disk
        stored_full_path = Config.EVIDENCE_DIR / Path(ev["stored_path"])
        assert stored_full_path.exists()
        assert stored_full_path.read_bytes() == evidence_content

        # On-demand verification of unchanged file
        check = EvidenceService.verify_integrity(ev["id"], verified_by="Auditor")
        assert check["integrity_status"] == "VERIFIED_MATCH"
        assert check["sha256_hash"] == expected_hash


def test_evidence_integrity_mismatch_detected(app):
    with app.app_context():
        case = CaseService.create_case(title="Tampering Detection Case", investigator="Forensics Specialist")
        original_bytes = b"Original Authentic Incident Log Stream"
        stream = io.BytesIO(original_bytes)

        ev = EvidenceService.store_evidence(
            case_id=case["id"],
            file_stream=stream,
            original_filename="syslog.audit",
            acquired_by="Forensics Specialist"
        )
        assert ev["integrity_status"] == "VERIFIED_MATCH"

        # Simulate unauthorized file tampering on disk!
        stored_path = Config.EVIDENCE_DIR / Path(ev["stored_path"])
        stored_path.write_bytes(b"Tampered Corrupted Attacker Bytes")

        # Verify integrity on demand
        check = EvidenceService.verify_integrity(ev["id"], verified_by="Auditor")
        assert check["integrity_status"] == "FAILED_MISMATCH"
        assert "FAILED" in check["verification_notes"]


def test_evidence_file_missing_detected(app):
    with app.app_context():
        case = CaseService.create_case(title="Missing Evidence Case", investigator="Forensics Specialist")
        stream = io.BytesIO(b"Ephemeral Bytes")
        ev = EvidenceService.store_evidence(
            case_id=case["id"],
            file_stream=stream,
            original_filename="ephemeral.tmp",
            acquired_by="Forensics Specialist"
        )

        stored_path = Config.EVIDENCE_DIR / Path(ev["stored_path"])
        stored_path.unlink()  # Delete file from storage

        check = EvidenceService.verify_integrity(ev["id"])
        assert check["integrity_status"] == "FILE_MISSING"


def test_sanitize_filename_prevents_directory_traversal():
    unsafe_name = "../../../etc/passwd"
    clean = EvidenceService.sanitize_filename(unsafe_name)
    assert ".." not in clean
    assert "/" not in clean
    assert "\\" not in clean
