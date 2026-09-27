"""
Unit and Integration Tests for JOCKY Cyber Forensic Platform & Autopsy Features.
Tests Email Forensics, Removable Media USB Activity, Location Telemetry, Hex Reader,
and Autopsy Forensic Analyzer (Keyword search, Extension Mismatch, Hash IOC Lookup).
"""
import os
import json
import tempfile
import pytest
from pathlib import Path

from collector.email_forensics import get_email_forensics
from collector.removable_media import get_removable_media_forensics
from collector.location import get_location_telemetry
from collector.windows_collector import detect_extension_mismatch
import server.server as srv
from server.server import app, init_db


@pytest.fixture
def autopsy_test_client():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = os.path.join(tmpdir, "autopsy_test.db")
        evd_dir = os.path.join(tmpdir, "evidence")
        os.environ["JOCKY_DB"] = test_db
        os.environ["JOCKY_EVIDENCE_DIR"] = evd_dir
        srv.DB_PATH = test_db
        srv.EVIDENCE_DIR = evd_dir
        init_db(test_db)
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client


def test_email_forensics_collector(tmp_path):
    eml_file = tmp_path / "test_mail.eml"
    eml_content = (
        "From: alice@example.com\n"
        "To: bob@example.com\n"
        "Subject: Urgent Evidence Report\n"
        "Date: Sun, 13 Sep 2026 12:00:00 +0000\n"
        "Message-ID: <12345@example.com>\n"
        "\n"
        "This is confidential forensic evidence content."
    )
    eml_file.write_text(eml_content)
    
    results = get_email_forensics()
    assert isinstance(results, list)


def test_removable_media_collector():
    media = get_removable_media_forensics()
    assert isinstance(media, list)


def test_location_telemetry():
    loc = get_location_telemetry(force_offline=True)
    assert "city" in loc
    assert "confidence" in loc
    assert loc["confidence"] == "LOW"


def test_extension_mismatch_detector(tmp_path):
    disguised = tmp_path / "fake_image.png"
    disguised.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff")
    
    res = detect_extension_mismatch(str(disguised), ".png")
    assert res["mismatch"] is True
    assert "Executable" in res["detected_type"]


def test_autopsy_api_endpoints(autopsy_test_client):
    res_em = autopsy_test_client.get("/api/cases/case_demo/email")
    assert res_em.status_code == 200
    assert "artifacts" in res_em.get_json()

    res_rm = autopsy_test_client.get("/api/cases/case_demo/removable_media")
    assert res_rm.status_code == 200
    assert "devices" in res_rm.get_json()

    res_loc = autopsy_test_client.get("/api/cases/case_demo/location")
    assert res_loc.status_code == 200

    res_srch = autopsy_test_client.post("/api/cases/case_demo/autopsy/search", json={"query": "test"})
    assert res_srch.status_code == 200
    assert "matches" in res_srch.get_json()

    res_mis = autopsy_test_client.get("/api/cases/case_demo/autopsy/mismatches")
    assert res_mis.status_code == 200
    assert "mismatches" in res_mis.get_json()

    res_hash = autopsy_test_client.get("/api/cases/case_demo/autopsy/hash_lookup")
    assert res_hash.status_code == 200
    assert "threats" in res_hash.get_json()


def test_hex_viewer_endpoint(autopsy_test_client, tmp_path):
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"HELLO_FORENSICS_TEST_HEADER_CONTENT_12345")

    res_hex = autopsy_test_client.get(f"/api/devices/test_dev/filesystem/hex?path={str(sample_file)}")
    assert res_hex.status_code == 200
    data = res_hex.get_json()
    assert "hex_dump" in data
    assert len(data["hex_dump"]) > 0
    assert "offset" in data["hex_dump"][0]
