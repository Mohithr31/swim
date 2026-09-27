"""
test_dfir_b1_b12.py
===================
Comprehensive End-to-End Validation Suite for JOCKY DFIR B1-B12.

Tests:
1. Forensic Collector Modules (B1-B10):
   - Browser Forensics (B1)
   - Application Forensics (B2)
   - Messaging Forensics (B3)
   - Email Forensics (B4)
   - Web & Cloud Activity (B5)
   - Device & USB Forensics (B6)
   - System & OS Forensics (B7)
   - Filesystem Forensics (B8)
   - Live Incident Monitoring (B9)
   - Forensic Packaging & Integrity (B10)
2. Database Schema & Universal Query Engine (B11):
   - 20 normalized tables and indexes present
   - Universal query with pagination, sorting, search, and filtering
   - Case overview statistics calculation
3. REST API Endpoints (B1-B12):
   - Authentication & session cookie validation
   - All B1-B12 forensic endpoints
   - Live monitoring controls
   - Hash verification endpoint
   - JSON & HTML reporting endpoints
4. Reporting Engine (B12):
   - Multi-format report generation (JSON, HTML)
   - Complete forensic case summary & integrity verification
"""

import os
import shutil
import json
import sqlite3
import pytest
from server.server import app, DASHBOARD_USERNAME, DASHBOARD_PASSWORD, DASHBOARD_OTP
import server.server as srv
from server.database import get_db_connection, query_evidence_records, get_dfir_overview_stats
from server.reports import generate_json_report, generate_html_report, ReportGenerator

# Collector Classes
from collector.browser_forensics import BrowserForensicsCollector
from collector.application_forensics import ApplicationForensicsCollector
from collector.messaging_forensics import MessagingForensicsCollector
from collector.email_collector import EmailForensicsCollector
from collector.web_activity_mapper import WebActivityMapper
from collector.device_forensics import DeviceForensicsCollector
from collector.system_collector import SystemForensicsCollector
from collector.filesystem_forensics import FilesystemForensicsCollector
from collector.live_engine import LiveMonitoringEngine
from collector.packaging import EvidencePackager

VALID_STATUSES = {
    "COLLECTED", "NOT_PRESENT", "NOT_ACCESSIBLE", 
    "PERMISSION_REQUIRED", "NOT_SUPPORTED", 
    "NO_EVIDENCE_FOUND", "COLLECTION_ERROR", "SUCCESS", "ALREADY_RUNNING", "VERIFIED"
}


@pytest.fixture(autouse=True)
def setup_dfir_test_db():
    """Copy authentic forensic database into the isolated test runner DB."""
    real_db = os.path.abspath("jocky_forensics.db")
    if os.path.isfile(real_db) and hasattr(srv, "DB_PATH") and srv.DB_PATH and srv.DB_PATH != real_db:
        shutil.copy2(real_db, srv.DB_PATH)


# ============================================================================
# 1. Forensic Collector Tests (B1 - B10)
# ============================================================================

class TestForensicCollectors:
    """Test all collector modules execute cleanly and return honest DFIR data."""

    def test_b1_browser_collector(self):
        collector = BrowserForensicsCollector(device_id="DEV-TEST", case_id="CASE-TEST")
        res = collector.collect_all_browser_evidence()
        assert isinstance(res, dict)
        assert "status" in res
        assert res["status"] in VALID_STATUSES
        assert "history" in res
        assert "downloads" in res
        assert "bookmarks" in res
        assert isinstance(res["history"], list)
        assert isinstance(res["downloads"], list)
        assert isinstance(res["bookmarks"], list)

    def test_b2_application_collector(self):
        collector = ApplicationForensicsCollector(device_id="DEV-TEST", case_id="CASE-TEST")
        res = collector.collect_all_application_evidence()
        assert isinstance(res, dict)
        assert "status" in res
        assert res["status"] in VALID_STATUSES
        assert "installed_applications" in res
        assert "running_processes" in res
        assert isinstance(res["installed_applications"], list)
        assert isinstance(res["running_processes"], list)

    def test_b3_messaging_collector(self):
        collector = MessagingForensicsCollector(device_id="DEV-TEST", case_id="CASE-TEST")
        res = collector.collect_all_messaging_evidence()
        assert isinstance(res, dict)
        assert "status" in res
        assert res["status"] in VALID_STATUSES
        assert "messages" in res
        assert isinstance(res["messages"], list)

    def test_b4_email_collector(self):
        collector = EmailForensicsCollector(device_id="DEV-TEST", case_id="CASE-TEST")
        res = collector.collect_all_email_evidence()
        assert isinstance(res, dict)
        assert "status" in res
        assert res["status"] in VALID_STATUSES
        assert "messages" in res
        assert isinstance(res["messages"], list)

    def test_b5_web_social_collector(self):
        mapper = WebActivityMapper(device_id="DEV-TEST", case_id="CASE-TEST")
        sample_history = [
            {
                "url": "https://github.com/login",
                "domain": "github.com",
                "timestamp": "2026-09-24T12:00:00Z",
                "browser": "Edge",
                "profile": "Default"
            }
        ]
        res = mapper.map_from_history(sample_history)
        assert isinstance(res, dict)
        assert "status" in res
        assert res["status"] in VALID_STATUSES
        assert "items" in res
        assert isinstance(res["items"], list)
        assert len(res["items"]) >= 1
        assert res["items"][0]["platform"] == "GitHub"

    def test_b6_device_collector(self):
        collector = DeviceForensicsCollector(device_id="DEV-TEST", case_id="CASE-TEST")
        res = collector.collect_all_device_evidence()
        assert isinstance(res, dict)
        assert "status" in res
        assert res["status"] in VALID_STATUSES
        assert "unified_records" in res
        assert isinstance(res["unified_records"], list)

    def test_b7_system_collector(self):
        collector = SystemForensicsCollector(device_id="DEV-TEST", case_id="CASE-TEST")
        res = collector.collect_system_info()
        assert isinstance(res, dict)
        assert "status" in res
        assert res["status"] in VALID_STATUSES
        assert "hostname" in res
        assert "operating_system" in res

    def test_b8_filesystem_collector(self):
        collector = FilesystemForensicsCollector(device_id="DEV-TEST", case_id="CASE-TEST", max_files_per_category=5)
        res = collector.collect_all_filesystem_evidence()
        assert isinstance(res, dict)
        assert "status" in res
        assert res["status"] in VALID_STATUSES
        assert "files" in res
        assert isinstance(res["files"], list)

    def test_b9_live_monitoring(self):
        engine = LiveMonitoringEngine(device_id="DEV-TEST", case_id="CASE-TEST")
        
        # Test start
        start_res = engine.start_monitoring()
        assert start_res["status"] in ("COLLECTED", "ALREADY_RUNNING")

        # Test status
        status = engine.get_status()
        assert "is_monitoring" in status
        assert status["is_monitoring"] is True

        # Test snapshot
        snap = engine.trigger_snapshot_now()
        assert snap["status"] == "COLLECTED"
        assert "events_captured" in snap

        # Test stop
        stop_res = engine.stop_monitoring()
        assert stop_res["status"] == "COLLECTED"
        assert engine.is_monitoring is False

    def test_b10_packaging(self, tmp_path):
        packager = EvidencePackager(output_dir=str(tmp_path / "out"), spool_dir=str(tmp_path / "spool"))
        manifest = packager.create_evidence_package(
            case_id="TEST-CASE",
            device_id="TEST-DEV",
            db_path=srv.DB_PATH
        )
        assert manifest["case_id"] == "TEST-CASE"
        assert "package_hash" in manifest
        assert "package_zip_path" in manifest
        assert os.path.isfile(manifest["package_zip_path"])
        assert manifest["package_zip_size"] > 0


# ============================================================================
# 2. Database Schema & Query Engine Tests (B11)
# ============================================================================

class TestDatabaseAndQueryEngine:
    """Verify SQLite database schema and universal query engine."""

    def test_database_tables_exist(self):
        conn = get_db_connection(srv.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        expected_tables = {
            "artifacts", "browser_history", "browser_downloads", "browser_bookmarks",
            "applications", "processes", "messages", "email_messages", "email_attachments",
            "web_activity", "devices_artifacts", "filesystem", "network_events",
            "timeline", "findings", "evidence_files", "collection_runs", "hashes"
        }
        for table in expected_tables:
            assert table in tables, f"Missing expected table: {table}"

    def test_query_evidence_records(self):
        conn = get_db_connection(srv.DB_PATH)
        res = query_evidence_records(
            conn=conn,
            table="browser_history",
            case_id="CASE-001",
            page=1,
            limit=10,
            sort_by="id",
            order="asc"
        )
        conn.close()
        assert "total" in res
        assert "items" in res
        assert "limit" in res
        assert "page" in res
        assert res["limit"] == 10
        assert isinstance(res["items"], list)
        assert res["status"] in ("COLLECTED", "NO_EVIDENCE_FOUND")

    def test_case_overview_stats(self):
        conn = get_db_connection(srv.DB_PATH)
        stats = get_dfir_overview_stats(conn, case_id="CASE-001")
        conn.close()
        assert isinstance(stats, dict)
        assert stats["status"] in ("COLLECTED", "NO_EVIDENCE_FOUND")
        assert "counts" in stats


# ============================================================================
# 3. REST API Tests (B1 - B12)
# ============================================================================

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        # Authenticate session
        client.post("/login", data={
            "username": DASHBOARD_USERNAME,
            "password": DASHBOARD_PASSWORD,
            "otp": DASHBOARD_OTP
        }, follow_redirects=True)
        yield client

class TestRestApiEndpoints:
    """Test all DFIR REST API endpoints return HTTP 200 and expected schemas."""

    def test_case_overview(self, client):
        res = client.get("/api/case/overview?case_id=CASE-001")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] in ("SUCCESS", "COLLECTED")
        assert data["case_id"] == "CASE-001"
        assert "counts" in data

    def test_system_endpoint(self, client):
        res = client.get("/api/system?case_id=CASE-001")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] in ("SUCCESS", "COLLECTED")
        assert "system" in data

    def test_browser_endpoints(self, client):
        # History
        res = client.get("/api/browser/history?case_id=CASE-001&limit=5")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")
        assert "items" in data
        assert len(data["items"]) <= 5

        # Downloads
        res = client.get("/api/browser/downloads?case_id=CASE-001")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

        # Bookmarks
        res = client.get("/api/browser/bookmarks?case_id=CASE-001")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

    def test_applications_and_processes(self, client):
        # Applications
        res = client.get("/api/applications?case_id=CASE-001&limit=5")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

        # Processes
        res = client.get("/api/processes?case_id=CASE-001&limit=5")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

    def test_messaging_and_email(self, client):
        # Messaging
        res = client.get("/api/messaging?case_id=CASE-001")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

        # Email
        res = client.get("/api/email?case_id=CASE-001")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

    def test_web_activity(self, client):
        res = client.get("/api/web-activity?case_id=CASE-001&limit=5")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

    def test_devices_endpoints(self, client):
        # Artifacts view
        res = client.get("/api/devices/artifacts?case_id=CASE-001")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

        # Enrolled view
        res = client.get("/api/devices/enrolled")
        assert res.status_code == 200
        assert isinstance(res.get_json(), list)

    def test_filesystem_endpoint(self, client):
        res = client.get("/api/filesystem?case_id=CASE-001&limit=5")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

    def test_network_endpoint(self, client):
        res = client.get("/api/network?case_id=CASE-001&limit=5")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

    def test_live_monitoring_endpoints(self, client):
        # Status
        res = client.get("/api/live")
        assert res.status_code == 200
        data = res.get_json()
        assert "is_monitoring" in data

        # Snapshot
        res = client.post("/api/live/snapshot")
        assert res.status_code == 200
        assert res.get_json()["status"] == "COLLECTED"

    def test_timeline_and_findings(self, client):
        # Timeline
        res = client.get("/api/timeline?case_id=CASE-001&limit=10")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

        # Findings
        res = client.get("/api/findings?case_id=CASE-001")
        assert res.status_code == 200
        assert res.get_json()["status"] in ("SUCCESS", "COLLECTED", "NO_EVIDENCE_FOUND")

    def test_hash_verification_endpoint(self, client):
        res = client.post("/api/hashes/verify", json={
            "sha256": "5e08281cfdf7b1fa1f1d1f05e3f8983944265463768c7e974e44e27f42ef44df"
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] in ("VERIFIED", "NOT_PRESENT")
        assert "matched" in data

    def test_reporting_endpoints(self, client):
        # JSON Report
        res_json = client.get("/api/reports/json?case_id=CASE-001")
        assert res_json.status_code == 200
        data = res_json.get_json()
        assert "case_id" in data
        assert data["case_id"] == "CASE-001"
        assert "report_format" in data

        # HTML Report
        res_html = client.get("/api/reports/html?case_id=CASE-001")
        assert res_html.status_code == 200
        assert "text/html" in res_html.content_type
        assert b"JOCKY Forensic Report" in res_html.data


# ============================================================================
# 4. Multi-format Reporting Engine Tests (B12)
# ============================================================================

class TestReportingEngine:
    """Validate JSON and HTML report generators directly."""

    def test_generate_json_report(self):
        rep = generate_json_report("CASE-001")
        assert isinstance(rep, dict)
        assert rep["case_id"] == "CASE-001"
        assert "report_format" in rep
        assert "artifact_statistics" in rep

    def test_generate_html_report(self):
        html = generate_html_report("CASE-001")
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html
        assert "CASE-001" in html
        assert "JOCKY Forensic Report" in html
        assert "@media print" in html
