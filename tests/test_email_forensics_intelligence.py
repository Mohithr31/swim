import pytest
import os
import json
from collector.email_intelligence import (
    EmailCollector,
    HeaderAnalyzer,
    AttachmentAnalyzer,
    CommunicationAnalyzer,
    SuspiciousEmailAnalyzer,
    get_email_overview_intelligence,
    search_who_shared_what,
    get_master_forensic_timeline
)
from server.server import app

def test_header_analyzer_real_headers():
    raw_headers = {
        "From": "alice@example.com",
        "To": "bob@example.com",
        "Subject": "Project Alpha",
        "Date": "Tue, 10 Sep 2026 18:45:22 +0000",
        "Message-ID": "<msg123@example.com>",
        "Received": "Received: from mail.example.com (spf=pass) by mx.google.com",
        "X-Originating-IP": "198.51.100.45"
    }
    analysis = HeaderAnalyzer.analyze_headers(raw_headers)
    assert analysis["spf_result"] == "PASS"
    assert analysis["observed_ip"] == "198.51.100.45"
    assert analysis["observed_ip_label"] == "IP ADDRESS OBSERVED IN EMAIL EVIDENCE"

def test_attachment_analyzer():
    email_list = [{
        "from": "alice@example.com",
        "to": "bob@example.com",
        "subject": "Project Alpha",
        "date": "2026-09-10 18:45:22",
        "attachments": [{"filename": "report.pdf", "mime": "application/pdf", "size_bytes": 2500000}]
    }]
    atts = AttachmentAnalyzer.extract_attachments_forensics(email_list)
    assert len(atts) == 1
    info = atts[0]
    assert info["file_name"] == "report.pdf"
    assert info["extension"] == ".pdf"
    assert info["mime_type"] == "application/pdf"
    assert len(info["hash_sha256"]) == 64
    assert info["extraction_status"] == "EXTRACTED_SUCCESS"

def test_suspicious_email_analyzer():
    email_list = [{
        "from": "CEO Executive <payroll@spoofed-domain.com>",
        "to": "finance@example.com",
        "subject": "Urgent wire transfer invoice.exe",
        "attachments": [{"filename": "invoice.exe", "mime": "application/octet-stream"}],
        "spf_result": "FAIL",
        "date": "2026-09-10 03:15:00"
    }]
    threats = SuspiciousEmailAnalyzer.analyze_threat_indicators(email_list)
    assert len(threats) >= 1
    indicators = [t["indicator"] for t in threats]
    assert "Executable / Archive Attachment" in indicators

def test_demo_overview_intelligence():
    overview = get_email_overview_intelligence(demo_mode=True)
    assert overview["total_emails"] == 1248
    assert overview["unique_senders"] == 87
    assert overview["unique_recipients"] == 142
    assert overview["attachments_count"] == 326
    assert overview["suspicious_count"] == 23
    assert overview["email_accounts_count"] == 14
    assert overview["date_range"] == "01/01/2026 → 15/09/2026"
    assert len(overview["emails"]) > 0

def test_who_shared_what_search():
    results = search_who_shared_what(keyword="Project", demo_mode=True)
    assert len(results) > 0
    match = results[0]
    assert "sender" in match
    assert "shared_with" in match
    assert "hash" in match
    assert "evidence_source" in match

def test_master_forensic_timeline():
    timeline = get_master_forensic_timeline(demo_mode=True)
    assert len(timeline) >= 5
    categories = {ev["category"] for ev in timeline}
    assert "EMAIL" in categories
    assert "DEVICE" in categories
    assert "FILE" in categories

def test_flask_api_email_endpoints():
    client = app.test_client()
    res1 = client.get("/api/email/intelligence/overview?demo=1")
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1["total_emails"] == 1248

    res2 = client.get("/api/email/intelligence/who_shared_what?keyword=Project&demo=1")
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert "results" in data2

    res3 = client.get("/api/email/intelligence/timeline?demo=1")
    assert res3.status_code == 200
    data3 = res3.get_json()
    assert "timeline" in data3
