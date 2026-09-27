import pytest
import os
import json
from collector.physical_device_intelligence import (
    PhysicalDeviceCollector,
    ConnectionHistoryAnalyzer,
    FileTransferAnalyzer,
    FileAccessAnalyzer,
    DeviceActivityTimeline,
    get_physical_device_overview_intelligence,
    search_device_activity,
    generate_device_forensic_report
)
from server.server import app

def test_connection_history_analyzer():
    devices = [{
        "device": "SanDisk Ultra USB 3.0",
        "device_type": "USB Storage",
        "manufacturer": "SanDisk",
        "model": "Ultra USB 3.0",
        "serial": "SD-99882410-A",
        "first_connected": "2026-09-01 14:21:10",
        "last_connected": "2026-09-15 18:42:31",
        "last_disconnected": "2026-09-15 19:17:44",
        "duration": "35m 13s",
        "connection_count": 14
    }]
    sessions = ConnectionHistoryAnalyzer.analyze_connection_history(devices)
    assert len(sessions) == 1
    sess = sessions[0]
    assert sess["device"] == "SanDisk Ultra USB 3.0"
    assert sess["duration"] == "35m 13s"
    assert sess["connection_count"] == 14
    assert sess["confidence"] == "CONFIRMED"

def test_file_transfer_analyzer_direction():
    raw_transfers = [
        {"filename": "report.pdf", "target_path": "E:\\report.pdf", "direction": "SYSTEM → USB", "size_bytes": 2516582},
        {"filename": "image.jpg", "target_path": "C:\\Pictures\\image.jpg", "direction": "USB → SYSTEM", "size_bytes": 3104920}
    ]
    transfers = FileTransferAnalyzer.extract_file_transfers(raw_transfers)
    assert len(transfers) == 2
    assert transfers[0]["direction"] == "SYSTEM → USB"
    assert transfers[1]["direction"] == "USB → SYSTEM"
    assert len(transfers[0]["hash_sha256"]) == 64

def test_file_access_analyzer():
    raw_access = [
        {"filename": "notes.txt", "target_path": "E:\\notes.txt", "action": "Opened", "user": "SYSTEM\\Investigator"}
    ]
    records = FileAccessAnalyzer.extract_file_access_records(raw_access)
    assert len(records) == 1
    rec = records[0]
    assert rec["file_name"] == "notes.txt"
    assert rec["action"] == "Opened"

def test_device_activity_timeline():
    timeline = DeviceActivityTimeline.build_device_activity_timeline("SanDisk Ultra USB 3.0")
    assert len(timeline) >= 5
    events = [t["event"] for t in timeline]
    assert "USB CONNECTED" in events
    assert "USB DISCONNECTED" in events

def test_demo_physical_device_overview():
    overview = get_physical_device_overview_intelligence(demo_mode=True)
    assert overview["status"] == "DEMO DATA MODE (SIMULATED)"
    assert overview["last_connected_device"]["device"] == "SanDisk Ultra USB 3.0"
    assert overview["connections_count"] == 14
    assert overview["files_transferred_count"] == 37
    assert overview["files_accessed_count"] == 82
    assert len(overview["copied_to_device"]) > 0
    assert len(overview["copied_from_device"]) > 0

def test_search_device_activity():
    results = search_device_activity(date_str="2026-09-15", time_str="18:45", demo_mode=True)
    assert len(results) > 0
    match = results[0]
    assert "timestamp" in match
    assert "action" in match

def test_generate_device_forensic_report():
    rep = generate_device_forensic_report(demo_mode=True)
    assert rep["report_title"] == "PHYSICAL DEVICE FORENSIC ANALYSIS REPORT"
    assert "evidence_summary" in rep
    assert "connection_history" in rep

def test_flask_api_device_endpoints():
    client = app.test_client()
    res1 = client.get("/api/devices/intelligence/overview?demo=1")
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1["connections_count"] == 14

    res2 = client.get("/api/devices/intelligence/search?date=2026-09-15&demo=1")
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert "results" in data2

    res3 = client.get("/api/devices/intelligence/report?demo=1")
    assert res3.status_code == 200
    data3 = res3.get_json()
    assert "report_title" in data3
