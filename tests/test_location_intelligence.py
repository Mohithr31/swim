import pytest
import os
import json
from collector.location_intelligence import (
    LocationCollector,
    GPSArtifactParser,
    WifiLocationAnalyzer,
    NetworkLocationAnalyzer,
    EXIFLocationAnalyzer,
    LocationTimelineAnalyzer,
    LocationConfidenceEngine,
    LocationEvidence,
    get_location_overview_intelligence,
    search_location_by_time,
    search_location_date_range,
    generate_location_forensic_report
)
from server.server import app


def test_location_collector_initialization_and_discovery():
    artifacts = LocationCollector.collect_raw_location_artifacts()
    assert isinstance(artifacts, list)
    # Each artifact should be a valid dict or empty if no real evidence
    for a in artifacts:
        assert "evidence_type" in a
        assert "confidence" in a
        assert "source" in a


def test_location_evidence_model():
    ev = LocationEvidence(
        id="LOC-TEST-001",
        evidence_type="Approximate IP Geolocation",
        latitude=12.9716,
        longitude=77.5946,
        accuracy=50000.0,
        source="Public IP Geolocation",
        confidence="LOW"
    )
    d = ev.to_dict()
    assert d["id"] == "LOC-TEST-001"
    assert d["evidence_label"] == "Approximate IP Geolocation"
    assert d["latitude"] == 12.9716
    assert d["confidence"] == "LOW"


def test_location_confidence_engine():
    assert LocationConfidenceEngine.evaluate_confidence("GPS Artifact") == "HIGH"
    assert LocationConfidenceEngine.evaluate_confidence("EXIF GPS") == "HIGH"
    assert LocationConfidenceEngine.evaluate_confidence("WI-FI LOCATION EVIDENCE") == "MEDIUM"
    assert LocationConfidenceEngine.evaluate_confidence("Approximate IP Geolocation") == "LOW"


def test_exif_gps_binary_parser():
    # Empty/invalid bytes should return None safely
    assert GPSArtifactParser.extract_exif_gps_from_bytes(b"") is None
    assert GPSArtifactParser.extract_exif_gps_from_bytes(b"invalid_jpeg_data_stream") is None


def test_demo_location_overview():
    overview = get_location_overview_intelligence(demo_mode=True)
    assert overview["status"] == "DEMO DATA MODE (SIMULATED)"
    assert overview["known_locations"] == 24
    assert overview["location_events_count"] == 186
    assert overview["gps_artifacts_count"] == 42
    assert overview["network_location_events_count"] == 73
    assert overview["devices_with_location_count"] == 6
    assert overview["date_range"] == "01/01/2026 → 15/09/2026"
    assert len(overview["location_events"]) > 0


def test_search_location_by_time_exact_and_window():
    res = search_location_by_time(date_str="2026-09-15", time_str="18:45:00", range_mins=5, device_filter="Samsung Galaxy S24", demo_mode=True)
    assert res["requested_time"] == "2026-09-15 18:45:00"
    best = res["best_available_location"]
    assert best is not None
    assert best["device"] == "Samsung Galaxy S24"
    assert "Bengaluru" in best["location_name"]
    assert best["confidence"] == "HIGH"
    assert best["diff_seconds"] == 8
    assert len(res["supporting_events"]) >= 3


def test_empty_search_location_window():
    res = search_location_by_time(date_str="1999-01-01", time_str="00:00:00", range_mins=5, device_filter="Samsung Galaxy S24", demo_mode=True)
    assert res["best_available_location"] is None
    assert len(res["supporting_events"]) == 0


def test_search_location_date_range():
    results = search_location_date_range(start_time="2026-09-15 18:00:00", end_time="2026-09-15 19:30:00", demo_mode=True)
    assert len(results) > 0
    assert results[0]["timestamp"] >= "2026-09-15 18:00:00"


def test_generate_location_report():
    rep = generate_location_forensic_report(demo_mode=True)
    assert rep["report_title"] == "LOCATION INTELLIGENCE FORENSIC REPORT"
    assert "executive_summary" in rep
    assert "sample_time_query" in rep


def test_flask_location_api_endpoints():
    client = app.test_client()
    
    # 1. Overview & Statistics
    res1 = client.get("/api/location/intelligence/overview?demo=1")
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1["known_locations"] == 24

    res1_alias = client.get("/api/location?demo=1")
    assert res1_alias.status_code == 200
    assert res1_alias.get_json()["known_locations"] == 24

    # 2. Timeline
    res_tl = client.get("/api/location/timeline?demo=1")
    assert res_tl.status_code == 200
    assert "timeline" in res_tl.get_json()

    # 3. Sources
    res_src = client.get("/api/location/sources?demo=1")
    assert res_src.status_code == 200
    assert "sources" in res_src.get_json()

    # 4. Search
    res2 = client.get("/api/location/intelligence/search?date=2026-09-15&time=18:45:00&range=5&device=Samsung+Galaxy+S24&demo=1")
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert "best_available_location" in data2
    assert data2["best_available_location"]["confidence"] == "HIGH"

    # 5. Report
    res3 = client.get("/api/location/intelligence/report?demo=1")
    assert res3.status_code == 200
    data3 = res3.get_json()
    assert "report_title" in data3
