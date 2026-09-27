"""
Tests for JOCKY Network Forensics Engine
"""
import sys
import os
import pytest

# Ensure project root is on the path
root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root not in sys.path:
    sys.path.insert(0, root)


# ---------------------------------------------------------------------------
# 1. Unit Tests — Data Classes
# ---------------------------------------------------------------------------

class TestNetworkSearchEngine:
    """Test the search engine date/time filtering."""

    def test_search_returns_all_when_no_date(self):
        from collector.network_forensics import NetworkSearchEngine
        timeline = [
            {"timestamp": "2026-09-15T10:00:00+00:00", "event_type": "WLAN", "description": "Connected"},
            {"timestamp": "2026-09-15T12:00:00+00:00", "event_type": "DHCP", "description": "Lease"},
        ]
        results = NetworkSearchEngine.search_by_time(timeline, date_str=None)
        assert len(results) == 2

    def test_search_filters_by_date(self):
        from collector.network_forensics import NetworkSearchEngine
        timeline = [
            {"timestamp": "2026-09-15T10:00:00+00:00", "event_type": "WLAN", "description": "Connected"},
            {"timestamp": "2026-09-15T10:03:00+00:00", "event_type": "DHCP", "description": "Lease"},
            {"timestamp": "2026-09-14T10:00:00+00:00", "event_type": "WLAN", "description": "Old"},
        ]
        results = NetworkSearchEngine.search_by_time(timeline, date_str="2026-09-15", time_str="10:01", range_mins=5)
        # Should match the first two (within 5 min of 10:01) but not the third (different day)
        assert len(results) == 2
        assert all(r.get("search_distance_seconds") is not None for r in results)

    def test_search_fallback_on_no_match(self):
        from collector.network_forensics import NetworkSearchEngine
        timeline = [
            {"timestamp": "2026-09-10T10:00:00+00:00", "event_type": "WLAN", "description": "Old event"},
        ]
        results = NetworkSearchEngine.search_by_time(timeline, date_str="2026-09-15", time_str="10:00", range_mins=5)
        # No match in window, should return fallback
        assert len(results) >= 1
        assert results[0].get("fallback") is True


class TestDatetimeParsing:
    """Test the datetime parser."""

    def test_iso_format(self):
        from collector.network_forensics import _parse_network_datetime
        dt = _parse_network_datetime("2026-09-15T10:30:00+00:00")
        assert dt is not None
        assert dt.hour == 10
        assert dt.minute == 30

    def test_date_and_time_separate(self):
        from collector.network_forensics import _parse_network_datetime
        dt = _parse_network_datetime("2026-09-15", "14:30")
        assert dt is not None
        assert dt.hour == 14
        assert dt.minute == 30

    def test_date_only(self):
        from collector.network_forensics import _parse_network_datetime
        dt = _parse_network_datetime("2026-09-15")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 9
        assert dt.day == 15

    def test_none_returns_none(self):
        from collector.network_forensics import _parse_network_datetime
        assert _parse_network_datetime(None) is None
        assert _parse_network_datetime("") is None


class TestNetworkTimelineBuilder:
    """Test the timeline builder."""

    def test_builds_from_events(self):
        from collector.network_forensics import NetworkTimelineBuilder
        events = [
            {"timestamp": "2026-09-15T10:00:00+00:00", "event_type": "WLAN", "description": "Connected", "ssid": "TestNet"},
            {"timestamp": "2026-09-15T11:00:00+00:00", "event_type": "DHCP", "description": "Lease"},
        ]
        timeline = NetworkTimelineBuilder.build_timeline([], [], [], [], events)
        assert len(timeline) == 2
        # Should be sorted descending
        assert timeline[0]["timestamp"] >= timeline[1]["timestamp"]

    def test_builds_from_registered_networks(self):
        from collector.network_forensics import NetworkTimelineBuilder
        registered = [
            {"profile_name": "TestNet", "category": "Private", "date_created": "2026-01-01T00:00:00+00:00", "date_last_connected": "2026-09-15T10:00:00+00:00", "evidence_source": "Registry"},
        ]
        timeline = NetworkTimelineBuilder.build_timeline([], [], registered, [], [])
        # Should have 2 entries: first seen + last connected
        assert len(timeline) == 2

    def test_builds_from_connections(self):
        from collector.network_forensics import NetworkTimelineBuilder
        connections = [
            {"timestamp": "2026-09-15T10:00:00+00:00", "protocol": "TCP", "state": "ESTABLISHED", "local_address": "192.168.1.1", "local_port": "443", "remote_address": "1.2.3.4", "remote_port": "80", "process": "chrome.exe"},
        ]
        timeline = NetworkTimelineBuilder.build_timeline(connections, [], [], [], [])
        assert len(timeline) == 1
        assert "Active Connection" in timeline[0]["event_type"]


# ---------------------------------------------------------------------------
# 2. Demo Data Tests
# ---------------------------------------------------------------------------

class TestDemoData:
    """Test demo data generation."""

    def test_demo_overview_returns_data(self):
        from collector.network_forensics import get_network_overview_intelligence
        result = get_network_overview_intelligence(demo_mode=True)
        assert result["demo_mode"] is True
        assert result["active_connections_count"] > 0
        assert result["wifi_profiles_count"] > 0
        assert result["dns_cache_count"] > 0
        assert not result["no_evidence"]
        assert "DEMO" in result["module"]

    def test_demo_search_returns_results(self):
        from collector.network_forensics import search_network_by_time
        result = search_network_by_time(date_str="2026-09-15", time_str="10:00", range_mins=1440, demo_mode=True)
        assert result["demo_mode"] is True
        assert result["result_count"] > 0

    def test_demo_report_generates(self):
        from collector.network_forensics import generate_network_forensic_report
        report = generate_network_forensic_report(demo_mode=True)
        assert "report_title" in report
        assert report["summary"]["wifi_profiles_saved"] > 0
        assert len(report["evidence_sources"]) > 0

    def test_demo_connections_labeled_simulated(self):
        from collector.network_forensics import get_network_overview_intelligence
        result = get_network_overview_intelligence(demo_mode=True)
        for conn in result["connections"]:
            assert conn["confidence"] == "SIMULATED"

    def test_non_demo_does_not_fabricate(self):
        """In non-demo mode, all data comes from real system collection (which may be empty)."""
        from collector.network_forensics import get_network_overview_intelligence
        result = get_network_overview_intelligence(demo_mode=False)
        assert result["demo_mode"] is False
        # Should not have SIMULATED confidence markers
        for conn in result.get("connections", []):
            assert conn.get("confidence") != "SIMULATED"


# ---------------------------------------------------------------------------
# 3. Network Report Tests
# ---------------------------------------------------------------------------

class TestNetworkReportGenerator:
    """Test report generation."""

    def test_report_structure(self):
        from collector.network_forensics import NetworkReportGenerator
        report = NetworkReportGenerator.generate_report(
            connections=[{"state": "ESTABLISHED", "evidence_source": "netstat"}],
            profiles=[{"ssid": "Test", "evidence_source": "netsh"}],
            registered=[],
            interfaces=[{"interface_name": "Wi-Fi", "evidence_source": "psutil"}],
            dns_entries=[],
            events=[],
            timeline=[],
        )
        assert report["report_title"] == "JOCKY Network Forensic Report"
        assert report["summary"]["total_active_connections"] == 1
        assert report["summary"]["wifi_profiles_saved"] == 1
        assert report["summary"]["network_interfaces"] == 1
        assert "netstat" in report["evidence_sources"]
        assert "netsh" in report["evidence_sources"]

    def test_report_has_honesty_note(self):
        from collector.network_forensics import NetworkReportGenerator
        report = NetworkReportGenerator.generate_report([], [], [], [], [], [], [])
        assert "honesty_note" in report
        assert "fabricated" in report["honesty_note"].lower()


# ---------------------------------------------------------------------------
# 4. Flask API Endpoint Tests
# ---------------------------------------------------------------------------

class TestFlaskEndpoints:
    """Test the Flask API endpoints for network forensics."""

    @pytest.fixture
    def client(self):
        """Create a Flask test client."""
        from server.server import app
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_overview_endpoint(self, client):
        resp = client.get("/api/network/intelligence/overview?demo=1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["demo_mode"] is True
        assert "active_connections_count" in data
        assert data["active_connections_count"] > 0

    def test_search_endpoint(self, client):
        resp = client.get("/api/network/intelligence/search?demo=1&date=2026-09-15&time=10:00&range=1440")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "results" in data
        assert data["result_count"] > 0

    def test_report_endpoint(self, client):
        resp = client.get("/api/network/intelligence/report?demo=1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["report_title"] == "JOCKY Network Forensic Report"
        assert "summary" in data

    def test_overview_non_demo(self, client):
        resp = client.get("/api/network/intelligence/overview")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["demo_mode"] is False

    def test_search_with_event_type_filter(self, client):
        resp = client.get("/api/network/intelligence/search?demo=1&date=2026-09-15&time=10:00&range=1440&event_type=wlan")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "results" in data
