"""Unit test for connected device accessed and shared files tracking."""
import pytest
from collector.removable_media import get_file_transfers_and_activity, get_removable_media_forensics
from server.server import app


def test_get_file_transfers_and_activity_structure():
    """Verify get_file_transfers_and_activity returns a list of dictionaries with required keys."""
    records = get_file_transfers_and_activity()
    assert isinstance(records, list)
    for rec in records:
        assert "drive_letter" in rec
        assert "filename" in rec
        assert "target_path" in rec
        assert "operation_type" in rec
        assert "accessed_time" in rec


def test_removable_media_attaches_accessed_files():
    """Verify get_removable_media_forensics attaches accessed and file_activity_records to devices."""
    devices = get_removable_media_forensics()
    assert isinstance(devices, list)
    for dev in devices:
        assert "device" in dev
        assert "status" in dev
        if "file_activity_records" in dev:
            assert isinstance(dev["file_activity_records"], list)
        if "accessed_shared_files" in dev:
            assert isinstance(dev["accessed_shared_files"], list)


def test_accessed_shared_files_api_endpoint():
    """Test the central server API endpoint for connected device accessed and shared files."""
    client = app.test_client()
    res = client.get("/api/devices/accessed_shared_files")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_count" in data
    assert "accessed_files" in data
    assert "shared_files" in data
    assert "connected_devices" in data
    assert "all_records" in data
    assert isinstance(data["accessed_files"], list)
    assert isinstance(data["shared_files"], list)


def test_agent_specific_accessed_shared_files_api_endpoint():
    """Test device-specific endpoint for connected device accessed and shared files."""
    client = app.test_client()
    res = client.get("/api/devices/agent_local/accessed_shared_files")
    assert res.status_code == 200
    data = res.get_json()
    assert data["device_id"] == "agent_local"
    assert "accessed_files" in data
    assert "shared_files" in data
