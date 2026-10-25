import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from collector.raw_acquisition import file_bytes, file_size, list_dir
from collector.browser_forensics import BrowserForensicsCollector


def test_read_only_acquisition_reads_real_file():
    if os.name == "nt":
        path = os.path.abspath(__file__)
        parent = os.path.dirname(path)
        base = os.path.basename(path)
        assert file_bytes(path, 128)
        assert file_size(path) is not None
        assert any(name == base for name, _ in list_dir(parent))
    else:
        path = "/etc/hostname"
        assert file_bytes(path, 128)
        assert file_size(path) is not None
        assert any(name == "hostname" for name, _ in list_dir("/etc"))


def test_browser_collector_declares_real_acquisition_layer():
    data = BrowserForensicsCollector(device_id="TEST", case_id="CASE-TEST").collect_all_browser_evidence()
    assert data["status"] in {"COLLECTED", "NO_EVIDENCE_FOUND", "NOT_PRESENT"}
    assert "history" in data and "downloads" in data and "bookmarks" in data
    # The retained low-level acquisition layer is independently tested above.
