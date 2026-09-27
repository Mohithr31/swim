#!/usr/bin/env python3
"""Read-only smoke test for the Linux forensic collectors."""
import json
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from collector.linux_collector import filesystem
from collector.removable_media import get_removable_media_forensics, get_file_transfers_and_activity
from collector.network_forensics import get_network_overview_intelligence
from collector.location_intelligence import get_location_overview_intelligence
from collector.recovery import scan_deleted_files

checks = {
    "filesystem_root": filesystem("/"),
    "physical_devices": get_removable_media_forensics(),
    "physical_activity": get_file_transfers_and_activity(),
    "network": get_network_overview_intelligence(False),
    "location": get_location_overview_intelligence(False),
    "deleted_files": scan_deleted_files("/"),
}
print(json.dumps({k: {"type": type(v).__name__, "count": len(v) if hasattr(v, "__len__") else None} for k,v in checks.items()}, indent=2, default=str))
