import json
import sys
import pytest

from agent.jocky_agent import COLLECTOR_DISPATCH
from src.parser import ALLOWLISTED_OPERATIONS


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Linux-native collectors require POSIX modules (pwd, grp)"
)
def test_linux_collector_functions_return_serializable_data():
    from collector import linux_collector as lc

    funcs = [
        lc.system_info,
        lc.processes,
        lc.network,
        lc.users,
        lc.services,
        lc.filesystem,
        lc.disk_usage,
        lc.scheduled_tasks,
        lc.environment,
        lc.logs,
        lc.software,
        lc.network_config,
        lc.mounts,
        lc.memory,
        lc.registry,
        lc.live_events,
        lc.security_telemetry,
        lc.recovery,
        lc.offline,
        lc.get_linux_login_events,
        lc.get_linux_network_interfaces,
        lc.get_linux_storage,
    ]

    for fn in funcs:
        value = fn()
        json.dumps(value)


def test_every_allowlisted_operation_has_agent_dispatch():
    assert ALLOWLISTED_OPERATIONS.issubset(COLLECTOR_DISPATCH.keys())


def test_linux_extension_mismatch_detector(tmp_path):
    from collector import linux_collector as lc

    # Create dummy ELF file named as image.png
    elf_file = tmp_path / "image.png"
    elf_file.write_bytes(
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    res = lc.detect_extension_mismatch(str(elf_file), ".png")

    assert res["mismatch"] is True
    assert "ELF" in res["detected_type"]

    # Create legitimate PNG file
    png_file = tmp_path / "photo.png"
    png_file.write_bytes(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    )

    res2 = lc.detect_extension_mismatch(str(png_file), ".png")

    assert res2["mismatch"] is False


def test_linux_collector_schema_parity():
    from collector import linux_collector as lc

    # -------------------------
    # Login events
    # -------------------------
    logins = lc.get_linux_login_events()

    # No login artifacts is a valid forensic result.
    assert isinstance(logins, list)

    if logins:
        required_login_keys = {
            "event_id",
            "timestamp",
            "username",
            "sid",
            "logon_type",
            "source_workstation",
            "source_ip",
            "authentication_package",
            "status",
            "description",
        }

        for event in logins:
            assert isinstance(event, dict)
            assert required_login_keys.issubset(event.keys())

    # -------------------------
    # Network interfaces
    # -------------------------
    ifaces = lc.get_linux_network_interfaces()

    assert isinstance(ifaces, list)

    if ifaces:
        assert isinstance(ifaces[0], dict)
        assert "interface_name" in ifaces[0]

    # -------------------------
    # Storage
    # -------------------------
    storage = lc.get_linux_storage()

    assert isinstance(storage, list)

    if storage:
        assert isinstance(storage[0], dict)
        assert "drive" in storage[0]
        assert "capacity_gb" in storage[0]
