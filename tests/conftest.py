"""
JOCKY Test Configuration & Determinism Fixtures

Ensures all tests are host-independent by providing stable mocks for:
  - OS kernel modules, users, network interfaces, browser profiles
  - Security service states, driver inventories
  - Live telemetry, log sources
"""
import os
import pytest
from unittest.mock import patch, MagicMock

# ─── Stable mock data that never varies by host ──────────────────────────────

MOCK_PROC_MODULES = (
    "ext4 1234567 3 - Live 0xffffffffc05a0000\n"
    "bluetooth 456789 0 - Live 0xffffffffc0600000\n"
    "usbcore 234567 5 - Live 0xffffffffc0700000\n"
)

MOCK_PROCESS_LIST = [
    {"pid": 1, "ppid": 0, "name": "systemd", "user": "root",
     "executable": "/sbin/init", "command_line": "/sbin/init splash",
     "state": "S", "memory_kb": 12000, "threads": 1,
     "start_time": "2026-09-11T00:00:00+00:00", "source": "/proc",
     "executable_sha256": "a" * 64, "open_files": [], "file_descriptors": [],
     "accessed_directories": [], "working_directory": "/", "root_directory": "/",
     "child_pids": [2], "child_count": 1,
     "file_access_note": "mock"},
    {"pid": 2, "ppid": 1, "name": "kthreadd", "user": "root",
     "executable": "", "command_line": "[kthreadd]",
     "state": "S", "memory_kb": 0, "threads": 1,
     "start_time": "2026-09-11T00:00:01+00:00", "source": "/proc",
     "executable_sha256": None, "open_files": [], "file_descriptors": [],
     "accessed_directories": [], "working_directory": None, "root_directory": None,
     "child_pids": [], "child_count": 0,
     "file_access_note": "mock"},
]

MOCK_NETWORK = [
    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": "22",
     "remote_address": "192.168.1.100", "remote_port": "54321",
     "state": "ESTABLISHED", "pid": 1234, "process": "sshd", "source": "ss/netstat"},
    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": "5000",
     "remote_address": "0.0.0.0", "remote_port": "0",
     "state": "LISTEN", "pid": 5678, "process": "python3", "source": "ss/netstat"},
]

MOCK_USERS = [
    {"username": "analyst", "uid": 1000, "gid": 1000,
     "home": "/home/analyst", "shell": "/bin/bash",
     "account_status": "present", "logged_in": True,
     "login_sessions": [{"terminal": "pts/0", "login_date": "Sep 11 08:00", "source": "who"}],
     "source": "/etc/passwd + who (human accounts)"},
]

MOCK_SERVICES = [
    {"service_name": "sshd", "load_state": "loaded", "active_state": "active",
     "sub_state": "running", "description": "OpenSSH Daemon", "source": "systemctl"},
    {"service_name": "cron", "load_state": "loaded", "active_state": "active",
     "sub_state": "running", "description": "Regular background program", "source": "systemctl"},
]

MOCK_LOGS = [
    {"timestamp": "2026-09-11T08:00:00+00:00", "channel": "sshd",
     "event_id": "1234", "level": "INFO", "provider": "sshd",
     "message": "Accepted publickey for analyst from 192.168.1.100 port 54321",
     "source": "journald", "priority": "6"},
    {"timestamp": "2026-09-11T08:05:00+00:00", "channel": "kernel",
     "event_id": "", "level": "INFO", "provider": "kernel",
     "message": "usb 1-1: new USB device found", "source": "dmesg"},
]

MOCK_DRIVERS = [
    {"driver_name": "ext4", "path": "/lib/modules/6.1.0/kernel/fs/ext4/ext4.ko",
     "sha256": "b" * 64, "signer": "Canonical Ltd.",
     "signature_status": "SIGNED", "loaded": True, "service_name": "ext4",
     "is_vulnerable": False, "cve": "N/A", "description": "Fourth Extended Filesystem",
     "risk_level": "CLEAN", "remediation": None, "mitre_technique": None,
     "size_bytes": 1234567, "vermagic": "6.1.0", "source": "/proc/modules + modinfo",
     "assessment_timestamp": "2026-09-11T08:00:00+00:00"},
]

MOCK_SYSTEM_INFO = {
    "hostname": "jocky-test-host", "operating_system": "Ubuntu 24.04 LTS",
    "kernel": "6.1.0-mock", "os_version": "24.04",
    "architecture": "x86_64", "architecture_bits": "64bit",
    "system_directory": "/", "logged_in_user": "analyst",
    "uptime_seconds": 3600, "python_version": "3.12.0",
    "processor": "Mock CPU", "cpu_cores": 4,
    "total_ram_gb": 8.0, "free_ram_gb": 4.0,
    "total_disk_gb": 100.0, "free_disk_gb": 50.0,
    "boot_time": "2026-09-11T00:00:00+00:00",
    "timezone": "UTC", "timestamp": "2026-09-11T08:00:00+00:00",
    "source": "Linux endpoint (read-only)",
}


# ─── Session-scoped fixtures ──────────────────────────────────────────────────

@pytest.fixture(scope="session")
def mock_linux_env():
    """Patch all host-specific Linux calls for the entire test session."""
    with patch("subprocess.check_output", return_value=""), \
         patch("os.listdir", return_value=[]), \
         patch("builtins.open", side_effect=OSError("mocked")):
        yield


@pytest.fixture
def stable_db(tmp_path):
    """Provide a fresh in-memory SQLite database for each test."""
    db_file = str(tmp_path / "test_jocky.db")
    from server.database import init_db
    init_db(db_file)
    return db_file


@pytest.fixture
def mock_proc_modules(monkeypatch):
    """Provide deterministic /proc/modules content."""
    import io
    monkeypatch.setattr("builtins.open",
        lambda path, *a, **kw: io.StringIO(MOCK_PROC_MODULES)
        if str(path) == "/proc/modules" else open.__wrapped__(path, *a, **kw)
        if hasattr(open, "__wrapped__") else (_ for _ in ()).throw(OSError("mocked"))
    )
    yield MOCK_PROC_MODULES


@pytest.fixture
def temp_evidence_dir(tmp_path):
    """Provide a temporary evidence directory."""
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    return str(ev_dir)


@pytest.fixture(autouse=True)
def isolate_env(tmp_path):
    """Isolate database path and evidence directory per test to prevent test cross-contamination."""
    old_db = os.environ.get("JOCKY_DB")
    old_evd = os.environ.get("JOCKY_EVIDENCE_DIR")
    
    test_db = str(tmp_path / "test_isolated.db")
    test_evd = str(tmp_path / "evidence")
    os.makedirs(test_evd, exist_ok=True)
    
    os.environ["JOCKY_DB"] = test_db
    os.environ["JOCKY_EVIDENCE_DIR"] = test_evd
    
    import server.server as srv
    from server.database import init_db
    srv.DB_PATH = test_db
    srv.EVIDENCE_DIR = test_evd
    try:
        init_db(test_db)
    except Exception:
        pass

    yield

    if old_db is not None:
        os.environ["JOCKY_DB"] = old_db
    else:
        os.environ.pop("JOCKY_DB", None)

    if old_evd is not None:
        os.environ["JOCKY_EVIDENCE_DIR"] = old_evd
    else:
        os.environ.pop("JOCKY_EVIDENCE_DIR", None)


@pytest.fixture
def app(tmp_path):
    """Provide isolated application instance for testing."""
    from app import create_app
    from app.config import Config
    test_db = tmp_path / "test_app.db"
    test_evd = tmp_path / "evidence"
    test_rep = tmp_path / "reports"
    test_evd.mkdir(parents=True, exist_ok=True)
    test_rep.mkdir(parents=True, exist_ok=True)
    Config.DB_PATH = test_db
    Config.EVIDENCE_DIR = test_evd
    Config.REPORTS_DIR = test_rep
    test_app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(test_db),
        "EVIDENCE_STORAGE_PATH": str(test_evd),
        "REPORTS_STORAGE_PATH": str(test_rep),
    })
    return test_app


@pytest.fixture
def client(app):
    """Provide Flask test client."""
    return app.test_client()

