from collector.linux_collector import system_info, memory, browser_history


def test_linux_system_info_has_dashboard_fields():
    x = system_info()
    for key in ("hostname", "operating_system", "kernel", "architecture", "system_directory",
                "uptime_seconds", "python_version", "processor", "cpu_cores",
                "total_ram_gb", "total_disk_gb", "free_disk_gb", "boot_time"):
        assert key in x


def test_linux_memory_is_dashboard_normalized():
    x = memory()
    assert x["assessment_type"] == "Physical Memory (RAM)"
    assert x["total_ram_gb"] >= 0
    assert x["used_ram_gb"] >= 0
    assert 0 <= x["usage_pct"] <= 100


def test_linux_browser_history_returns_list():
    x = browser_history(20)
    assert isinstance(x, list)
    if x:
        assert {"browser", "url", "title", "timestamp"}.issubset(x[0])
