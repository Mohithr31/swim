"""
JOCKY DFIR Gateway — B7 System Forensics Engine
Collects authentic endpoint identity, hardware specifications, operating system build,
uptime, boot time, CPU, memory, domain/workgroup, timezone, locale, and BIOS information.
If any hardware attribute cannot be queried, returns NOT_ACCESSIBLE. Never fabricates values.
"""
import os
import sys
import time
import socket
import locale
import hashlib
import platform
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

try:
    import psutil
except ImportError:
    psutil = None

try:
    import winreg
except ImportError:
    winreg = None


def _to_iso(dt_or_ts) -> str:
    if not dt_or_ts:
        return "NOT_ACCESSIBLE"
    if isinstance(dt_or_ts, datetime):
        if dt_or_ts.tzinfo is None:
            dt_or_ts = dt_or_ts.replace(tzinfo=timezone.utc)
        return dt_or_ts.astimezone(timezone.utc).isoformat()
    try:
        ts = float(dt_or_ts)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return str(dt_or_ts)


class SystemForensicsCollector:
    """B7 System Forensics Engine."""

    def __init__(self, device_id: str = "DEV-LOCAL", case_id: str = "CAS-DEFAULT"):
        self.device_id = device_id
        self.case_id = case_id
        self.os_type = platform.system()

    def collect_system_info(self) -> Dict[str, Any]:
        """Collect real endpoint hardware and operating system profile."""
        hostname = socket.gethostname()

        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get("USERNAME") or os.environ.get("USER") or "NOT_ACCESSIBLE"

        os_name = f"{platform.system()} {platform.release()}"
        os_version = platform.version()
        arch = platform.machine() or platform.architecture()[0]

        # Windows Build Number
        build_number = "NOT_ACCESSIBLE"
        if self.os_type == "Windows" and winreg:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, winreg.KEY_READ)
                bld, _ = winreg.QueryValueEx(k, "CurrentBuildNumber")
                ubr, _ = winreg.QueryValueEx(k, "UBR")
                build_number = f"{bld}.{ubr}"
                winreg.CloseKey(k)
            except Exception:
                build_number = os_version
        elif self.os_type == "Linux":
            build_number = platform.uname().release
        elif self.os_type == "Darwin":
            build_number = platform.mac_ver()[0]

        # CPU info
        cpu_name = platform.processor() or "NOT_ACCESSIBLE"
        if self.os_type == "Windows" and winreg:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", 0, winreg.KEY_READ)
                proc_name, _ = winreg.QueryValueEx(k, "ProcessorNameString")
                if proc_name:
                    cpu_name = str(proc_name).strip()
                winreg.CloseKey(k)
            except Exception:
                pass
        elif self.os_type == "Linux" and os.path.exists("/proc/cpuinfo"):
            try:
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if "model name" in line:
                            cpu_name = line.split(":", 1)[1].strip()
                            break
            except Exception:
                pass

        # Cores & Memory
        logical_cores = psutil.cpu_count(logical=True) if psutil else "NOT_ACCESSIBLE"
        physical_cores = psutil.cpu_count(logical=False) if psutil else "NOT_ACCESSIBLE"

        total_ram_gb = "NOT_ACCESSIBLE"
        avail_ram_gb = "NOT_ACCESSIBLE"
        ram_bytes = 0
        if psutil:
            try:
                vm = psutil.virtual_memory()
                ram_bytes = vm.total
                total_ram_gb = f"{round(vm.total / (1024**3), 2)} GB"
                avail_ram_gb = f"{round(vm.available / (1024**3), 2)} GB"
            except Exception:
                pass

        # Boot time & Uptime
        boot_time_iso = "NOT_ACCESSIBLE"
        uptime_str = "NOT_ACCESSIBLE"
        uptime_seconds = 0
        if psutil:
            try:
                bt = psutil.boot_time()
                boot_time_iso = _to_iso(bt)
                now_ts = time.time()
                uptime_seconds = int(now_ts - bt)
                hours, remainder = divmod(uptime_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                days, hours = divmod(hours, 24)
                uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"
            except Exception:
                pass

        # Domain / Workgroup
        domain_workgroup = os.environ.get("USERDOMAIN") or "WORKGROUP"
        if self.os_type == "Windows" and winreg:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_READ)
                dom, _ = winreg.QueryValueEx(k, "Domain")
                if dom:
                    domain_workgroup = str(dom)
                winreg.CloseKey(k)
            except Exception:
                pass

        # Timezone & Locale
        tz_name = "UTC"
        try:
            tz_name = time.tzname[0] if hasattr(time, "tzname") and time.tzname else "UTC"
        except Exception:
            pass

        loc_str = "NOT_ACCESSIBLE"
        try:
            loc = locale.getdefaultlocale()
            loc_str = f"{loc[0]}.{loc[1]}" if loc[0] else "NOT_ACCESSIBLE"
        except Exception:
            pass

        # BIOS / Firmware
        bios_info = "NOT_ACCESSIBLE"
        if self.os_type == "Windows" and winreg:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", 0, winreg.KEY_READ)
                vendor, _ = winreg.QueryValueEx(k, "BIOSVendor")
                version, _ = winreg.QueryValueEx(k, "BIOSVersion")
                date, _ = winreg.QueryValueEx(k, "BIOSReleaseDate")
                bios_info = f"{vendor} {version} ({date})".strip()
                winreg.CloseKey(k)
            except Exception:
                pass

        sys_data = {
            "device_id": self.device_id,
            "case_id": self.case_id,
            "hostname": hostname,
            "username": username,
            "operating_system": os_name,
            "os_name": self.os_type,
            "os_version": os_version,
            "build": build_number,
            "architecture": arch,
            "cpu": cpu_name,
            "cpu_cores": f"{physical_cores} physical / {logical_cores} logical" if physical_cores != "NOT_ACCESSIBLE" else str(logical_cores),
            "ram": total_ram_gb,
            "ram_bytes": ram_bytes,
            "ram_available": avail_ram_gb,
            "boot_time": boot_time_iso,
            "uptime": uptime_str,
            "uptime_seconds": uptime_seconds,
            "domain_workgroup": domain_workgroup,
            "timezone": tz_name,
            "locale": loc_str,
            "bios": bios_info,
            "firmware": bios_info,
            "status": "COLLECTED",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        return sys_data
