"""Read-only live memory telemetry. Offline dump parsing not available — explicitly reported."""
import os
import sys
import ctypes
from datetime import datetime, timezone


def get_live_memory_statistics():
    now = datetime.now(timezone.utc).isoformat()

    if sys.platform == 'win32':
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ('dwLength', ctypes.c_ulong), ('dwMemoryLoad', ctypes.c_ulong),
                ('ullTotalPhys', ctypes.c_ulonglong), ('ullAvailPhys', ctypes.c_ulonglong),
                ('ullTotalPageFile', ctypes.c_ulonglong), ('ullAvailPageFile', ctypes.c_ulonglong),
                ('ullTotalVirtual', ctypes.c_ulonglong), ('ullAvailVirtual', ctypes.c_ulonglong),
                ('sullAvailExtendedVirtual', ctypes.c_ulonglong),
            ]
        s = MEMORYSTATUSEX()
        s.dwLength = ctypes.sizeof(s)
        try:
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s)):
                total = s.ullTotalPhys
                free = s.ullAvailPhys
                return {
                    'assessment_type': 'LIVE_MEMORY_STATISTICS', 'timestamp': now,
                    'total_ram_gb': round(total / 2**30, 2),
                    'used_ram_gb': round((total - free) / 2**30, 2),
                    'free_ram_gb': round(free / 2**30, 2),
                    'usage_pct': float(s.dwMemoryLoad),
                    'commit_total_gb': round(s.ullTotalPageFile / 2**30, 2),
                    'source': 'GlobalMemoryStatusEx',
                }
        except Exception as e:
            return {'assessment_type': 'LIVE_MEMORY_STATISTICS', 'timestamp': now, 'status': 'ERROR', 'error': str(e)}

    # Linux/macOS — try psutil first, fall back to /proc/meminfo
    try:
        import psutil
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()
        return {
            'assessment_type': 'LIVE_MEMORY_STATISTICS', 'timestamp': now,
            'total_ram_gb': round(vm.total / 2**30, 2),
            'used_ram_gb': round(vm.used / 2**30, 2),
            'free_ram_gb': round(vm.available / 2**30, 2),
            'usage_pct': vm.percent,
            'commit_total_gb': round(sm.total / 2**30, 2),
            'source': 'psutil',
        }
    except ImportError:
        pass

    try:
        vals = {}
        for line in open('/proc/meminfo', errors='replace'):
            k, v = line.split(':', 1)
            vals[k] = int(v.strip().split()[0]) * 1024
        total = vals.get('MemTotal', 0)
        avail = vals.get('MemAvailable', vals.get('MemFree', 0))
        used = max(total - avail, 0)
        return {
            'assessment_type': 'LIVE_MEMORY_STATISTICS', 'timestamp': now,
            'total_ram_gb': round(total / 2**30, 2),
            'used_ram_gb': round(used / 2**30, 2),
            'free_ram_gb': round(avail / 2**30, 2),
            'usage_pct': round(used / total * 100, 2) if total else 0,
            'commit_total_gb': round(vals.get('SwapTotal', 0) / 2**30, 2),
            'source': '/proc/meminfo',
        }
    except Exception as e:
        return {'assessment_type': 'LIVE_MEMORY_STATISTICS', 'timestamp': now, 'status': 'ERROR', 'error': str(e)}


def analyze_memory_dump_image(dump_path):
    """
    Full memory-image parsing is not available on this deployment.
    Returns NOT_AVAILABLE so callers can handle it gracefully.
    """
    return {
        'assessment_type': 'MEMORY_IMAGE_ANALYSIS',
        'status': 'NOT_AVAILABLE',
        'dump_path': dump_path or '',
        'message': (
            'Memory-image parsing requires a Volatility3-compatible profile. '
            'This capability is not available in the current deployment.'
        ),
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
