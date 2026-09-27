"""
JOCKY Benign Security Behaviour Test Fixtures

Synthetic telemetry representing injection, integrity, driver and
security-posture indicators for testing detectors WITHOUT implementing
any covert injection or security-control bypass.

All data is fabricated for test purposes only.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List

_NOW = datetime.now(timezone.utc).isoformat()


# ─── Process injection / hollowing fixtures ───────────────────────────────────

FIXTURE_CLEAN_PROCESS = {
    "pid": 1000, "process_name": "bash", "exe": "/bin/bash",
    "injection_score": 0, "risk_level": "CLEAN", "indicators": [],
}

FIXTURE_RWX_INJECTION = {
    "pid": 2001, "process_name": "suspicious_proc", "exe": "/tmp/suspicious_proc",
    "injection_score": 6,
    "risk_level": "HIGH",
    "indicators": [
        "executable_writable_mapping at 0x7f0000000000",
        "no_path_executable_mapping at 0x7f0001000000",
    ],
}

FIXTURE_HOLLOW_PROCESS = {
    "pid": 2002, "process_name": "svchost_clone", "exe": "/tmp/svchost_clone",
    "injection_score": 5,
    "risk_level": "HIGH",
    "indicators": [
        "hollow_memory_indicator: VmSize=500000kB VmRSS=4000kB ratio=125.0",
        "deleted_exe: process executable was deleted after launch",
    ],
}

FIXTURE_DELETED_EXE = {
    "pid": 2003, "process_name": "stealthy", "exe": "/tmp/.hidden (deleted)",
    "injection_score": 3,
    "risk_level": "MEDIUM",
    "indicators": ["deleted_exe: process executable was deleted after launch"],
}

FIXTURE_ANOMALOUS_LIB = {
    "pid": 2004, "process_name": "app_with_preload", "exe": "/usr/bin/app",
    "injection_score": 1,
    "risk_level": "LOW",
    "indicators": ["anomalous_loaded_library: /tmp/evil_preload.so"],
}

INJECTION_ASSESSMENT_MULTI = {
    "assessment_type": "Process Injection / Hollowing Detector",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "processes_scanned": 200,
    "suspicious_processes": [
        FIXTURE_RWX_INJECTION,
        FIXTURE_HOLLOW_PROCESS,
        FIXTURE_DELETED_EXE,
        FIXTURE_ANOMALOUS_LIB,
    ],
    "clean_count": 196,
    "risk_summary": {"HIGH": 2, "MEDIUM": 1, "LOW": 1, "CLEAN": 196},
}

INJECTION_ASSESSMENT_CLEAN = {
    "assessment_type": "Process Injection / Hollowing Detector",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "processes_scanned": 100,
    "suspicious_processes": [],
    "clean_count": 100,
    "risk_summary": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 100},
}


# ─── API integrity fixtures ───────────────────────────────────────────────────

FIXTURE_CLEAN_LIBRARY = {
    "path": "/lib/x86_64-linux-gnu/libc.so.6",
    "sha256": "a" * 64,
    "elf_magic_valid": True,
    "suspicious_exec_sections": [],
    "risk_level": "CLEAN",
    "source": "API integrity assessment (read-only)",
}

FIXTURE_HOOKED_LIBRARY = {
    "path": "/lib/x86_64-linux-gnu/libssl.so.3",
    "sha256": "b" * 64,
    "elf_magic_valid": True,
    "suspicious_exec_sections": [".evil_section", ".injected"],
    "risk_level": "HIGH",
    "source": "API integrity assessment (read-only)",
}

FIXTURE_INVALID_ELF = {
    "path": "/lib/x86_64-linux-gnu/libdl.so.2",
    "sha256": "c" * 64,
    "elf_magic_valid": False,
    "suspicious_exec_sections": [],
    "risk_level": "CLEAN",
    "source": "API integrity assessment (read-only)",
}

FIXTURE_ANON_EXEC_REGION = {
    "pid": 3001, "process_name": "hooked_app",
    "anonymous_executable_regions": 3,
    "regions": [
        {"start": "0x7f0000000000", "end": "0x7f0000001000", "perms": "r-xp"},
        {"start": "0x7f0001000000", "end": "0x7f0001001000", "perms": "rwxp"},
        {"start": "0x7f0002000000", "end": "0x7f0002001000", "perms": "r-xp"},
    ],
    "risk_level": "HIGH",
    "note": "Anonymous executable memory regions may indicate API hooking.",
}

API_INTEGRITY_ASSESSMENT_HIGH = {
    "assessment_type": "API Integrity Assessment",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "library_integrity": [FIXTURE_CLEAN_LIBRARY, FIXTURE_HOOKED_LIBRARY, FIXTURE_INVALID_ELF],
    "process_api_map_anomalies": [FIXTURE_ANON_EXEC_REGION],
    "risk_summary": {"high_risk_libraries": 1, "processes_with_anon_exec_regions": 1},
}

API_INTEGRITY_ASSESSMENT_CLEAN = {
    "assessment_type": "API Integrity Assessment",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "library_integrity": [FIXTURE_CLEAN_LIBRARY],
    "process_api_map_anomalies": [],
    "risk_summary": {"high_risk_libraries": 0, "processes_with_anon_exec_regions": 0},
}


# ─── Kernel integrity fixtures ────────────────────────────────────────────────

FIXTURE_NORMAL_MODULE = {
    "name": "ext4", "size_bytes": 1234567, "state": "Live",
    "path": "/lib/modules/6.1.0/kernel/fs/ext4/ext4.ko",
    "signer": "Canonical Ltd.", "vermagic": "6.1.0",
    "description": "Fourth Extended Filesystem",
    "sha256": "d" * 64, "signed": True,
    "suspicious_name": False, "is_security_module": False,
}

FIXTURE_SUSPICIOUS_MODULE = {
    "name": "rootkit_xyz", "size_bytes": 45000, "state": "Live",
    "path": "NOT_RESOLVED",
    "signer": "UNSIGNED", "vermagic": "unknown",
    "description": "",
    "sha256": "NOT_AVAILABLE", "signed": False,
    "suspicious_name": True, "is_security_module": False,
}

FIXTURE_SECURITY_MODULE = {
    "name": "apparmor", "size_bytes": 98000, "state": "Live",
    "path": "/lib/modules/6.1.0/kernel/security/apparmor/apparmor.ko",
    "signer": "Canonical Ltd.", "vermagic": "6.1.0",
    "description": "AppArmor security module",
    "sha256": "e" * 64, "signed": True,
    "suspicious_name": False, "is_security_module": True,
}

KERNEL_INTEGRITY_CLEAN = {
    "assessment_type": "Kernel Integrity Assessment",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "modules": [FIXTURE_NORMAL_MODULE, FIXTURE_SECURITY_MODULE],
    "suspicious_modules": [],
    "unsigned_modules": [],
    "security_modules_active": ["apparmor"],
    "lsm_hooks": ["apparmor", "yama"],
    "indicators": [],
    "total_modules": 2,
    "suspicious_count": 0,
    "unsigned_count": 0,
}

KERNEL_INTEGRITY_SUSPICIOUS = {
    "assessment_type": "Kernel Integrity Assessment",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "modules": [FIXTURE_NORMAL_MODULE, FIXTURE_SUSPICIOUS_MODULE, FIXTURE_SECURITY_MODULE],
    "suspicious_modules": ["rootkit_xyz"],
    "unsigned_modules": ["rootkit_xyz"],
    "security_modules_active": ["apparmor"],
    "lsm_hooks": ["apparmor"],
    "indicators": [{"type": "suspicious_module_name", "module": "rootkit_xyz", "severity": "HIGH"}],
    "total_modules": 3,
    "suspicious_count": 1,
    "unsigned_count": 1,
}


# ─── Security posture fixtures ────────────────────────────────────────────────

POSTURE_ALL_ACTIVE = {
    "assessment_type": "Security Posture / Control Health Assessment",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "controls": {
        "auditd": {"label": "Linux Audit Daemon", "status": "active", "health": "ACTIVE"},
        "clamav-daemon": {"label": "ClamAV Antivirus", "status": "active", "health": "ACTIVE"},
        "ufw": {"label": "UFW Firewall", "status": "active", "health": "ACTIVE"},
        "apparmor": {"label": "AppArmor MAC", "status": "active", "health": "ACTIVE"},
        "falcon-sensor": {"label": "CrowdStrike Falcon Sensor", "status": "not-found", "health": "NOT_OBSERVED"},
    },
    "risk_indicators": [],
    "overall_risk": "LOW",
}

POSTURE_CONTROLS_DISABLED = {
    "assessment_type": "Security Posture / Control Health Assessment",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "controls": {
        "auditd": {"label": "Linux Audit Daemon", "status": "inactive", "health": "DISABLED"},
        "ufw": {"label": "UFW Firewall", "status": "inactive", "health": "DISABLED"},
        "apparmor": {"label": "AppArmor MAC", "status": "active", "health": "ACTIVE"},
        "clamav-daemon": {"label": "ClamAV Antivirus", "status": "not-found", "health": "NOT_OBSERVED"},
    },
    "risk_indicators": [
        {"control": "auditd", "label": "Linux Audit Daemon", "severity": "HIGH",
         "status": "DISABLED", "note": "Linux Audit Daemon is installed but disabled."},
        {"control": "ufw", "label": "UFW Firewall", "severity": "HIGH",
         "status": "DISABLED", "note": "UFW Firewall is installed but disabled."},
    ],
    "overall_risk": "HIGH",
}

POSTURE_CONTROLS_DEGRADED = {
    "assessment_type": "Security Posture / Control Health Assessment",
    "platform": "Linux",
    "timestamp": _NOW,
    "read_only": True,
    "controls": {
        "auditd": {"label": "Linux Audit Daemon", "status": "active", "health": "ACTIVE"},
        "selinux": {"label": "SELinux", "mode": "Permissive", "health": "DEGRADED"},
        "ufw": {"label": "UFW Firewall", "status": "not-found", "health": "NOT_OBSERVED"},
    },
    "risk_indicators": [
        {"control": "selinux", "label": "SELinux", "severity": "MEDIUM",
         "status": "DEGRADED", "note": "SELinux is in a degraded or permissive state."},
    ],
    "overall_risk": "MEDIUM",
}


# ─── BYOVD driver fixtures ────────────────────────────────────────────────────

FIXTURE_CLEAN_DRIVER = {
    "driver_name": "normal_disk.ko",
    "path": "/lib/modules/6.1.0/kernel/drivers/block/normal_disk.ko",
    "sha256": "f" * 64, "signer": "Canonical Ltd.",
    "signature_status": "SIGNED", "loaded": True,
    "service_name": "normal_disk",
    "is_vulnerable": False, "cve": "N/A",
    "description": "Normal block device driver",
    "risk_level": "CLEAN", "remediation": None, "mitre_technique": None,
    "size_bytes": 56789, "vermagic": "6.1.0",
    "source": "/proc/modules + modinfo",
    "assessment_timestamp": _NOW,
}

FIXTURE_VULN_DRIVER_CRITICAL = {
    "driver_name": "rtcore64.sys",
    "path": "C:\\Windows\\System32\\drivers\\rtcore64.sys",
    "sha256": "0" * 64, "signer": "UNSIGNED",
    "signature_status": "UNSIGNED / NO SIGNER", "loaded": True,
    "service_name": "rtcore64",
    "is_vulnerable": True, "cve": "CVE-2021-21551",
    "description": "MSI Afterburner driver — arbitrary kernel memory read/write via IOCTL.",
    "risk_level": "CRITICAL",
    "remediation": "Uninstall MSI Afterburner or update to a patched version. Block via WDAC policy.",
    "mitre_technique": "T1068",
    "size_bytes": 32768, "vermagic": "",
    "source": "System32\\drivers inventory",
    "assessment_timestamp": _NOW,
}

FIXTURE_VULN_DRIVER_HIGH = {
    "driver_name": "spydrvr.sys",
    "path": "C:\\Windows\\System32\\drivers\\spydrvr.sys",
    "sha256": "1" * 64, "signer": "UNSIGNED",
    "signature_status": "UNSIGNED / NO SIGNER", "loaded": True,
    "service_name": "spydrvr",
    "is_vulnerable": True, "cve": "CVE-2019-19469",
    "description": "SpeedFan driver — kernel read/write via crafted IOCTL.",
    "risk_level": "HIGH",
    "remediation": "Remove SpeedFan. Block driver via WDAC.",
    "mitre_technique": "T1068",
    "size_bytes": 16384, "vermagic": "",
    "source": "System32\\drivers inventory",
    "assessment_timestamp": _NOW,
}

BYOVD_REPORT_WITH_VULNS: Dict[str, Any] = {
    "assessment_type": "BYOVD Vulnerability Risk Assessment",
    "platform": "linux",
    "timestamp": _NOW,
    "read_only": True,
    "summary": {
        "total_drivers_scanned": 3,
        "vulnerable_drivers_found": 2,
        "critical_risk_count": 1,
        "high_risk_count": 1,
        "unsigned_drivers_count": 0,
        "overall_risk": "CRITICAL",
    },
    "vulnerable_drivers": [FIXTURE_VULN_DRIVER_CRITICAL, FIXTURE_VULN_DRIVER_HIGH],
    "unsigned_drivers_sample": [],
    "remediation_plan": {
        "required": True,
        "total_vulnerable": 2,
        "immediate_action_count": 1,
        "actions": [
            {"priority": "IMMEDIATE", "driver": "rtcore64.sys", "cve": "CVE-2021-21551",
             "action": "Uninstall MSI Afterburner or update to a patched version.",
             "mitre_technique": "T1068", "wdac_block_recommended": True,
             "hvci_recommended": True},
            {"priority": "HIGH", "driver": "spydrvr.sys", "cve": "CVE-2019-19469",
             "action": "Remove SpeedFan. Block driver via WDAC.",
             "mitre_technique": "T1068", "wdac_block_recommended": True,
             "hvci_recommended": False},
        ],
        "general_recommendations": [
            "Enable HVCI on Windows.",
            "Deploy WDAC policy with Microsoft's recommended block list.",
        ],
    },
    "catalogue_version": "11 entries",
    "catalogue_reference": "https://www.loldrivers.io",
}

BYOVD_REPORT_CLEAN: Dict[str, Any] = {
    "assessment_type": "BYOVD Vulnerability Risk Assessment",
    "platform": "linux",
    "timestamp": _NOW,
    "read_only": True,
    "summary": {
        "total_drivers_scanned": 1,
        "vulnerable_drivers_found": 0,
        "critical_risk_count": 0,
        "high_risk_count": 0,
        "unsigned_drivers_count": 0,
        "overall_risk": "LOW",
    },
    "vulnerable_drivers": [],
    "unsigned_drivers_sample": [],
    "remediation_plan": {"required": False, "actions": []},
    "catalogue_version": "11 entries",
    "catalogue_reference": "https://www.loldrivers.io",
}


# ─── Authentication / log fixtures ───────────────────────────────────────────

FIXTURE_SUCCESSFUL_LOGINS: List[Dict[str, Any]] = [
    {"username": "analyst", "status": "SUCCESS", "source_ip": "192.168.1.100",
     "timestamp": "2026-09-11T08:00:00+00:00", "source_workstation": "ws-analyst"},
    {"username": "admin", "status": "SUCCESS", "source_ip": "10.0.0.5",
     "timestamp": "2026-09-11T09:00:00+00:00", "source_workstation": "ws-admin"},
]

FIXTURE_FAILED_LOGINS: List[Dict[str, Any]] = [
    {"username": "analyst", "status": "FAILED", "source_ip": "10.10.10.10",
     "timestamp": "2026-09-11T07:55:00+00:00", "source_workstation": "ATTACKER-PC"},
    {"username": "analyst", "status": "FAILED", "source_ip": "10.10.10.10",
     "timestamp": "2026-09-11T07:55:10+00:00", "source_workstation": "ATTACKER-PC"},
    {"username": "analyst", "status": "FAILED", "source_ip": "10.10.10.10",
     "timestamp": "2026-09-11T07:55:20+00:00", "source_workstation": "ATTACKER-PC"},
    {"username": "root", "status": "FAILED", "source_ip": "10.10.10.11",
     "timestamp": "2026-09-11T07:56:00+00:00", "source_workstation": "SCANNER-1"},
    {"username": "root", "status": "FAILED", "source_ip": "10.10.10.11",
     "timestamp": "2026-09-11T07:56:05+00:00", "source_workstation": "SCANNER-1"},
]


# ─── Normalised log fixtures (for logs normalization tests) ───────────────────

NORMALIZED_LINUX_LOGS: List[Dict[str, Any]] = [
    {"timestamp": "2026-09-11T08:00:00+00:00", "channel": "sshd", "event_id": "",
     "level": "INFO", "provider": "sshd", "severity_num": 6,
     "message": "Accepted publickey for analyst from 192.168.1.100 port 54321",
     "source": "journald", "raw": "Sep 11 08:00:00 host sshd[1234]: Accepted publickey..."},
    {"timestamp": "2026-09-11T08:05:00+00:00", "channel": "sudo", "event_id": "",
     "level": "NOTICE", "provider": "sudo", "severity_num": 5,
     "message": "analyst: TTY=pts/0 ; COMMAND=/bin/bash",
     "source": "journald", "raw": "Sep 11 08:05:00 host sudo[2222]: analyst TTY=pts/0..."},
]

NORMALIZED_WINDOWS_EVENTS: List[Dict[str, Any]] = [
    {"timestamp": "2026-09-11T08:00:00+00:00", "channel": "Security",
     "event_id": "4624", "level": "INFORMATION", "provider": "Microsoft-Windows-Security-Auditing",
     "severity_num": 4, "message": "An account was successfully logged on.",
     "source": "Windows Event Log", "raw": ""},
    {"timestamp": "2026-09-11T08:01:00+00:00", "channel": "Security",
     "event_id": "4625", "level": "INFORMATION", "provider": "Microsoft-Windows-Security-Auditing",
     "severity_num": 4, "message": "An account failed to log on.",
     "source": "Windows Event Log", "raw": ""},
]
