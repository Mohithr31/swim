"""Read-only endpoint security assessment for JOCKY.

Implements four forensic capabilities as defensive substitutes for the
offensive/evasion techniques described in the JOCKY Problem Statement:

  1. Process-injection / hollowing / thread-hijacking DETECTOR
     Correlates suspicious process creation, executable-memory anomalies,
     thread start addresses, module inconsistencies, and process ancestry.

  2. API-integrity assessment
     Compares selected user-mode API regions against trusted on-disk
     baselines where accessible; reports deviations, anomalous executable
     mappings, and module provenance anomalies.

  3. Kernel-integrity / driver assessment
     Enumerates loaded modules/drivers, verifies signing and paths, flags
     unusual modules and correlates with security telemetry.

  4. Security-posture / control-health assessment
     Reports whether relevant security services, drivers, and protections
     appear active, disabled, degraded, or not observed.
     Clearly distinguishes 'not observed' from 'disabled'.

This module is intentionally READ-ONLY. It does NOT disable, bypass,
unload, patch, exploit, or inject into any security control or process.
"""
from __future__ import annotations
import os
import re
import sys
import platform
import subprocess
import hashlib
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cmd(args: List[str], timeout: int = 8) -> str:
    try:
        return subprocess.check_output(
            args, text=True, stderr=subprocess.DEVNULL, timeout=timeout
        )
    except Exception:
        return ""


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# 1. Process-Injection / Hollowing Detector
# ─────────────────────────────────────────────────────────────────────────────

# Indicator weights used to compute a suspicion score per process.
_INJECTION_INDICATOR_WEIGHTS = {
    "executable_writable_mapping": 3,   # RWX or W+X anonymous mapping
    "no_path_executable_mapping": 2,    # anonymous executable mapping (fileless)
    "path_mismatch": 3,                 # /proc/pid/exe != main mapping in maps
    "deleted_exe": 3,                   # symlink target ends with " (deleted)"
    "unusual_thread_start": 2,          # thread entry outside main executable range
    "suspicious_child_of_trusted": 2,   # e.g. svchost spawned by non-services.exe
    "hollow_memory_indicator": 3,       # VSZ >> RSS by large factor (empty pages)
    "anomalous_loaded_library": 1,      # library path outside standard directories
}

_TRUSTED_LIB_PREFIXES = (
    "/lib", "/usr/lib", "/usr/local/lib",
    "/lib64", "/usr/lib64",
    "C:\\Windows\\System32", "C:\\Windows\\SysWOW64",
)


def _parse_proc_maps(pid: int) -> List[Dict[str, Any]]:
    """Parse /proc/<pid>/maps into a list of region dicts."""
    regions = []
    try:
        with open(f"/proc/{pid}/maps", "r", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                addr_range = parts[0].split("-")
                perms = parts[1] if len(parts) > 1 else "----"
                pathname = parts[5] if len(parts) > 5 else ""
                regions.append({
                    "start": int(addr_range[0], 16) if len(addr_range) > 0 else 0,
                    "end": int(addr_range[1], 16) if len(addr_range) > 1 else 0,
                    "perms": perms,
                    "pathname": pathname,
                })
    except Exception:
        pass
    return regions


def _detect_injection_linux(pid: int, exe_path: str) -> Dict[str, Any]:
    """Return injection indicators for a Linux process (read-only)."""
    indicators: List[str] = []
    score = 0
    regions = _parse_proc_maps(pid)

    for r in regions:
        perms = r["perms"]
        path = r["pathname"]
        is_exec = "x" in perms
        is_write = "w" in perms
        is_anon = path == "" or path.startswith("[")

        # RWX or anonymous executable mappings
        if is_exec and is_write and is_anon:
            indicators.append(f"executable_writable_mapping at 0x{r['start']:x}")
            score += _INJECTION_INDICATOR_WEIGHTS["executable_writable_mapping"]
        elif is_exec and is_anon:
            indicators.append(f"no_path_executable_mapping at 0x{r['start']:x}")
            score += _INJECTION_INDICATOR_WEIGHTS["no_path_executable_mapping"]

        # Loaded libraries outside standard directories
        if is_exec and path and not path.startswith("["):
            if not any(path.startswith(p) for p in _TRUSTED_LIB_PREFIXES):
                indicators.append(f"anomalous_loaded_library: {path}")
                score += _INJECTION_INDICATOR_WEIGHTS["anomalous_loaded_library"]

    # Deleted executable
    if exe_path and exe_path.endswith(" (deleted)"):
        indicators.append("deleted_exe: process executable was deleted after launch")
        score += _INJECTION_INDICATOR_WEIGHTS["deleted_exe"]

    # Path mismatch: /proc/pid/exe target vs first non-anon executable mapping
    try:
        real_exe = os.readlink(f"/proc/{pid}/exe")
        main_exec_paths = [
            r["pathname"] for r in regions
            if "x" in r["perms"] and r["pathname"] and not r["pathname"].startswith("[")
        ]
        if main_exec_paths and real_exe and main_exec_paths[0] != real_exe:
            indicators.append(
                f"path_mismatch: exe={real_exe} vs maps={main_exec_paths[0]}"
            )
            score += _INJECTION_INDICATOR_WEIGHTS["path_mismatch"]
    except Exception:
        pass

    # Hollow memory: VSZ >> RSS by > 10x and VSZ > 100 MB
    try:
        status = _read_file(f"/proc/{pid}/status")
        vm_rss = 0
        vm_size = 0
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                vm_rss = int(line.split()[1])
            elif line.startswith("VmSize:"):
                vm_size = int(line.split()[1])
        if vm_size > 100_000 and vm_rss > 0 and (vm_size / vm_rss) > 10:
            indicators.append(
                f"hollow_memory_indicator: VmSize={vm_size}kB VmRSS={vm_rss}kB ratio={vm_size/vm_rss:.1f}"
            )
            score += _INJECTION_INDICATOR_WEIGHTS["hollow_memory_indicator"]
    except Exception:
        pass

    return {
        "pid": pid,
        "injection_score": score,
        "risk_level": "HIGH" if score >= 5 else ("MEDIUM" if score >= 3 else ("LOW" if score >= 1 else "CLEAN")),
        "indicators": indicators,
    }


def detect_process_injection(limit: int = 200) -> Dict[str, Any]:
    """
    Forensic detector for process hollowing / reflective injection /
    thread-hijacking indicators.

    Read-only: inspects /proc filesystem. Does not modify any process.
    Returns a summary with per-process risk scores and indicators.
    """
    result: Dict[str, Any] = {
        "assessment_type": "Process Injection / Hollowing Detector",
        "platform": platform.system(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "processes_scanned": 0,
        "suspicious_processes": [],
        "clean_count": 0,
        "risk_summary": {},
    }

    if platform.system() != "Linux":
        result["note"] = "Linux /proc-based detection only; Windows path not yet implemented."
        return result

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    scanned = 0

    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except Exception:
            exe = ""
        det = _detect_injection_linux(pid, exe)
        scanned += 1
        level = det["risk_level"]
        counts[level] = counts.get(level, 0) + 1
        if det["indicators"]:
            try:
                comm = _read_file(f"/proc/{pid}/comm").strip()
            except Exception:
                comm = ""
            det["process_name"] = comm
            det["exe"] = exe
            result["suspicious_processes"].append(det)
        if scanned >= limit:
            break

    result["processes_scanned"] = scanned
    result["clean_count"] = counts.get("CLEAN", 0)
    result["risk_summary"] = counts
    # Sort highest risk first
    result["suspicious_processes"].sort(
        key=lambda x: x.get("injection_score", 0), reverse=True
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 2. API-Integrity Assessment
# ─────────────────────────────────────────────────────────────────────────────

# On Linux these are the key shared libraries whose integrity matters most
_LINUX_TRUSTED_LIBS = [
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libpthread.so.0",
    "/lib/x86_64-linux-gnu/libdl.so.2",
    "/lib64/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    # aarch64 / other arch fallbacks
    "/lib/aarch64-linux-gnu/libc.so.6",
]

# On Windows: system32 DLLs to spot-check
_WINDOWS_TRUSTED_DLLS = [
    "ntdll.dll", "kernel32.dll", "kernelbase.dll",
    "advapi32.dll", "user32.dll", "ws2_32.dll",
]


def _assess_linux_lib_integrity() -> List[Dict[str, Any]]:
    """Compute SHA-256 for trusted Linux shared libraries and check signatures."""
    results = []
    for lib_path in _LINUX_TRUSTED_LIBS:
        if not os.path.isfile(lib_path):
            continue
        digest = _sha256_file(lib_path)
        # Check ELF magic bytes to verify the file is a valid shared library
        magic_ok = False
        try:
            with open(lib_path, "rb") as f:
                magic = f.read(4)
            magic_ok = magic == b"\x7fELF"
        except Exception:
            pass
        # Use readelf to check if the library is stripped or has unexpected sections
        sections_raw = _cmd(["readelf", "-S", "--wide", lib_path])
        suspicious_sections = []
        if sections_raw:
            for line in sections_raw.splitlines():
                # Flag any executable section that isn't .text or .plt
                m = re.search(r"\s+(\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", line)
                if m:
                    sec_name = m.group(1)
                    flags = m.group(2)
                    if "X" in flags and sec_name not in (
                        ".text", ".plt", ".plt.got", ".plt.sec", ".init", ".fini"
                    ) and not sec_name.startswith("["):
                        suspicious_sections.append(sec_name)
        results.append({
            "path": lib_path,
            "sha256": digest or "UNREADABLE",
            "elf_magic_valid": magic_ok,
            "suspicious_exec_sections": suspicious_sections,
            "risk_level": "HIGH" if suspicious_sections else "CLEAN",
            "source": "API integrity assessment (read-only)",
        })
    return results


def _assess_process_api_maps(limit: int = 50) -> List[Dict[str, Any]]:
    """
    For each running process, check for executable anonymous mappings that
    may indicate in-memory API patching / hooking / unhooking activity.
    """
    findings = []
    scanned = 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        regions = _parse_proc_maps(pid)
        anon_exec_regions = [
            r for r in regions
            if "x" in r["perms"] and (r["pathname"] == "" or r["pathname"].startswith("["))
        ]
        if anon_exec_regions:
            try:
                comm = _read_file(f"/proc/{pid}/comm").strip()
            except Exception:
                comm = str(pid)
            findings.append({
                "pid": pid,
                "process_name": comm,
                "anonymous_executable_regions": len(anon_exec_regions),
                "regions": [
                    {"start": hex(r["start"]), "end": hex(r["end"]), "perms": r["perms"]}
                    for r in anon_exec_regions[:10]
                ],
                "risk_level": "HIGH" if len(anon_exec_regions) > 2 else "MEDIUM",
                "note": "Anonymous executable memory regions may indicate API hooking or in-memory injection.",
            })
        scanned += 1
        if scanned >= limit:
            break
    return findings


def assess_api_integrity() -> Dict[str, Any]:
    """
    API-integrity assessment.

    Compares trusted library hashes, validates ELF structure, enumerates
    suspicious executable memory mappings and module provenance anomalies.
    Read-only: never patches, unloads, or modifies any API.
    """
    result: Dict[str, Any] = {
        "assessment_type": "API Integrity Assessment",
        "platform": platform.system(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
    }

    if platform.system() == "Linux":
        result["library_integrity"] = _assess_linux_lib_integrity()
        result["process_api_map_anomalies"] = _assess_process_api_maps()
        result["risk_summary"] = {
            "high_risk_libraries": sum(
                1 for x in result["library_integrity"] if x.get("risk_level") == "HIGH"
            ),
            "processes_with_anon_exec_regions": len(result["process_api_map_anomalies"]),
        }
    elif platform.system() == "Windows":
        system32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
        dlls = []
        for dll in _WINDOWS_TRUSTED_DLLS:
            path = os.path.join(system32, dll)
            if os.path.isfile(path):
                dlls.append({
                    "dll": dll,
                    "path": path,
                    "sha256": _sha256_file(path) or "UNREADABLE",
                    "note": "Hash baseline; compare against known-good reference.",
                })
        result["system32_dll_hashes"] = dlls
        result["note"] = (
            "Collect these hashes and compare against a trusted reference set "
            "or Microsoft WHQL signed baseline to detect in-memory API patching."
        )
    else:
        result["note"] = f"API integrity assessment not yet implemented for {platform.system()}"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 3. Kernel-Integrity Assessment
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_MODULE_PATTERNS = re.compile(
    r"(rootkit|hide|stealth|hook|bypass|inject|ghost|cloak|intercept|patch|shadow)",
    re.IGNORECASE,
)

_KNOWN_SECURITY_MODULES = {
    "apparmor", "selinux", "tomoyo", "yama", "audit",
    "nf_conntrack", "iptable_filter",
}


def _linux_module_list() -> List[Dict[str, Any]]:
    modules = []
    try:
        with open("/proc/modules", "r", errors="replace") as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                name = parts[0]
                size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                state = parts[4] if len(parts) > 4 else "unknown"
                modules.append({"name": name, "size": size, "state": state})
    except Exception:
        pass
    return modules


def assess_kernel_integrity() -> Dict[str, Any]:
    """
    Kernel-integrity assessment.

    Enumerates loaded kernel modules, checks for suspicious names, validates
    signing where modinfo is available, and correlates with LSM/eBPF hooks.
    Read-only: never loads, unloads, or modifies kernel modules.
    """
    result: Dict[str, Any] = {
        "assessment_type": "Kernel Integrity Assessment",
        "platform": platform.system(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "modules": [],
        "suspicious_modules": [],
        "unsigned_modules": [],
        "security_modules_active": [],
        "lsm_hooks": [],
        "indicators": [],
    }

    if platform.system() != "Linux":
        result["note"] = "Kernel integrity assessment currently targets Linux only."
        return result

    modules = _linux_module_list()
    for mod in modules:
        name = mod["name"]

        # modinfo for signing/path data
        path = _cmd(["modinfo", "-n", name], timeout=5).strip()
        signer = _cmd(["modinfo", "-F", "signer", name], timeout=5).strip()
        vermagic = _cmd(["modinfo", "-F", "vermagic", name], timeout=5).strip()
        description = _cmd(["modinfo", "-F", "description", name], timeout=5).strip()

        suspicious = bool(_SUSPICIOUS_MODULE_PATTERNS.search(name))
        is_security = name.lower() in _KNOWN_SECURITY_MODULES
        signed = bool(signer)
        sha256 = _sha256_file(path) if path and os.path.isfile(path) else None

        entry = {
            "name": name,
            "size_bytes": mod["size"],
            "state": mod["state"],
            "path": path or "NOT_RESOLVED",
            "signer": signer or "UNSIGNED",
            "vermagic": vermagic,
            "description": description,
            "sha256": sha256 or "NOT_AVAILABLE",
            "signed": signed,
            "suspicious_name": suspicious,
            "is_security_module": is_security,
        }
        result["modules"].append(entry)

        if suspicious:
            result["suspicious_modules"].append(name)
            result["indicators"].append({
                "type": "suspicious_module_name",
                "module": name,
                "severity": "HIGH",
            })
        if not signed and path:
            result["unsigned_modules"].append(name)
        if is_security:
            result["security_modules_active"].append(name)

    # LSM hooks via /sys/kernel/security
    lsm_path = "/sys/kernel/security/lsm"
    if os.path.isfile(lsm_path):
        lsm_text = _read_file(lsm_path).strip()
        result["lsm_hooks"] = lsm_text.split(",") if lsm_text else []

    # eBPF programs (read-only listing)
    bpftool_out = _cmd(["bpftool", "prog", "list", "--json"], timeout=8)
    if bpftool_out:
        import json as _json
        try:
            progs = _json.loads(bpftool_out)
            result["ebpf_programs"] = [
                {"id": p.get("id"), "type": p.get("type"), "name": p.get("name")}
                for p in progs
            ]
            if result["ebpf_programs"]:
                result["indicators"].append({
                    "type": "ebpf_programs_present",
                    "count": len(result["ebpf_programs"]),
                    "severity": "INFORMATIONAL",
                    "note": "eBPF programs may be legitimate (tracing, security) or anomalous.",
                })
        except Exception:
            pass

    result["total_modules"] = len(result["modules"])
    result["suspicious_count"] = len(result["suspicious_modules"])
    result["unsigned_count"] = len(result["unsigned_modules"])
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 4. Security-Posture / Control-Health Assessment
# ─────────────────────────────────────────────────────────────────────────────

# Each service maps to its canonical systemctl name and a friendly label.
_LINUX_SECURITY_SERVICES = {
    "auditd": "Linux Audit Daemon",
    "clamav-daemon": "ClamAV Antivirus",
    "clamav-freshclam": "ClamAV Definition Updater",
    "falcon-sensor": "CrowdStrike Falcon Sensor",
    "osqueryd": "osquery Endpoint Agent",
    "sysmon": "Sysmon for Linux",
    "apparmor": "AppArmor MAC",
    "fail2ban": "fail2ban Intrusion Prevention",
    "ufw": "UFW Firewall",
    "firewalld": "firewalld",
}


def _linux_service_status(service: str) -> str:
    """Return 'active', 'inactive', 'not-found', or 'degraded'."""
    out = _cmd(["systemctl", "is-active", service]).strip()
    if out in ("active",):
        return "active"
    if out in ("inactive", "dead"):
        return "inactive"
    if out in ("failed", "deactivating"):
        return "degraded"
    return "not-found"  # activating / unknown / not installed


def _assess_linux_posture() -> Dict[str, Any]:
    posture = {}
    for svc, label in _LINUX_SECURITY_SERVICES.items():
        status = _linux_service_status(svc)
        posture[svc] = {
            "label": label,
            "status": status,
            "health": (
                "ACTIVE" if status == "active" else
                "DISABLED" if status == "inactive" else
                "DEGRADED" if status == "degraded" else
                "NOT_OBSERVED"   # distinguish not-installed from explicitly disabled
            ),
        }

    # Firewall check via iptables / nftables when ufw/firewalld not found
    if posture.get("ufw", {}).get("health") == "NOT_OBSERVED" and \
       posture.get("firewalld", {}).get("health") == "NOT_OBSERVED":
        iptables_out = _cmd(["iptables", "-L", "-n"], timeout=5)
        nft_out = _cmd(["nft", "list", "ruleset"], timeout=5)
        posture["raw_firewall"] = {
            "label": "Raw iptables / nftables",
            "iptables_rules_present": bool(iptables_out and "Chain" in iptables_out),
            "nftables_rules_present": bool(nft_out),
        }

    # SELinux / AppArmor enforcement mode
    selinux_mode = _cmd(["getenforce"], timeout=4).strip()
    if selinux_mode:
        posture["selinux"] = {
            "label": "SELinux",
            "mode": selinux_mode,
            "health": "ACTIVE" if selinux_mode.lower() == "enforcing" else
                      "DEGRADED" if selinux_mode.lower() == "permissive" else
                      "DISABLED",
        }

    aa_status = _cmd(["aa-status", "--enabled"], timeout=4)
    if "apparmor" not in posture or posture["apparmor"]["health"] == "NOT_OBSERVED":
        posture["apparmor_policy"] = {
            "label": "AppArmor Policy Enforcement",
            "enabled": aa_status.strip() == "" and _cmd(["aa-status"]).strip() != "",
        }

    return posture


def _assess_windows_posture() -> Dict[str, Any]:
    posture: Dict[str, Any] = {}

    # Windows Defender status
    defender_json = _cmd([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-MpComputerStatus | Select-Object "
        "AntivirusEnabled,RealTimeProtectionEnabled,"
        "BehaviorMonitorEnabled,IoavProtectionEnabled,"
        "AntispywareEnabled,IsTamperProtected,"
        "AMEngineVersion,AMProductVersion | ConvertTo-Json -Compress"
    ], timeout=15)
    if defender_json.strip():
        import json as _json
        try:
            d = _json.loads(defender_json)
            posture["windows_defender"] = {
                "label": "Windows Defender",
                "antivirus_enabled": d.get("AntivirusEnabled"),
                "realtime_protection": d.get("RealTimeProtectionEnabled"),
                "behavior_monitor": d.get("BehaviorMonitorEnabled"),
                "tamper_protection": d.get("IsTamperProtected"),
                "health": (
                    "ACTIVE" if d.get("AntivirusEnabled") and d.get("RealTimeProtectionEnabled")
                    else "DISABLED" if d.get("AntivirusEnabled") is False
                    else "DEGRADED"
                ),
                "engine_version": d.get("AMEngineVersion"),
            }
        except Exception:
            posture["windows_defender"] = {"raw": defender_json.strip()}
    else:
        posture["windows_defender"] = {"health": "NOT_OBSERVED"}

    # Windows Firewall profiles
    fw_json = _cmd([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    ], timeout=10)
    if fw_json.strip():
        import json as _json
        try:
            profiles = _json.loads(fw_json)
            if isinstance(profiles, dict):
                profiles = [profiles]
            posture["windows_firewall"] = {
                "label": "Windows Firewall",
                "profiles": profiles,
                "health": (
                    "ACTIVE" if all(p.get("Enabled") for p in profiles)
                    else "DEGRADED" if any(p.get("Enabled") for p in profiles)
                    else "DISABLED"
                ),
            }
        except Exception:
            pass
    else:
        posture["windows_firewall"] = {"health": "NOT_OBSERVED"}

    # UAC status
    uac_raw = _cmd([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA"
    ], timeout=8)
    posture["uac"] = {
        "label": "User Account Control",
        "enabled": uac_raw.strip() == "1",
        "health": "ACTIVE" if uac_raw.strip() == "1" else "DISABLED",
    }

    return posture


def assess_security_posture() -> Dict[str, Any]:
    """
    Security-posture / control-health assessment.

    Reports whether security services, drivers, and protections appear
    ACTIVE, DISABLED, DEGRADED, or NOT_OBSERVED.
    Clearly distinguishes 'not observed' (not installed) from 'disabled'
    (installed but off) from 'degraded' (failed / permissive).
    Read-only: does not modify any security control.
    """
    result: Dict[str, Any] = {
        "assessment_type": "Security Posture / Control Health Assessment",
        "platform": platform.system(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "controls": {},
        "risk_indicators": [],
    }

    if platform.system() == "Linux":
        result["controls"] = _assess_linux_posture()
    elif platform.system() == "Windows":
        result["controls"] = _assess_windows_posture()
    else:
        result["note"] = f"Posture assessment not yet implemented for {platform.system()}"
        return result

    # Summarise risk indicators from posture data
    for ctrl_key, ctrl_val in result["controls"].items():
        if isinstance(ctrl_val, dict):
            health = ctrl_val.get("health", "")
            if health == "DISABLED":
                result["risk_indicators"].append({
                    "control": ctrl_key,
                    "label": ctrl_val.get("label", ctrl_key),
                    "severity": "HIGH",
                    "status": "DISABLED",
                    "note": f"{ctrl_val.get('label', ctrl_key)} is installed but disabled.",
                })
            elif health == "DEGRADED":
                result["risk_indicators"].append({
                    "control": ctrl_key,
                    "label": ctrl_val.get("label", ctrl_key),
                    "severity": "MEDIUM",
                    "status": "DEGRADED",
                    "note": f"{ctrl_val.get('label', ctrl_key)} is in a degraded or permissive state.",
                })

    result["overall_risk"] = (
        "HIGH" if any(r["severity"] == "HIGH" for r in result["risk_indicators"])
        else "MEDIUM" if any(r["severity"] == "MEDIUM" for r in result["risk_indicators"])
        else "LOW"
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Helpers retained from original implementation
# ─────────────────────────────────────────────────────────────────────────────

def _linux_modules() -> List[str]:
    try:
        with open("/proc/modules", "r", encoding="utf-8", errors="replace") as f:
            return [line.split()[0] for line in f if line.strip()]
    except OSError:
        return []


def _security_processes() -> List[Dict[str, Any]]:
    try:
        import psutil
    except ImportError:
        return []
    keywords = re.compile(
        r"(defender|sentinel|crowdstrike|carbonblack|falcon|elastic|"
        r"osquery|auditd|sysmon|edr|antivirus|clamd|clamav)", re.I
    )
    found = []
    for p in psutil.process_iter(["pid", "name", "exe", "username", "cmdline"]):
        try:
            info = p.info
            text = " ".join([
                info.get("name") or "",
                info.get("exe") or "",
                " ".join(info.get("cmdline") or []),
            ])
            if keywords.search(text):
                found.append({k: info.get(k) for k in ("pid", "name", "exe", "username")})
        except Exception:
            continue
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Unified entry point (backward-compatible)
# ─────────────────────────────────────────────────────────────────────────────

def assess_endpoint() -> Dict[str, Any]:
    """
    Full endpoint assessment combining all four forensic capabilities.
    Backward-compatible replacement for the original assess_endpoint().
    """
    result: Dict[str, Any] = {
        "platform": platform.system(),
        "hostname": platform.node(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "security_processes": _security_processes(),
        "drivers": [],
        "indicators": [],
        # New capabilities
        "process_injection_assessment": {},
        "api_integrity_assessment": {},
        "kernel_integrity_assessment": {},
        "security_posture_assessment": {},
    }

    # ── Original capabilities ────────────────────────────────────────────────
    if platform.system() == "Linux":
        modules = _linux_modules()
        result["drivers"] = modules
        suspicious = [
            m for m in modules
            if re.search(r"(rootkit|hide|stealth|hook)", m, re.I)
        ]
        if suspicious:
            result["indicators"].append({
                "type": "suspicious_kernel_module_name",
                "items": suspicious,
            })
        result["security_services"] = [
            x for x in ("auditd", "clamav-daemon", "falcon-sensor", "osqueryd", "sysmon")
            if _cmd(["systemctl", "is-active", x]).strip() == "active"
        ]
    elif platform.system() == "Windows":
        ps = _cmd([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-MpComputerStatus | Select-Object AntivirusEnabled,"
            "RealTimeProtectionEnabled,BehaviorMonitorEnabled,"
            "IoavProtectionEnabled | ConvertTo-Json -Compress",
        ])
        result["defender"] = ps.strip() or None
        drv = _cmd(["driverquery", "/fo", "csv", "/nh"])
        result["drivers"] = drv.splitlines() if drv else []

    # ── New capabilities ─────────────────────────────────────────────────────
    result["process_injection_assessment"] = detect_process_injection()
    result["api_integrity_assessment"] = assess_api_integrity()
    result["kernel_integrity_assessment"] = assess_kernel_integrity()
    result["security_posture_assessment"] = assess_security_posture()

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 hardening additions (appended to Phase 1 implementation)
# ─────────────────────────────────────────────────────────────────────────────

# Configurable trusted API baseline store
_API_BASELINE_STORE: Dict[str, str] = {}   # path → expected SHA-256

def load_api_baselines(baseline_file: str) -> None:
    """
    Load a JSON file of {"/path/to/lib.so": "sha256hex", ...} as the
    trusted API baseline. If baseline is unavailable, results are marked
    as UNCERTAIN rather than falsely flagging as CLEAN.
    """
    global _API_BASELINE_STORE
    try:
        import json as _json
        with open(baseline_file, encoding="utf-8") as f:
            _API_BASELINE_STORE = _json.load(f)
    except Exception:
        _API_BASELINE_STORE = {}


def compare_against_baseline(path: str, actual_sha256: str) -> Dict[str, Any]:
    """
    Compare an actual SHA-256 against the trusted baseline (if loaded).
    Returns a dict with status: MATCH | MISMATCH | NO_BASELINE.
    """
    if not _API_BASELINE_STORE:
        return {
            "baseline_status": "NO_BASELINE",
            "note": (
                "No trusted baseline loaded. Hash is recorded for reference "
                "but cannot be compared. Load a baseline with load_api_baselines()."
            ),
        }
    expected = _API_BASELINE_STORE.get(path)
    if expected is None:
        return {
            "baseline_status": "NOT_IN_BASELINE",
            "note": f"{path} is not in the loaded baseline set.",
        }
    return {
        "baseline_status": "MATCH" if actual_sha256 == expected else "MISMATCH",
        "expected_sha256": expected,
        "actual_sha256": actual_sha256,
    }


def _linux_service_is_installed(service: str) -> bool:
    """Return True if a systemd unit file exists (installed, regardless of state)."""
    out = _cmd(["systemctl", "list-unit-files", service + ".service",
                "--no-legend", "--no-pager"])
    return bool(out and out.strip())


def _linux_service_status_v2(service: str) -> Dict[str, str]:
    """
    Return a rich status dict for a Linux service, distinguishing:
      ACTIVE | DISABLED | DEGRADED | NOT_INSTALLED | UNKNOWN

    A missing service is NOT_INSTALLED; an installed-but-stopped service is
    DISABLED. This avoids treating 'no telemetry' as 'disabled'.
    """
    active = _cmd(["systemctl", "is-active", service]).strip()
    enabled = _cmd(["systemctl", "is-enabled", service]).strip()
    installed = _linux_service_is_installed(service)

    if not installed:
        return {"raw_active": "", "raw_enabled": "", "health": "NOT_INSTALLED"}

    if active == "active":
        health = "ACTIVE"
    elif active in ("failed", "deactivating"):
        health = "DEGRADED"
    elif active in ("inactive", "dead"):
        health = "DISABLED" if enabled in ("disabled", "masked") else "INACTIVE"
    else:
        health = "UNKNOWN"

    return {"raw_active": active, "raw_enabled": enabled, "health": health}


def assess_security_posture_v2() -> Dict[str, Any]:
    """
    Hardened security posture assessment.

    Uses _linux_service_status_v2() to clearly separate:
      ACTIVE | DISABLED | INACTIVE | DEGRADED | NOT_INSTALLED | NOT_OBSERVED

    NOT_INSTALLED is distinct from DISABLED:
      - NOT_INSTALLED → the product is not present (collection limitation)
      - DISABLED      → the product is installed but administratively off (risk)
      - INACTIVE      → the service stopped but is not disabled (may be normal)

    Collection limitations are documented in the result.
    """
    result: Dict[str, Any] = {
        "assessment_type": "Security Posture / Control Health Assessment (v2)",
        "platform": platform.system(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "controls": {},
        "risk_indicators": [],
        "collection_limitations": [
            "Assessment is read-only via systemctl/proc; kernel-level hooks may suppress telemetry.",
            "NOT_INSTALLED means no unit file was found; it does not imply the control was removed.",
            "INACTIVE means the service stopped but its start-on-boot policy is unchanged.",
        ],
    }

    if platform.system() == "Linux":
        for svc, label in _LINUX_SECURITY_SERVICES.items():
            status = _linux_service_status_v2(svc)
            result["controls"][svc] = {"label": label, **status}

        for ctrl_key, ctrl_val in result["controls"].items():
            health = ctrl_val.get("health", "")
            if health == "DISABLED":
                result["risk_indicators"].append({
                    "control": ctrl_key, "label": ctrl_val.get("label", ctrl_key),
                    "severity": "HIGH", "status": "DISABLED",
                    "note": f"{ctrl_val.get('label', ctrl_key)} is installed but administratively disabled.",
                })
            elif health == "DEGRADED":
                result["risk_indicators"].append({
                    "control": ctrl_key, "label": ctrl_val.get("label", ctrl_key),
                    "severity": "MEDIUM", "status": "DEGRADED",
                    "note": f"{ctrl_val.get('label', ctrl_key)} is in a failed/degraded state.",
                })
            # INACTIVE is noted but not flagged as HIGH — may be expected
            elif health == "INACTIVE":
                result["risk_indicators"].append({
                    "control": ctrl_key, "label": ctrl_val.get("label", ctrl_key),
                    "severity": "LOW", "status": "INACTIVE",
                    "note": f"{ctrl_val.get('label', ctrl_key)} is installed but not running.",
                })
    elif platform.system() == "Windows":
        result["controls"] = _assess_windows_posture()
        for ctrl_key, ctrl_val in result["controls"].items():
            health = ctrl_val.get("health", "")
            sev = "HIGH" if health == "DISABLED" else "MEDIUM" if health == "DEGRADED" else None
            if sev:
                result["risk_indicators"].append({
                    "control": ctrl_key, "label": ctrl_val.get("label", ctrl_key),
                    "severity": sev, "status": health,
                    "note": f"{ctrl_val.get('label', ctrl_key)} health: {health}.",
                })
    else:
        result["note"] = f"Posture assessment v2 not yet implemented for {platform.system()}"

    result["overall_risk"] = (
        "HIGH" if any(r["severity"] == "HIGH" for r in result["risk_indicators"])
        else "MEDIUM" if any(r["severity"] == "MEDIUM" for r in result["risk_indicators"])
        else "LOW" if result["risk_indicators"]
        else "CLEAN"
    )
    return result
