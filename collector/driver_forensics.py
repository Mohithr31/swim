"""
JOCKY Driver Forensics & BYOVD Vulnerability Assessment Module

Enumerates kernel drivers (.sys / .ko files), analyses signatures, SHA-256
hashes, and matches against an expanded known-vulnerable-driver catalogue.
Generates a full risk/remediation workflow report.

STRICTLY READ-ONLY ASSESSMENT.
No driver loading, unloading, exploitation, or modification is performed.
"""
import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Expanded BYOVD Vulnerability Catalogue
# ─────────────────────────────────────────────────────────────────────────────
# Sources: loldrivers.io, MSRC, NVD — READ-ONLY reference data only.
# This catalogue is used for DETECTION, not exploitation.

KNOWN_VULNERABLE_DRIVERS: Dict[str, Dict[str, Any]] = {
    # Windows .sys drivers
    "rtcore64.sys": {
        "cve": "CVE-2021-21551",
        "description": "MSI Afterburner driver — arbitrary kernel memory read/write via IOCTL.",
        "risk": "CRITICAL",
        "vendor": "Micro-Star International",
        "remediation": "Uninstall MSI Afterburner or update to a patched version. Block via WDAC policy.",
        "loldrivers_id": "rtcore64",
        "mitre_technique": "T1068",
    },
    "gdrv.sys": {
        "cve": "CVE-2018-19320",
        "description": "GIGABYTE GDRV driver — arbitrary physical memory read/write.",
        "risk": "CRITICAL",
        "vendor": "GIGABYTE",
        "remediation": "Remove GIGABYTE APP Center. Add driver hash to WDAC block list.",
        "loldrivers_id": "gdrv",
        "mitre_technique": "T1068",
    },
    "procexp152.sys": {
        "cve": "CVE-2022-21882",
        "description": "Process Explorer driver — abused for kernel object tampering.",
        "risk": "HIGH",
        "vendor": "Sysinternals / Microsoft",
        "remediation": "Block the unsigned/older variant via WDAC. Prefer signed Sysinternals builds.",
        "loldrivers_id": "procexp152",
        "mitre_technique": "T1543",
    },
    "atsiv.sys": {
        "cve": "CVE-2007-5633",
        "description": "Atsiv driver — abused for unsigned driver loading bypass.",
        "risk": "CRITICAL",
        "vendor": "Unknown/Untrusted",
        "remediation": "Block via WDAC and add to Microsoft blocklist. Enable HVCI.",
        "loldrivers_id": "atsiv",
        "mitre_technique": "T1014",
    },
    "ene.sys": {
        "cve": "CVE-2020-12440",
        "description": "ENE RGB driver — arbitrary physical memory mapping via MmMapIoSpace.",
        "risk": "CRITICAL",
        "vendor": "ENE Technology",
        "remediation": "Remove ENE RGB software. Block driver hash via WDAC.",
        "loldrivers_id": "ene",
        "mitre_technique": "T1068",
    },
    "dbutil_2_3.sys": {
        "cve": "CVE-2021-21551",
        "description": "Dell DBUtil 2.3 — privilege escalation via arbitrary memory write.",
        "risk": "CRITICAL",
        "vendor": "Dell",
        "remediation": "Apply Dell DSA-2021-088. Run Dell Security Advisory tool.",
        "loldrivers_id": "dbutil_2_3",
        "mitre_technique": "T1068",
    },
    "spydrvr.sys": {
        "cve": "CVE-2019-19469",
        "description": "SpeedFan driver — kernel read/write via crafted IOCTL.",
        "risk": "HIGH",
        "vendor": "Alfredo Milani Comparetti",
        "remediation": "Remove SpeedFan. Block driver via WDAC.",
        "loldrivers_id": "spydrvr",
        "mitre_technique": "T1068",
    },
    "cpuz141.sys": {
        "cve": "CVE-2017-15302",
        "description": "CPU-Z driver — memory read/write via IOCTL interface.",
        "risk": "HIGH",
        "vendor": "CPUID",
        "remediation": "Update CPU-Z to patched version. Block legacy driver hash.",
        "loldrivers_id": "cpuz141",
        "mitre_technique": "T1068",
    },
    "amifldrv64.sys": {
        "cve": "CVE-2018-18688",
        "description": "AMI flasher driver — arbitrary physical memory read/write.",
        "risk": "CRITICAL",
        "vendor": "American Megatrends Inc.",
        "remediation": "Block via WDAC and HVCI. Restrict firmware update tools.",
        "loldrivers_id": "amifldrv64",
        "mitre_technique": "T1068",
    },
    "aswarpot.sys": {
        "cve": "CVE-2022-26522",
        "description": "Avast Anti-Rootkit driver — heap-based buffer overflow, local privilege escalation.",
        "risk": "HIGH",
        "vendor": "Avast Software",
        "remediation": "Update Avast to version 22.1.2504+. Monitor for old driver presence.",
        "loldrivers_id": "aswarpot",
        "mitre_technique": "T1068",
    },
    "physmem.sys": {
        "cve": "CVE-2020-12928",
        "description": "Razer kernel driver — arbitrary physical memory access.",
        "risk": "CRITICAL",
        "vendor": "Razer USA",
        "remediation": "Update Razer Synapse. Block via WDAC.",
        "loldrivers_id": "physmem",
        "mitre_technique": "T1068",
    },
    # Linux kernel modules (reference heuristic — name-based flagging)
    "rkbreaker.ko": {
        "cve": "N/A",
        "description": "Generic rootkit driver name pattern.",
        "risk": "CRITICAL",
        "vendor": "Unknown",
        "remediation": "Investigate immediately. Run rkhunter and chkrootkit. Consider system re-image.",
        "loldrivers_id": None,
        "mitre_technique": "T1014",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Hash helpers
# ─────────────────────────────────────────────────────────────────────────────

def calculate_sha256(filepath: str) -> str:
    if not os.path.exists(filepath):
        return ""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


_sha256_file = calculate_sha256  # alias


# ─────────────────────────────────────────────────────────────────────────────
# Linux module metadata
# ─────────────────────────────────────────────────────────────────────────────

def _linux_module_metadata(mod_name: str):
    """Resolve a loaded Linux module to its on-disk path using modinfo (read-only)."""
    path = signer = vermagic = description = ""
    for flag, attr in [("-n", "path"), ("-F signer", "signer"),
                        ("-F vermagic", "vermagic"), ("-F description", "description")]:
        try:
            val = subprocess.check_output(
                ["modinfo"] + flag.split() + [mod_name],
                text=True, stderr=subprocess.DEVNULL, timeout=5
            ).strip()
            locals()[attr] = val
            if attr == "path":
                path = val
            elif attr == "signer":
                signer = val
            elif attr == "vermagic":
                vermagic = val
            elif attr == "description":
                description = val
        except Exception:
            pass
    return path, signer, vermagic, description


# ─────────────────────────────────────────────────────────────────────────────
# Remediation generator
# ─────────────────────────────────────────────────────────────────────────────

def _build_remediation_plan(vuln_drivers: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate a structured remediation plan for all detected vulnerable drivers."""
    if not vuln_drivers:
        return {"required": False, "actions": []}

    actions = []
    for drv in vuln_drivers:
        cve = drv.get("cve", "N/A")
        name = drv.get("driver_name", "unknown")
        remediation = drv.get("remediation", "Review vendor advisory.")
        risk = drv.get("risk_level", "UNKNOWN")
        actions.append({
            "priority": "IMMEDIATE" if risk == "CRITICAL" else "HIGH" if risk == "HIGH" else "MEDIUM",
            "driver": name,
            "cve": cve,
            "action": remediation,
            "mitre_technique": drv.get("mitre_technique", "N/A"),
            "wdac_block_recommended": risk in ("CRITICAL", "HIGH"),
            "hvci_recommended": risk == "CRITICAL",
        })
    # Sort by priority
    order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    actions.sort(key=lambda x: order.get(x["priority"], 9))

    return {
        "required": True,
        "total_vulnerable": len(vuln_drivers),
        "immediate_action_count": sum(1 for a in actions if a["priority"] == "IMMEDIATE"),
        "actions": actions,
        "general_recommendations": [
            "Enable Hypervisor-Protected Code Integrity (HVCI) on Windows to block vulnerable drivers.",
            "Deploy Windows Defender Application Control (WDAC) policy with Microsoft's recommended block list.",
            "Review https://www.loldrivers.io for the current vulnerable driver catalogue.",
            "Restrict who can load kernel modules (Linux: lockdown=confidentiality or integrity).",
            "Monitor /proc/modules and Windows Event ID 7045 for new driver load events.",
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main collection functions
# ─────────────────────────────────────────────────────────────────────────────

def get_driver_forensics() -> List[Dict[str, Any]]:
    """
    Collect read-only kernel-module / driver forensic metadata.

    Linux: reads /proc/modules and resolves module files via modinfo.
    Windows: inventories System32\\drivers\\ .sys files.
    Returns a list of driver records with risk assessment.
    """
    if sys.platform != "win32":
        return _get_linux_drivers()
    return _get_windows_drivers()


def _get_linux_drivers() -> List[Dict[str, Any]]:
    drivers = []
    try:
        with open("/proc/modules", errors="replace") as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                mod_name = parts[0]
                mod_size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                mod_state = parts[4] if len(parts) > 4 else "unknown"

                path, signer, vermagic, description = _linux_module_metadata(mod_name)
                digest = _sha256_file(path) if path and os.path.isfile(path) else ""
                fname_lower = (
                    os.path.basename(path).lower() if path
                    else mod_name.lower() + ".ko"
                )
                vuln_info = KNOWN_VULNERABLE_DRIVERS.get(fname_lower)
                is_vulnerable = vuln_info is not None

                signature_status = (
                    "SIGNED" if signer else
                    "UNSIGNED / NO SIGNER" if path else
                    "NOT_VERIFIED"
                )

                drivers.append({
                    "driver_name": mod_name,
                    "path": path or f"/proc/modules ({mod_name})",
                    "sha256": digest or ("NOT_AVAILABLE" if path else "NOT_RESOLVED"),
                    "signer": signer or ("Unknown" if path else "NOT_RESOLVED"),
                    "signature_status": signature_status,
                    "loaded": mod_state == "Live",
                    "service_name": mod_name,
                    "is_vulnerable": is_vulnerable,
                    "cve": vuln_info["cve"] if is_vulnerable else "N/A",
                    "description": vuln_info["description"] if is_vulnerable else (description or "Loaded Linux kernel module"),
                    "risk_level": vuln_info["risk"] if is_vulnerable else "CLEAN",
                    "remediation": vuln_info.get("remediation") if is_vulnerable else None,
                    "mitre_technique": vuln_info.get("mitre_technique") if is_vulnerable else None,
                    "size_bytes": mod_size,
                    "vermagic": vermagic,
                    "source": "/proc/modules + modinfo",
                    "assessment_timestamp": datetime.now(timezone.utc).isoformat(),
                })
    except Exception:
        pass
    return drivers


def _get_windows_drivers() -> List[Dict[str, Any]]:
    system_root = os.environ.get("SystemRoot") or "C:\\Windows"
    drivers_dir = os.path.join(system_root, "System32", "drivers")
    drivers_telemetry = []
    if not os.path.exists(drivers_dir):
        return drivers_telemetry
    try:
        driver_files = [f for f in os.listdir(drivers_dir) if f.lower().endswith(".sys")][:100]
        for fname in driver_files:
            fpath = os.path.join(drivers_dir, fname)
            file_hash = calculate_sha256(fpath)
            fname_lower = fname.lower()
            vuln_info = KNOWN_VULNERABLE_DRIVERS.get(fname_lower)
            is_vulnerable = vuln_info is not None
            drivers_telemetry.append({
                "driver_name": fname,
                "path": fpath,
                "sha256": file_hash or "N/A",
                "signer": "NOT_COLLECTED",
                "signature_status": "NOT_VERIFIED",
                "loaded": False,
                "service_name": fname.split(".")[0],
                "is_vulnerable": is_vulnerable,
                "cve": vuln_info["cve"] if is_vulnerable else "N/A",
                "description": vuln_info["description"] if is_vulnerable else "Standard System Driver",
                "risk_level": vuln_info["risk"] if is_vulnerable else "CLEAN",
                "remediation": vuln_info.get("remediation") if is_vulnerable else None,
                "mitre_technique": vuln_info.get("mitre_technique") if is_vulnerable else None,
                "source": "System32\\drivers inventory",
                "assessment_timestamp": datetime.now(timezone.utc).isoformat(),
            })
    except Exception:
        pass
    return drivers_telemetry


def get_byovd_risk_report() -> Dict[str, Any]:
    """
    Full BYOVD vulnerability risk workflow report.

    Inventories all drivers, matches against the vulnerability catalogue,
    assesses risk levels, and generates a structured remediation plan.
    Read-only: never loads, exploits, or modifies drivers.
    """
    drivers = get_driver_forensics()
    vulnerable = [d for d in drivers if d.get("is_vulnerable")]
    unsigned = [
        d for d in drivers
        if d.get("signature_status") in ("UNSIGNED / NO SIGNER", "NOT_VERIFIED")
        and not d.get("is_vulnerable")
    ]
    critical = [d for d in vulnerable if d.get("risk_level") == "CRITICAL"]
    high = [d for d in vulnerable if d.get("risk_level") == "HIGH"]

    return {
        "assessment_type": "BYOVD Vulnerability Risk Assessment",
        "platform": sys.platform,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "summary": {
            "total_drivers_scanned": len(drivers),
            "vulnerable_drivers_found": len(vulnerable),
            "critical_risk_count": len(critical),
            "high_risk_count": len(high),
            "unsigned_drivers_count": len(unsigned),
            "overall_risk": (
                "CRITICAL" if critical else
                "HIGH" if high else
                "MEDIUM" if vulnerable else
                "LOW"
            ),
        },
        "vulnerable_drivers": vulnerable,
        "unsigned_drivers_sample": unsigned[:20],
        "remediation_plan": _build_remediation_plan(vulnerable),
        "catalogue_version": f"{len(KNOWN_VULNERABLE_DRIVERS)} entries",
        "catalogue_reference": "https://www.loldrivers.io",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — expanded BYOVD catalogue additions
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_VULNERABLE_DRIVERS.update({
    # Additional catalogue entries with version-aware notes and signer info
    "elbycdio.sys": {
        "cve": "CVE-2020-12928",
        "description": "ElbyCDIO driver — arbitrary memory read/write; used in AV bypass chains.",
        "risk": "HIGH",
        "vendor": "Elaborate Bytes AG",
        "signer": "Elaborate Bytes AG",
        "remediation": "Uninstall CloneDVD/CloneCD. Block via WDAC.",
        "loldrivers_id": "elbycdio",
        "mitre_technique": "T1068",
        "affected_versions": "<= 6.0.0.2",
    },
    "fiddrv.sys": {
        "cve": "CVE-2020-15368",
        "description": "FIDDRV — arbitrary physical memory r/w; found in various OEM tools.",
        "risk": "CRITICAL",
        "vendor": "Fintek",
        "signer": "Fintek Microelectronics",
        "remediation": "Block driver via WDAC block list. Enable HVCI.",
        "loldrivers_id": "fiddrv",
        "mitre_technique": "T1068",
        "affected_versions": "all known versions",
    },
    "mhyprot2.sys": {
        "cve": "CVE-2020-36603",
        "description": "MiHoYo anti-cheat driver — arbitrary kernel memory ops from user-mode.",
        "risk": "CRITICAL",
        "vendor": "miHoYo Co., Ltd.",
        "signer": "miHoYo Co., Ltd.",
        "remediation": "Uninstall Genshin Impact / MiHoYo software. Block via WDAC.",
        "loldrivers_id": "mhyprot2",
        "mitre_technique": "T1068",
        "affected_versions": "<= 1.0.0.0",
    },
    "ntiolib.sys": {
        "cve": "CVE-2019-12280",
        "description": "NTIOLib — OEM driver allowing arbitrary MSR and physical memory access.",
        "risk": "CRITICAL",
        "vendor": "MSI / various OEMs",
        "signer": "Micro-Star International",
        "remediation": "Remove MSI Control Center / related OEM tools. Block via WDAC.",
        "loldrivers_id": "ntiolib",
        "mitre_technique": "T1068",
        "affected_versions": "all known versions",
    },
    "winrh64.sys": {
        "cve": "CVE-2019-18845",
        "description": "WinRing0 driver — r/w to IO port, MSR and physical memory.",
        "risk": "CRITICAL",
        "vendor": "OpenLibSys.org",
        "signer": "OpenLibSys.org",
        "remediation": "Remove software using WinRing0. Block via WDAC.",
        "loldrivers_id": "winrh64",
        "mitre_technique": "T1068",
        "affected_versions": "<= 1.0.1.1",
    },
    "pcd.sys": {
        "cve": "CVE-2021-3438",
        "description": "HP SSDT driver — buffer overflow allows privilege escalation.",
        "risk": "HIGH",
        "vendor": "HP Inc.",
        "signer": "HP Inc.",
        "remediation": "Apply HP advisory HPSBPI03748. Update HP support tools.",
        "loldrivers_id": "pcd",
        "mitre_technique": "T1068",
        "affected_versions": "<= 15.0",
    },
    "daxin.sys": {
        "cve": "N/A",
        "description": "Daxin rootkit driver — stealthy kernel backdoor observed in nation-state campaigns.",
        "risk": "CRITICAL",
        "vendor": "Unknown / Threat Actor",
        "signer": "UNSIGNED",
        "remediation": "Treat as active compromise. Isolate host, initiate IR, re-image.",
        "loldrivers_id": None,
        "mitre_technique": "T1014",
        "affected_versions": "N/A",
    },
    "kprocesshacker.sys": {
        "cve": "N/A",
        "description": "Process Hacker kernel driver — process/memory manipulation from user-mode.",
        "risk": "HIGH",
        "vendor": "wj32",
        "signer": "wj32",
        "remediation": "Block via WDAC. Process Hacker is a legitimate tool but abused for EDR blind.",
        "loldrivers_id": "kprocesshacker",
        "mitre_technique": "T1543",
        "affected_versions": "<= 2.39",
    },
})


def get_driver_provenance(driver_name: str) -> Dict[str, Any]:
    """
    Return provenance metadata for a driver name from the catalogue.
    Includes signer, affected_versions, loldrivers reference.
    """
    entry = KNOWN_VULNERABLE_DRIVERS.get(driver_name.lower(), {})
    if not entry:
        return {"driver_name": driver_name, "in_catalogue": False}
    return {
        "driver_name": driver_name,
        "in_catalogue": True,
        "cve": entry.get("cve"),
        "vendor": entry.get("vendor"),
        "signer": entry.get("signer", "N/A"),
        "affected_versions": entry.get("affected_versions", "see advisory"),
        "risk": entry.get("risk"),
        "loldrivers_id": entry.get("loldrivers_id"),
        "loldrivers_url": (
            f"https://www.loldrivers.io/drivers/{entry['loldrivers_id']}"
            if entry.get("loldrivers_id") else None
        ),
        "mitre_technique": entry.get("mitre_technique"),
        "remediation": entry.get("remediation"),
    }
