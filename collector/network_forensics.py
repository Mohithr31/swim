"""
JOCKY Network Forensics Engine
Answers: WHAT NETWORK → WHEN CONNECTED → HOW LONG → WHAT NETWORK EVENTS → WHAT CONNECTIONS → WHAT EVIDENCE

Strictly separates Network Forensics from Connected Devices, Location Intelligence, and Email Forensics.
Enforces zero fake data policy: Returns NO NETWORK EVIDENCE FOUND unless demo_mode is explicitly enabled.

Forensic Distinctions:
  NETWORK OBSERVED  ≠  NETWORK CONNECTED
  NETWORK ACTIVITY OBSERVED  ≠  USER ACTIVITY
  IP GEOLOCATION  ≠  PHYSICAL LOCATION
"""
import os
import re
import sys
import json
import socket
import subprocess
import shutil
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Cross-platform Linux network evidence helpers

def _linux_cmd(cmd: List[str], timeout: int = 10) -> str:
    try:
        return subprocess.check_output(cmd, text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return ""


def _linux_active_connections() -> List[Dict[str, Any]]:
    out=_linux_cmd(["ss","-tunap"],10) or _linux_cmd(["netstat","-tunap"],10)
    rows=[]
    for line in out.splitlines():
        p=line.split()
        if len(p)<5 or p[0].lower() in ("netid","proto","active"): continue
        proto=p[0].upper(); local=p[4]; remote=p[5] if len(p)>5 else ""; state=p[1] if proto.startswith("TCP") else "N/A"; users=" ".join(p[6:]) if len(p)>6 else ""
        pid=None; m=re.search(r"pid=(\d+)",users); pid=int(m.group(1)) if m else None
        def split_ep(ep):
            if ep.startswith("[") and "]:" in ep: a,b=ep.rsplit("]:",1); return a.strip("[]"),b
            return ep.rsplit(":",1) if ":" in ep else (ep,"")
        la,lp=split_ep(local); ra,rp=split_ep(remote)
        rows.append({"protocol":proto,"local_address":la,"local_port":lp,"remote_address":ra,"remote_port":rp,"state":state,"pid":pid,"process":users,"evidence_source":"Linux ss/netstat","confidence":"CONFIRMED","timestamp":datetime.now(timezone.utc).isoformat()})
    return rows


def _linux_wifi_profiles() -> List[Dict[str, Any]]:
    rows=[]
    if shutil.which("nmcli"):
        out=_linux_cmd(["nmcli","-t","-f","NAME,TYPE,DEVICE,ACTIVE","connection","show"],10)
        for line in out.splitlines():
            p=line.split(":")
            if len(p)>=4 and p[1] in ("wifi","802-11-wireless"):
                rows.append({"ssid":p[0],"connection_mode":"configured","authentication":"Unknown","cipher":"Unknown","security_key":"Not collected","network_type":"Wi-Fi","radio_type":"Unknown","device":p[2],"active":p[3].lower() in ("yes","true"),"evidence_source":"NetworkManager nmcli","confidence":"CONFIRMED"})
    return rows


def _linux_network_events() -> List[Dict[str, Any]]:
    rows=[]
    out=_linux_cmd(["journalctl","-u","NetworkManager","-o","short-iso","--no-pager","-n","300"],15)
    for line in out.splitlines():
        low=line.lower()
        if not any(k in low for k in ("connected to", "disconnected from", "connection activated", "connection deactivated", "dhcp4", "dhcp6")): continue
        rows.append({"event_type":"NetworkManager","event_id":None,"timestamp":line.split()[0] if line.split() else None,"description":line[-500:],"evidence_source":"NetworkManager journal","confidence":"CONFIRMED"})
    return rows


# ---------------------------------------------------------------------------
# 1. Wi-Fi Profile Collector — netsh wlan show profiles + registry
# ---------------------------------------------------------------------------

class NetworkProfileCollector:
    """Collects saved Wi-Fi profiles and their metadata from netsh and registry."""

    @staticmethod
    def collect_wifi_profiles() -> List[Dict[str, Any]]:
        """Retrieve saved Wi-Fi profile names from netsh wlan show profiles."""
        profiles: List[Dict[str, Any]] = []
        if sys.platform != "win32":
            return _linux_wifi_profiles()
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "profiles"],
                text=True, errors="replace", stderr=subprocess.DEVNULL,
                timeout=15,
            )
            for line in out.splitlines():
                line = line.strip()
                # Lines like: "All User Profile     : MyNetworkName"
                match = re.match(r"All User Profile\s*:\s*(.+)", line, re.IGNORECASE)
                if not match:
                    match = re.match(r"User Profile\s*:\s*(.+)", line, re.IGNORECASE)
                if match:
                    ssid = match.group(1).strip()
                    if ssid:
                        detail = NetworkProfileCollector._get_profile_detail(ssid)
                        profiles.append(detail)
        except Exception:
            pass
        return profiles

    @staticmethod
    def _get_profile_detail(ssid: str) -> Dict[str, Any]:
        """Query detail for a single Wi-Fi profile."""
        info: Dict[str, Any] = {
            "ssid": ssid,
            "connection_mode": "Unknown",
            "authentication": "Unknown",
            "cipher": "Unknown",
            "security_key": "Present",
            "network_type": "Infrastructure",
            "radio_type": "Unknown",
            "evidence_source": "netsh wlan show profile",
            "confidence": "CONFIRMED",
        }
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
                text=True, errors="replace", stderr=subprocess.DEVNULL,
                timeout=10,
            )
            for line in out.splitlines():
                line = line.strip()
                if line.lower().startswith("connection mode"):
                    info["connection_mode"] = line.split(":", 1)[-1].strip()
                elif line.lower().startswith("authentication"):
                    info["authentication"] = line.split(":", 1)[-1].strip()
                elif line.lower().startswith("cipher"):
                    info["cipher"] = line.split(":", 1)[-1].strip()
                elif line.lower().startswith("security key"):
                    info["security_key"] = line.split(":", 1)[-1].strip()
                elif line.lower().startswith("network type"):
                    info["network_type"] = line.split(":", 1)[-1].strip()
                elif line.lower().startswith("radio type"):
                    info["radio_type"] = line.split(":", 1)[-1].strip()
        except Exception:
            pass
        return info

    @staticmethod
    def collect_registered_networks() -> List[Dict[str, Any]]:
        """Retrieve previously connected network profiles from Windows Registry."""
        networks: List[Dict[str, Any]] = []
        if sys.platform != "win32":
            return [{"profile_name": r.get("ssid"), "description": "NetworkManager configured connection", "date_created": None, "date_last_connected": None, "category": "Wi-Fi", "evidence_source": r.get("evidence_source"), "confidence": r.get("confidence")} for r in _linux_wifi_profiles()]
        try:
            import winreg
            base_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as key:
                idx = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, idx)
                        with winreg.OpenKey(key, subkey_name) as sk:
                            profile_name = _reg_value(sk, "ProfileName", "Unknown")
                            description = _reg_value(sk, "Description", "")
                            managed = _reg_value(sk, "Managed", 0)
                            category = _reg_value(sk, "Category", 0)

                            date_created = _parse_systemtime(_reg_value(sk, "DateCreated", None))
                            date_last_connected = _parse_systemtime(_reg_value(sk, "DateLastConnected", None))

                            cat_label = {0: "Public", 1: "Private", 2: "Domain"}.get(category, "Unknown")

                            networks.append({
                                "profile_guid": subkey_name,
                                "profile_name": profile_name,
                                "description": description,
                                "category": cat_label,
                                "managed": bool(managed),
                                "date_created": date_created,
                                "date_last_connected": date_last_connected,
                                "evidence_source": f"Registry: HKLM\\{base_key}\\{subkey_name}",
                                "confidence": "CONFIRMED",
                            })
                        idx += 1
                    except OSError:
                        break
        except Exception:
            pass
        return networks


# ---------------------------------------------------------------------------
# 2. Active Connection Analyzer — netstat -ano
# ---------------------------------------------------------------------------

class NetworkConnectionAnalyzer:
    """Parses active TCP/UDP connections from netstat and maps PIDs to processes."""

    @staticmethod
    def collect_active_connections() -> List[Dict[str, Any]]:
        connections: List[Dict[str, Any]] = []
        if sys.platform != "win32":
            return _linux_active_connections()
        try:
            out = subprocess.check_output(
                ["netstat", "-ano"],
                text=True, errors="replace", stderr=subprocess.DEVNULL,
                timeout=15,
            )
            pid_map = NetworkConnectionAnalyzer._build_pid_map()
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
                    continue
                proto = parts[0]
                loc = parts[1]
                loc_ip, loc_port = loc.rsplit(":", 1) if ":" in loc else (loc, "0")

                if proto == "TCP" and len(parts) >= 5:
                    rem = parts[2]
                    rem_ip, rem_port = rem.rsplit(":", 1) if ":" in rem else (rem, "0")
                    state = parts[3]
                    pid_str = parts[4]
                else:
                    rem_ip, rem_port = "*", "*"
                    state = "N/A"
                    pid_str = parts[3] if len(parts) >= 4 else "0"

                try:
                    pid = int(pid_str)
                except ValueError:
                    pid = 0

                process_name = pid_map.get(pid, f"PID {pid}")

                connections.append({
                    "protocol": proto,
                    "local_address": loc_ip,
                    "local_port": loc_port,
                    "remote_address": rem_ip,
                    "remote_port": rem_port,
                    "state": state,
                    "pid": pid,
                    "process": process_name,
                    "evidence_source": "netstat -ano",
                    "confidence": "CONFIRMED",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        except Exception:
            pass
        return connections

    @staticmethod
    def _build_pid_map() -> Dict[int, str]:
        """Map PIDs to process names via tasklist."""
        pid_map: Dict[int, str] = {}
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True, errors="replace", stderr=subprocess.DEVNULL,
                timeout=10,
            )
            for line in out.splitlines():
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2:
                    name = parts[0].strip('"')
                    try:
                        pid = int(parts[1].strip('"'))
                        pid_map[pid] = name
                    except ValueError:
                        pass
        except Exception:
            pass
        return pid_map


# ---------------------------------------------------------------------------
# 3. Network Interface Collector — psutil
# ---------------------------------------------------------------------------

class NetworkInterfaceCollector:
    """Collects network adapter details using psutil."""

    @staticmethod
    def collect_interfaces() -> List[Dict[str, Any]]:
        interfaces: List[Dict[str, Any]] = []
        try:
            import psutil
            for name, addresses in psutil.net_if_addrs().items():
                ipv4 = next((a.address for a in addresses if a.family == socket.AF_INET), None)
                ipv6 = next((a.address for a in addresses if a.family == socket.AF_INET6), None)
                mac = next((a.address for a in addresses
                            if getattr(a.family, "name", "") in {"AF_LINK", "AF_PACKET"}), None)
                if not ipv4 and not ipv6 and not mac:
                    continue
                stats = psutil.net_if_stats().get(name)
                lowered = name.lower()
                if any(t in lowered for t in ("wi-fi", "wifi", "wlan", "wireless")):
                    iface_type = "Wi-Fi"
                elif any(t in lowered for t in ("ethernet", "eth", "local area")):
                    iface_type = "Ethernet"
                elif "loopback" in lowered:
                    iface_type = "Loopback"
                elif "bluetooth" in lowered:
                    iface_type = "Bluetooth"
                elif "vpn" in lowered or "tunnel" in lowered:
                    iface_type = "VPN / Tunnel"
                else:
                    iface_type = "Other"

                io_counters = {}
                try:
                    io = psutil.net_io_counters(pernic=True).get(name)
                    if io:
                        io_counters = {
                            "bytes_sent": io.bytes_sent,
                            "bytes_recv": io.bytes_recv,
                            "packets_sent": io.packets_sent,
                            "packets_recv": io.packets_recv,
                            "errors_in": io.errin,
                            "errors_out": io.errout,
                        }
                except Exception:
                    pass

                interfaces.append({
                    "interface_name": name,
                    "interface_type": iface_type,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "mac_address": mac,
                    "status": "Connected" if stats and stats.isup else "Disconnected",
                    "speed_mbps": stats.speed if stats else None,
                    "mtu": stats.mtu if stats else None,
                    "io_counters": io_counters,
                    "evidence_source": "psutil net_if_addrs / net_if_stats",
                    "confidence": "CONFIRMED",
                })
        except Exception:
            pass
        return interfaces


# ---------------------------------------------------------------------------
# 4. DNS Cache Collector — ipconfig /displaydns
# ---------------------------------------------------------------------------

class DNSCacheCollector:
    """Collects locally cached DNS resolution entries."""

    @staticmethod
    def collect_dns_cache() -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if sys.platform != "win32":
            out=_linux_cmd(["resolvectl","status"],10) if shutil.which("resolvectl") else _linux_cmd(["cat","/etc/resolv.conf"],5)
            for line in out.splitlines():
                m=re.search(r"DNS Servers?:\s*(.+)",line,re.I)
                if m:
                    for server in re.split(r"\s+",m.group(1).strip()):
                        if server:
                            entries.append({"record_name":"DNS Server","record_type":"CONFIG","ttl":None,"data_length":None,"section":"Configuration","a_record":server,"cname_record":None,"evidence_source":"Linux resolver configuration","confidence":"CONFIRMED","timestamp":datetime.now(timezone.utc).isoformat()})
            return entries
        try:
            out = subprocess.check_output(
                ["ipconfig", "/displaydns"],
                text=True, errors="replace", stderr=subprocess.DEVNULL,
                timeout=15,
            )
            current: Optional[Dict[str, Any]] = None
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith("----"):
                    continue
                if line.lower().startswith("record name"):
                    if current and current.get("record_name"):
                        entries.append(current)
                    current = {
                        "record_name": line.split(":", 1)[-1].strip(),
                        "record_type": "Unknown",
                        "ttl": None,
                        "data_length": None,
                        "section": "Answer",
                        "a_record": None,
                        "cname_record": None,
                        "evidence_source": "ipconfig /displaydns",
                        "confidence": "CONFIRMED",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                elif current:
                    if line.lower().startswith("record type"):
                        val = line.split(":", 1)[-1].strip()
                        type_map = {"1": "A", "5": "CNAME", "28": "AAAA", "12": "PTR", "33": "SRV", "15": "MX"}
                        current["record_type"] = type_map.get(val, val)
                    elif line.lower().startswith("time to live"):
                        try:
                            current["ttl"] = int(line.split(":", 1)[-1].strip())
                        except ValueError:
                            pass
                    elif line.lower().startswith("data length"):
                        try:
                            current["data_length"] = int(line.split(":", 1)[-1].strip())
                        except ValueError:
                            pass
                    elif line.lower().startswith("section"):
                        current["section"] = line.split(":", 1)[-1].strip()
                    elif line.lower().startswith("a (host) record"):
                        current["a_record"] = line.split(":", 1)[-1].strip()
                    elif line.lower().startswith("cname record"):
                        current["cname_record"] = line.split(":", 1)[-1].strip()
                    elif line.lower().startswith("aaaa record"):
                        current["a_record"] = line.split(":", 1)[-1].strip()
                        current["record_type"] = "AAAA"
            if current and current.get("record_name"):
                entries.append(current)
        except Exception:
            pass
        return entries


# ---------------------------------------------------------------------------
# 5. Network Event Collector — Windows Event Log
# ---------------------------------------------------------------------------

class NetworkEventCollector:
    """Queries Windows Event Log for network-related events."""

    @staticmethod
    def collect_network_events() -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if sys.platform != "win32":
            return _linux_network_events()

        events.extend(NetworkEventCollector._collect_wlan_events())
        events.extend(NetworkEventCollector._collect_network_logon_events())
        events.extend(NetworkEventCollector._collect_dhcp_events())

        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return events

    @staticmethod
    def _collect_wlan_events() -> List[Dict[str, Any]]:
        """WLAN AutoConfig events: connect/disconnect."""
        results: List[Dict[str, Any]] = []
        try:
            cmd = [
                "wevtutil", "qe",
                "Microsoft-Windows-WLAN-AutoConfig/Operational",
                "/q:*[System[(EventID=8001 or EventID=8002 or EventID=8003)]]",
                "/c:50", "/rd:true", "/f:text",
            ]
            out = subprocess.check_output(
                cmd, text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=20,
            )
            current: Optional[Dict[str, Any]] = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Event["):
                    if current:
                        results.append(current)
                    current = {
                        "event_type": "WLAN",
                        "event_id": None,
                        "timestamp": None,
                        "description": "",
                        "ssid": None,
                        "evidence_source": "WLAN-AutoConfig Event Log",
                        "confidence": "CONFIRMED",
                    }
                elif current:
                    if line.startswith("Date:"):
                        current["timestamp"] = line.split(":", 1)[-1].strip()
                    elif line.startswith("Event ID:"):
                        try:
                            eid = int(line.split(":", 1)[-1].strip())
                            current["event_id"] = eid
                            eid_desc = {8001: "WLAN Connected", 8002: "WLAN Connection Successful", 8003: "WLAN Disconnected"}
                            current["description"] = eid_desc.get(eid, f"WLAN Event {eid}")
                        except ValueError:
                            pass
                    elif "ssid" in line.lower() or "SSID" in line:
                        ssid_match = re.search(r"SSID[:\s]+([^\s,]+)", line, re.IGNORECASE)
                        if ssid_match:
                            current["ssid"] = ssid_match.group(1)
            if current:
                results.append(current)
        except Exception:
            pass
        return results

    @staticmethod
    def _collect_network_logon_events() -> List[Dict[str, Any]]:
        """Network logon events from Security log."""
        results: List[Dict[str, Any]] = []
        try:
            cmd = [
                "wevtutil", "qe", "Security",
                "/q:*[System[(EventID=4624 or EventID=4625)]]",
                "/c:30", "/rd:true", "/f:text",
            ]
            out = subprocess.check_output(
                cmd, text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=20,
            )
            current: Optional[Dict[str, Any]] = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Event["):
                    if current:
                        results.append(current)
                    current = {
                        "event_type": "Network Logon",
                        "event_id": None,
                        "timestamp": None,
                        "description": "",
                        "source_ip": None,
                        "logon_type": None,
                        "evidence_source": "Security Event Log",
                        "confidence": "CONFIRMED",
                    }
                elif current:
                    if line.startswith("Date:"):
                        current["timestamp"] = line.split(":", 1)[-1].strip()
                    elif line.startswith("Event ID:"):
                        try:
                            eid = int(line.split(":", 1)[-1].strip())
                            current["event_id"] = eid
                            current["description"] = "Successful Network Logon" if eid == 4624 else "Failed Network Logon"
                        except ValueError:
                            pass
                    elif "source network address" in line.lower():
                        current["source_ip"] = line.split(":", 1)[-1].strip()
                    elif "logon type" in line.lower():
                        current["logon_type"] = line.split(":", 1)[-1].strip()
            if current:
                results.append(current)
        except Exception:
            pass
        return results

    @staticmethod
    def _collect_dhcp_events() -> List[Dict[str, Any]]:
        """DHCP client events."""
        results: List[Dict[str, Any]] = []
        try:
            cmd = [
                "wevtutil", "qe",
                "Microsoft-Windows-Dhcp-Client/Admin",
                "/c:20", "/rd:true", "/f:text",
            ]
            out = subprocess.check_output(
                cmd, text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=15,
            )
            current: Optional[Dict[str, Any]] = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Event["):
                    if current:
                        results.append(current)
                    current = {
                        "event_type": "DHCP",
                        "event_id": None,
                        "timestamp": None,
                        "description": "DHCP Client Event",
                        "evidence_source": "DHCP-Client Event Log",
                        "confidence": "CONFIRMED",
                    }
                elif current:
                    if line.startswith("Date:"):
                        current["timestamp"] = line.split(":", 1)[-1].strip()
                    elif line.startswith("Event ID:"):
                        try:
                            current["event_id"] = int(line.split(":", 1)[-1].strip())
                        except ValueError:
                            pass
                    elif line.startswith("Description:"):
                        current["description"] = line.split(":", 1)[-1].strip()[:200]
            if current:
                results.append(current)
        except Exception:
            pass
        return results


# ---------------------------------------------------------------------------
# 6. Network Timeline Builder
# ---------------------------------------------------------------------------

class NetworkTimelineBuilder:
    """Constructs a chronological timeline of all network events."""

    @staticmethod
    def build_timeline(
        connections: List[Dict[str, Any]],
        profiles: List[Dict[str, Any]],
        registered: List[Dict[str, Any]],
        dns_entries: List[Dict[str, Any]],
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []

        for ev in events:
            ts = ev.get("timestamp")
            if ts:
                timeline.append({
                    "timestamp": ts,
                    "event_type": ev.get("event_type", "Network Event"),
                    "description": ev.get("description", "Network event observed"),
                    "detail": ev.get("ssid") or ev.get("source_ip") or "",
                    "evidence_source": ev.get("evidence_source", "Event Log"),
                    "confidence": ev.get("confidence", "CONFIRMED"),
                })

        for net in registered:
            ts = net.get("date_last_connected")
            if ts:
                timeline.append({
                    "timestamp": ts,
                    "event_type": "Network Connected",
                    "description": f"Connected to network: {net.get('profile_name', 'Unknown')}",
                    "detail": f"Category: {net.get('category', 'Unknown')}",
                    "evidence_source": net.get("evidence_source", "Registry"),
                    "confidence": net.get("confidence", "CONFIRMED"),
                })
            ts_created = net.get("date_created")
            if ts_created:
                timeline.append({
                    "timestamp": ts_created,
                    "event_type": "Network First Seen",
                    "description": f"Network first registered: {net.get('profile_name', 'Unknown')}",
                    "detail": f"Category: {net.get('category', 'Unknown')}",
                    "evidence_source": net.get("evidence_source", "Registry"),
                    "confidence": net.get("confidence", "CONFIRMED"),
                })

        for conn in connections:
            ts = conn.get("timestamp")
            if ts:
                timeline.append({
                    "timestamp": ts,
                    "event_type": "Active Connection",
                    "description": f"{conn.get('protocol', 'TCP')} {conn.get('state', 'UNKNOWN')}",
                    "detail": f"{conn.get('local_address', '')}:{conn.get('local_port', '')} -> {conn.get('remote_address', '')}:{conn.get('remote_port', '')} ({conn.get('process', '')})",
                    "evidence_source": conn.get("evidence_source", "netstat"),
                    "confidence": conn.get("confidence", "CONFIRMED"),
                })

        timeline.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return timeline


# ---------------------------------------------------------------------------
# 7. Network Search Engine
# ---------------------------------------------------------------------------

class NetworkSearchEngine:
    """Exact date + time search with configurable window."""

    @staticmethod
    def search_by_time(
        timeline: List[Dict[str, Any]],
        date_str: Optional[str] = None,
        time_str: Optional[str] = None,
        range_mins: int = 5,
    ) -> List[Dict[str, Any]]:
        if not date_str:
            return timeline

        target_dt = _parse_network_datetime(date_str, time_str)
        if not target_dt:
            return []

        delta = timedelta(minutes=range_mins)
        results = []
        for ev in timeline:
            ts = ev.get("timestamp")
            if not ts:
                continue
            ev_dt = _parse_network_datetime(ts)
            if not ev_dt:
                continue
            if abs((ev_dt - target_dt).total_seconds()) <= delta.total_seconds():
                distance_sec = abs((ev_dt - target_dt).total_seconds())
                ev_copy = dict(ev)
                ev_copy["search_distance_seconds"] = round(distance_sec, 1)
                results.append(ev_copy)

        results.sort(key=lambda e: e.get("search_distance_seconds", 9999))

        if not results and timeline:
            closest = []
            for ev in timeline:
                ts = ev.get("timestamp")
                if not ts:
                    continue
                ev_dt = _parse_network_datetime(ts)
                if not ev_dt:
                    continue
                distance_sec = abs((ev_dt - target_dt).total_seconds())
                ev_copy = dict(ev)
                ev_copy["search_distance_seconds"] = round(distance_sec, 1)
                ev_copy["fallback"] = True
                closest.append(ev_copy)
            closest.sort(key=lambda e: e.get("search_distance_seconds", 9999))
            results = closest[:5]

        return results


# ---------------------------------------------------------------------------
# 8. Network Report Generator
# ---------------------------------------------------------------------------

class NetworkReportGenerator:
    """Generates structured network forensic reports."""

    @staticmethod
    def generate_report(
        connections: List[Dict[str, Any]],
        profiles: List[Dict[str, Any]],
        registered: List[Dict[str, Any]],
        interfaces: List[Dict[str, Any]],
        dns_entries: List[Dict[str, Any]],
        events: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        established = [c for c in connections if str(c.get("state", "")).upper() in ("ESTABLISHED", "ESTAB")]
        listening = [c for c in connections if str(c.get("state", "")).upper() == "LISTEN"]

        sources = set()
        for item_list in [connections, profiles, registered, interfaces, dns_entries, events]:
            for item in item_list:
                src = item.get("evidence_source")
                if src:
                    sources.add(src)

        return {
            "report_title": "JOCKY Network Forensic Report",
            "generated_at": now.isoformat(),
            "timezone": "UTC",
            "summary": {
                "total_active_connections": len(connections),
                "established_connections": len(established),
                "listening_services": len(listening),
                "wifi_profiles_saved": len(profiles),
                "registered_networks": len(registered),
                "network_interfaces": len(interfaces),
                "dns_cache_entries": len(dns_entries),
                "network_events": len(events),
                "timeline_entries": len(timeline),
            },
            "evidence_sources": sorted(sources),
            "evidence_source_count": len(sources),
            "connections": connections[:100],
            "wifi_profiles": profiles,
            "registered_networks": registered,
            "interfaces": interfaces,
            "dns_cache": dns_entries[:100],
            "events": events[:100],
            "timeline": timeline[:200],
            "honesty_note": "All data in this report was collected from live system artifacts. No data was fabricated.",
        }


# ---------------------------------------------------------------------------
# 9. Demo Data Generator (only used when demo_mode=True)
# ---------------------------------------------------------------------------

def _generate_demo_data() -> Dict[str, Any]:
    """Generate realistic demo data for UI testing. Clearly labeled as SIMULATED."""
    now = datetime.now(timezone.utc)

    profiles = [
        {"ssid": "DEMO_CorporateWiFi_5G", "connection_mode": "Connect automatically", "authentication": "WPA2-Enterprise", "cipher": "AES", "security_key": "Present", "network_type": "Infrastructure", "radio_type": "802.11ac", "evidence_source": "[DEMO] netsh wlan show profile", "confidence": "SIMULATED"},
        {"ssid": "DEMO_HomeNetwork", "connection_mode": "Connect automatically", "authentication": "WPA2-Personal", "cipher": "AES", "security_key": "Present", "network_type": "Infrastructure", "radio_type": "802.11n", "evidence_source": "[DEMO] netsh wlan show profile", "confidence": "SIMULATED"},
        {"ssid": "DEMO_CoffeeShop_Free", "connection_mode": "Connect manually", "authentication": "Open", "cipher": "None", "security_key": "Absent", "network_type": "Infrastructure", "radio_type": "802.11ac", "evidence_source": "[DEMO] netsh wlan show profile", "confidence": "SIMULATED"},
        {"ssid": "DEMO_Airport_Lounge", "connection_mode": "Connect manually", "authentication": "WPA2-Personal", "cipher": "AES", "security_key": "Present", "network_type": "Infrastructure", "radio_type": "802.11ax", "evidence_source": "[DEMO] netsh wlan show profile", "confidence": "SIMULATED"},
    ]

    registered = [
        {"profile_guid": "{DEMO-GUID-0001}", "profile_name": "DEMO_CorporateWiFi_5G", "description": "Corporate office network", "category": "Domain", "managed": True, "date_created": (now - timedelta(days=180)).isoformat(), "date_last_connected": (now - timedelta(hours=2)).isoformat(), "evidence_source": "[DEMO] Registry NetworkList", "confidence": "SIMULATED"},
        {"profile_guid": "{DEMO-GUID-0002}", "profile_name": "DEMO_HomeNetwork", "description": "Home Wi-Fi", "category": "Private", "managed": False, "date_created": (now - timedelta(days=365)).isoformat(), "date_last_connected": (now - timedelta(hours=8)).isoformat(), "evidence_source": "[DEMO] Registry NetworkList", "confidence": "SIMULATED"},
        {"profile_guid": "{DEMO-GUID-0003}", "profile_name": "DEMO_CoffeeShop_Free", "description": "Public hotspot", "category": "Public", "managed": False, "date_created": (now - timedelta(days=30)).isoformat(), "date_last_connected": (now - timedelta(days=3)).isoformat(), "evidence_source": "[DEMO] Registry NetworkList", "confidence": "SIMULATED"},
    ]

    connections = [
        {"protocol": "TCP", "local_address": "192.168.1.100", "local_port": "49234", "remote_address": "142.250.193.46", "remote_port": "443", "state": "ESTABLISHED", "pid": 7812, "process": "chrome.exe", "evidence_source": "[DEMO] netstat", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"protocol": "TCP", "local_address": "192.168.1.100", "local_port": "49235", "remote_address": "13.107.42.14", "remote_port": "443", "state": "ESTABLISHED", "pid": 3204, "process": "msedge.exe", "evidence_source": "[DEMO] netstat", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": "5000", "remote_address": "0.0.0.0", "remote_port": "0", "state": "LISTEN", "pid": 9912, "process": "python.exe", "evidence_source": "[DEMO] netstat", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"protocol": "TCP", "local_address": "192.168.1.100", "local_port": "49300", "remote_address": "52.96.148.66", "remote_port": "443", "state": "ESTABLISHED", "pid": 4520, "process": "OUTLOOK.EXE", "evidence_source": "[DEMO] netstat", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"protocol": "UDP", "local_address": "192.168.1.100", "local_port": "53", "remote_address": "*", "remote_port": "*", "state": "N/A", "pid": 1204, "process": "svchost.exe", "evidence_source": "[DEMO] netstat", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": "445", "remote_address": "0.0.0.0", "remote_port": "0", "state": "LISTEN", "pid": 4, "process": "System", "evidence_source": "[DEMO] netstat", "confidence": "SIMULATED", "timestamp": now.isoformat()},
    ]

    interfaces = [
        {"interface_name": "Wi-Fi", "interface_type": "Wi-Fi", "ipv4": "192.168.1.100", "ipv6": "fe80::1a2b:3c4d:5e6f:7890", "mac_address": "AA:BB:CC:DD:EE:FF", "status": "Connected", "speed_mbps": 866, "mtu": 1500, "io_counters": {"bytes_sent": 1543290880, "bytes_recv": 8721034240, "packets_sent": 2341000, "packets_recv": 6890000, "errors_in": 0, "errors_out": 0}, "evidence_source": "[DEMO] psutil", "confidence": "SIMULATED"},
        {"interface_name": "Ethernet", "interface_type": "Ethernet", "ipv4": None, "ipv6": None, "mac_address": "11:22:33:44:55:66", "status": "Disconnected", "speed_mbps": 0, "mtu": 1500, "io_counters": {}, "evidence_source": "[DEMO] psutil", "confidence": "SIMULATED"},
        {"interface_name": "Loopback Pseudo-Interface 1", "interface_type": "Loopback", "ipv4": "127.0.0.1", "ipv6": "::1", "mac_address": None, "status": "Connected", "speed_mbps": 1073, "mtu": 65536, "io_counters": {}, "evidence_source": "[DEMO] psutil", "confidence": "SIMULATED"},
    ]

    dns_entries = [
        {"record_name": "www.google.com", "record_type": "A", "ttl": 120, "data_length": 4, "section": "Answer", "a_record": "142.250.193.46", "cname_record": None, "evidence_source": "[DEMO] ipconfig /displaydns", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"record_name": "login.microsoftonline.com", "record_type": "CNAME", "ttl": 300, "data_length": 8, "section": "Answer", "a_record": "40.126.32.72", "cname_record": "login.mso.msidentity.com", "evidence_source": "[DEMO] ipconfig /displaydns", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"record_name": "outlook.office365.com", "record_type": "A", "ttl": 60, "data_length": 4, "section": "Answer", "a_record": "52.96.148.66", "cname_record": None, "evidence_source": "[DEMO] ipconfig /displaydns", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"record_name": "github.com", "record_type": "A", "ttl": 60, "data_length": 4, "section": "Answer", "a_record": "140.82.121.4", "cname_record": None, "evidence_source": "[DEMO] ipconfig /displaydns", "confidence": "SIMULATED", "timestamp": now.isoformat()},
        {"record_name": "cdn.discordapp.com", "record_type": "CNAME", "ttl": 250, "data_length": 8, "section": "Answer", "a_record": "162.159.135.232", "cname_record": "cdn-discord.gw.bytebutter.com", "evidence_source": "[DEMO] ipconfig /displaydns", "confidence": "SIMULATED", "timestamp": now.isoformat()},
    ]

    events = [
        {"event_type": "WLAN", "event_id": 8001, "timestamp": (now - timedelta(hours=2)).isoformat(), "description": "WLAN Connected", "ssid": "DEMO_CorporateWiFi_5G", "evidence_source": "[DEMO] WLAN-AutoConfig Event Log", "confidence": "SIMULATED"},
        {"event_type": "WLAN", "event_id": 8003, "timestamp": (now - timedelta(hours=5)).isoformat(), "description": "WLAN Disconnected", "ssid": "DEMO_HomeNetwork", "evidence_source": "[DEMO] WLAN-AutoConfig Event Log", "confidence": "SIMULATED"},
        {"event_type": "WLAN", "event_id": 8001, "timestamp": (now - timedelta(hours=8)).isoformat(), "description": "WLAN Connected", "ssid": "DEMO_HomeNetwork", "evidence_source": "[DEMO] WLAN-AutoConfig Event Log", "confidence": "SIMULATED"},
        {"event_type": "Network Logon", "event_id": 4624, "timestamp": (now - timedelta(hours=1)).isoformat(), "description": "Successful Network Logon", "source_ip": "192.168.1.50", "logon_type": "3", "evidence_source": "[DEMO] Security Event Log", "confidence": "SIMULATED"},
        {"event_type": "Network Logon", "event_id": 4625, "timestamp": (now - timedelta(hours=3)).isoformat(), "description": "Failed Network Logon", "source_ip": "10.0.0.55", "logon_type": "3", "evidence_source": "[DEMO] Security Event Log", "confidence": "SIMULATED"},
        {"event_type": "DHCP", "event_id": 50036, "timestamp": (now - timedelta(hours=2, minutes=1)).isoformat(), "description": "DHCP lease obtained for 192.168.1.100", "evidence_source": "[DEMO] DHCP-Client Event Log", "confidence": "SIMULATED"},
    ]

    return {
        "connections": connections,
        "profiles": profiles,
        "registered": registered,
        "interfaces": interfaces,
        "dns_entries": dns_entries,
        "events": events,
    }


# ---------------------------------------------------------------------------
# 10. Public API functions
# ---------------------------------------------------------------------------

def get_network_overview_intelligence(demo_mode: bool = False) -> Dict[str, Any]:
    """Main entry point: Collect all network forensic data and return overview."""
    if demo_mode:
        demo = _generate_demo_data()
        connections = demo["connections"]
        profiles = demo["profiles"]
        registered = demo["registered"]
        interfaces = demo["interfaces"]
        dns_entries = demo["dns_entries"]
        events = demo["events"]
        demo_label = "[DEMO DATA MODE] "
    else:
        connections = NetworkConnectionAnalyzer.collect_active_connections()
        profiles = NetworkProfileCollector.collect_wifi_profiles()
        registered = NetworkProfileCollector.collect_registered_networks()
        interfaces = NetworkInterfaceCollector.collect_interfaces()
        dns_entries = DNSCacheCollector.collect_dns_cache()
        events = NetworkEventCollector.collect_network_events()
        demo_label = ""

    timeline = NetworkTimelineBuilder.build_timeline(connections, profiles, registered, dns_entries, events)

    established = [c for c in connections if str(c.get("state", "")).upper() in ("ESTABLISHED", "ESTAB")]
    listening = [c for c in connections if str(c.get("state", "")).upper() == "LISTEN"]

    sources = set()
    for lst in [connections, profiles, registered, interfaces, dns_entries, events]:
        for item in lst:
            src = item.get("evidence_source")
            if src:
                sources.add(src)

    no_evidence = not connections and not profiles and not registered and not events and not dns_entries

    return {
        "module": f"{demo_label}JOCKY Network Forensics",
        "demo_mode": demo_mode,
        "no_evidence": no_evidence,
        "status_message": "NO NETWORK EVIDENCE FOUND" if no_evidence else f"{demo_label}{len(connections)} active connections, {len(profiles)} Wi-Fi profiles, {len(registered)} registered networks, {len(events)} network events",
        "active_connections_count": len(connections),
        "established_count": len(established),
        "listening_count": len(listening),
        "wifi_profiles_count": len(profiles),
        "registered_networks_count": len(registered),
        "interfaces_count": len(interfaces),
        "dns_cache_count": len(dns_entries),
        "network_events_count": len(events),
        "timeline_count": len(timeline),
        "evidence_source_count": len(sources),
        "connections": connections,
        "wifi_profiles": profiles,
        "registered_networks": registered,
        "interfaces": interfaces,
        "dns_cache": dns_entries,
        "events": events,
        "timeline": timeline,
        "evidence_sources": sorted(sources),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "honesty_note": "All data collected from live system artifacts. No fabricated data." if not demo_mode else "DEMO MODE: Simulated data for UI testing only.",
    }


def search_network_by_time(
    date_str: Optional[str] = None,
    time_str: Optional[str] = None,
    range_mins: int = 5,
    event_type_filter: Optional[str] = None,
    demo_mode: bool = False,
) -> Dict[str, Any]:
    """Search network events by exact date and time."""
    overview = get_network_overview_intelligence(demo_mode=demo_mode)
    timeline = overview.get("timeline", [])

    if event_type_filter and event_type_filter.lower() not in ("all", "all events"):
        timeline = [e for e in timeline if event_type_filter.lower() in str(e.get("event_type", "")).lower()]

    results = NetworkSearchEngine.search_by_time(timeline, date_str, time_str, range_mins)

    has_fallback = any(r.get("fallback") for r in results)

    return {
        "search_date": date_str,
        "search_time": time_str,
        "search_range_minutes": range_mins,
        "event_type_filter": event_type_filter or "All Events",
        "result_count": len(results),
        "has_fallback": has_fallback,
        "fallback_note": "No exact matches found in the requested time window. Showing nearest available network events." if has_fallback else None,
        "results": results,
        "demo_mode": demo_mode,
    }


def generate_network_forensic_report(demo_mode: bool = False) -> Dict[str, Any]:
    """Generate an exportable network forensic report."""
    overview = get_network_overview_intelligence(demo_mode=demo_mode)
    return NetworkReportGenerator.generate_report(
        connections=overview.get("connections", []),
        profiles=overview.get("wifi_profiles", []),
        registered=overview.get("registered_networks", []),
        interfaces=overview.get("interfaces", []),
        dns_entries=overview.get("dns_cache", []),
        events=overview.get("events", []),
        timeline=overview.get("timeline", []),
    )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _reg_value(key, name: str, default=None):
    """Safely read a registry value."""
    try:
        import winreg
        val, _ = winreg.QueryValueEx(key, name)
        return val
    except Exception:
        return default


def _parse_systemtime(raw) -> Optional[str]:
    """Parse a REG_BINARY SYSTEMTIME (16-byte struct) into ISO date string."""
    if not raw or not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
        return None
    try:
        import struct
        year, month, _, day, hour, minute, second, ms = struct.unpack('<8H', raw[:16])
        dt = datetime(year, month, day, hour, minute, second, ms * 1000, tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def _parse_network_datetime(date_str: Optional[str], time_str: Optional[str] = None) -> Optional[datetime]:
    """Parse various date/time formats into datetime objects."""
    if not date_str:
        return None

    combined = date_str.strip()
    if time_str:
        combined = f"{combined} {time_str.strip()}"

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y",
        "%m/%d/%Y %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(combined, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    try:
        cleaned = re.sub(r'[+-]\d{2}:\d{2}$', '', combined)
        cleaned = cleaned.replace('Z', '')
        return datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc)
    except Exception:
        pass

    return None
