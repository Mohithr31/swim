"""
Tiny Monitor — B6 Device Forensics Engine
Collects authentic physical and logical device evidence across Windows, Linux, and macOS:
USB devices, Bluetooth, network adapters, ARP table, printers, Wi-Fi profiles, and removable media.
Every record contains authentic source, collection status, and hardware identifiers.
"""
import os
import sys
import json
import shutil
import hashlib
import platform
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

try:
    import winreg
except ImportError:
    winreg = None

try:
    import psutil
except ImportError:
    psutil = None


def _to_iso(dt_or_ts) -> str:
    if not dt_or_ts:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(dt_or_ts, datetime):
        if dt_or_ts.tzinfo is None:
            dt_or_ts = dt_or_ts.replace(tzinfo=timezone.utc)
        return dt_or_ts.astimezone(timezone.utc).isoformat()
    try:
        ts = float(dt_or_ts)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return str(dt_or_ts)


class DeviceForensicsCollector:
    """B6 Device Forensics Collector."""

    def __init__(self, device_id: str = "DEV-LOCAL", case_id: str = "CAS-DEFAULT"):
        self.device_id = device_id
        self.case_id = case_id
        self.os_type = platform.system()

    def collect_all_device_evidence(self) -> Dict[str, Any]:
        """Collect all B6 device evidence categories."""
        usb = self.collect_usb_devices()
        bluetooth = self.collect_bluetooth_devices()
        adapters, network_info = self.collect_network_adapters()
        arp = self.collect_arp_table()
        wifi = self.collect_wifi_profiles()
        printers = self.collect_printers()
        removable = self.collect_removable_media()

        # Combine into unified device_artifacts table records
        unified_records: List[Dict[str, Any]] = []

        for u in usb:
            unified_records.append({
                "id": u["id"], "device_id": self.device_id, "case_id": self.case_id,
                "device_type": "USB", "device_name": u.get("name", "USB Device"),
                "vendor": u.get("vendor"), "product": u.get("product"),
                "serial_number": u.get("serial_number"), "hardware_id": u.get("hardware_id"),
                "drive_letter": u.get("drive_letter"), "interface": "USB",
                "status": u.get("status", "COLLECTED"),
                "connection_time": u.get("timestamp"), "disconnection_time": None,
                "raw_details": json.dumps(u), "source": u.get("source", "USB Subsystem"),
                "timestamp": u.get("timestamp", datetime.now(timezone.utc).isoformat())
            })

        for b in bluetooth:
            unified_records.append({
                "id": b["id"], "device_id": self.device_id, "case_id": self.case_id,
                "device_type": "Bluetooth", "device_name": b.get("name", "Bluetooth Device"),
                "vendor": b.get("vendor"), "product": b.get("product"),
                "serial_number": b.get("address"), "hardware_id": b.get("address"),
                "drive_letter": None, "interface": "Bluetooth",
                "status": b.get("status", "COLLECTED"),
                "connection_time": b.get("last_seen"), "disconnection_time": None,
                "raw_details": json.dumps(b), "source": b.get("source", "Bluetooth Subsystem"),
                "timestamp": b.get("timestamp", datetime.now(timezone.utc).isoformat())
            })

        for a in adapters:
            unified_records.append({
                "id": a["id"], "device_id": self.device_id, "case_id": self.case_id,
                "device_type": "Network Adapter", "device_name": a.get("name", "Adapter"),
                "vendor": None, "product": a.get("description"),
                "serial_number": a.get("mac_address"), "hardware_id": a.get("mac_address"),
                "drive_letter": None, "interface": a.get("type", "Ethernet"),
                "status": a.get("status", "COLLECTED"),
                "connection_time": None, "disconnection_time": None,
                "raw_details": json.dumps(a), "source": a.get("source", "Network Subsystem"),
                "timestamp": a.get("timestamp", datetime.now(timezone.utc).isoformat())
            })

        for r in removable:
            unified_records.append({
                "id": r["id"], "device_id": self.device_id, "case_id": self.case_id,
                "device_type": "Removable Media", "device_name": r.get("name", "Drive"),
                "vendor": r.get("vendor"), "product": r.get("filesystem"),
                "serial_number": None, "hardware_id": r.get("mountpoint"),
                "drive_letter": r.get("device"), "interface": "Storage",
                "status": r.get("status", "COLLECTED"),
                "connection_time": None, "disconnection_time": None,
                "raw_details": json.dumps(r), "source": r.get("source", "Disk Subsystem"),
                "timestamp": r.get("timestamp", datetime.now(timezone.utc).isoformat())
            })

        for p in printers:
            unified_records.append({
                "id": p["id"], "device_id": self.device_id, "case_id": self.case_id,
                "device_type": "Printer", "device_name": p.get("name", "Printer"),
                "vendor": p.get("driver"), "product": p.get("port"),
                "serial_number": None, "hardware_id": p.get("port"),
                "drive_letter": None, "interface": "Print Spooler",
                "status": p.get("status", "COLLECTED"),
                "connection_time": None, "disconnection_time": None,
                "raw_details": json.dumps(p), "source": p.get("source", "Spooler"),
                "timestamp": p.get("timestamp", datetime.now(timezone.utc).isoformat())
            })

        total_devs = len(unified_records)
        overall_status = "COLLECTED" if total_devs > 0 else "NO_EVIDENCE_FOUND"

        return {
            "status": overall_status,
            "usb": usb,
            "bluetooth": bluetooth,
            "adapters": adapters,
            "network": network_info,
            "arp": arp,
            "wifi": wifi,
            "printers": printers,
            "removable_media": removable,
            "unified_records": unified_records,
            "total_count": total_devs
        }

    def collect_usb_devices(self) -> List[Dict[str, Any]]:
        """Collect connected and historical USB devices."""
        usb_list: List[Dict[str, Any]] = []

        if self.os_type == "Windows":
            # 1. Registry USBSTOR (Historical USB drives)
            if winreg:
                usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path, 0, winreg.KEY_READ)
                    n_sub = winreg.QueryInfoKey(key)[0]
                    for i in range(n_sub):
                        device_group = winreg.EnumKey(key, i)
                        try:
                            dev_key = winreg.OpenKey(key, device_group, 0, winreg.KEY_READ)
                            n_instances = winreg.QueryInfoKey(dev_key)[0]
                            for j in range(n_instances):
                                serial = winreg.EnumKey(dev_key, j)
                                try:
                                    inst_key = winreg.OpenKey(dev_key, serial, 0, winreg.KEY_READ)
                                    friendly_name = "USB Device"
                                    hardware_id = ""
                                    try:
                                        friendly_name, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                                    except Exception:
                                        pass
                                    try:
                                        hardware_id, _ = winreg.QueryValueEx(inst_key, "HardwareID")
                                        if isinstance(hardware_id, list):
                                            hardware_id = ", ".join(hardware_id)
                                    except Exception:
                                        pass
                                    winreg.CloseKey(inst_key)

                                    uid = f"USB-{hashlib.md5(f'{device_group}_{serial}'.encode()).hexdigest()[:10]}"
                                    usb_list.append({
                                        "id": uid,
                                        "name": friendly_name or device_group,
                                        "vendor": device_group.split("&")[1] if "&" in device_group else device_group,
                                        "product": friendly_name,
                                        "serial_number": serial,
                                        "hardware_id": hardware_id,
                                        "drive_letter": None,
                                        "source": f"HKLM\\{usbstor_path}\\{device_group}",
                                        "status": "COLLECTED",
                                        "timestamp": datetime.now(timezone.utc).isoformat()
                                    })
                                except Exception:
                                    pass
                            winreg.CloseKey(dev_key)
                        except Exception:
                            pass
                    winreg.CloseKey(key)
                except Exception:
                    pass

            # 2. PnP USB Devices via PowerShell or WMI
            try:
                ps_cmd = 'Get-PnpDevice -Class USB -Status OK | Select-Object FriendlyName, InstanceId, Status | ConvertTo-Json -Compress'
                out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_cmd], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=8)
                if out.strip():
                    data = json.loads(out)
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        fn = item.get("FriendlyName")
                        iid = item.get("InstanceId") or ""
                        if fn and not any(u.get("hardware_id") == iid for u in usb_list):
                            uid = f"USB-LIVE-{hashlib.md5(iid.encode()).hexdigest()[:10]}"
                            usb_list.append({
                                "id": uid,
                                "name": fn,
                                "vendor": "USB PnP",
                                "product": fn,
                                "serial_number": iid.split("\\")[-1] if "\\" in iid else iid,
                                "hardware_id": iid,
                                "drive_letter": None,
                                "source": "Windows PnP Subsystem (Live)",
                                "status": "COLLECTED",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
            except Exception:
                pass

        elif self.os_type == "Linux":
            if shutil.which("lsusb"):
                try:
                    out = subprocess.check_output(["lsusb"], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=5)
                    for line in out.splitlines():
                        if "ID" in line:
                            parts = line.split("ID", 1)[1].strip()
                            vid_pid = parts.split()[0]
                            desc = parts[len(vid_pid):].strip()
                            uid = f"USB-LNX-{hashlib.md5(line.encode()).hexdigest()[:10]}"
                            usb_list.append({
                                "id": uid,
                                "name": desc or vid_pid,
                                "vendor": vid_pid.split(":")[0] if ":" in vid_pid else "",
                                "product": desc,
                                "serial_number": vid_pid,
                                "hardware_id": line.strip(),
                                "drive_letter": None,
                                "source": "Linux lsusb",
                                "status": "COLLECTED",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                except Exception:
                    pass

        elif self.os_type == "Darwin":
            try:
                out = subprocess.check_output(["system_profiler", "SPUSBDataType", "-json"], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=8)
                data = json.loads(out)
                items = data.get("SPUSBDataType", [])
                for it in items:
                    name = it.get("_name", "USB Device")
                    uid = f"USB-MAC-{hashlib.md5(name.encode()).hexdigest()[:10]}"
                    usb_list.append({
                        "id": uid,
                        "name": name,
                        "vendor": it.get("manufacturer", "Apple / Vendor"),
                        "product": name,
                        "serial_number": it.get("serial_num", "N/A"),
                        "hardware_id": it.get("location_id", "N/A"),
                        "drive_letter": None,
                        "source": "macOS system_profiler SPUSBDataType",
                        "status": "COLLECTED",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
            except Exception:
                pass

        return usb_list

    def collect_bluetooth_devices(self) -> List[Dict[str, Any]]:
        """Collect Bluetooth paired and connected devices."""
        bt_list: List[Dict[str, Any]] = []

        if self.os_type == "Windows":
            # Registry Bluetooth Devices
            if winreg:
                bth_path = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bth_path, 0, winreg.KEY_READ)
                    n_sub = winreg.QueryInfoKey(key)[0]
                    for i in range(n_sub):
                        addr = winreg.EnumKey(key, i)
                        try:
                            dev_k = winreg.OpenKey(key, addr, 0, winreg.KEY_READ)
                            name_val = "Bluetooth Device"
                            try:
                                raw_name, _ = winreg.QueryValueEx(dev_k, "Name")
                                if isinstance(raw_name, bytes):
                                    name_val = raw_name.decode("utf-8", errors="ignore").rstrip("\x00")
                                else:
                                    name_val = str(raw_name)
                            except Exception:
                                pass
                            winreg.CloseKey(dev_k)

                            bid = f"BT-{hashlib.md5(addr.encode()).hexdigest()[:10]}"
                            bt_list.append({
                                "id": bid,
                                "name": name_val or f"BT Device ({addr})",
                                "address": addr,
                                "vendor": "Bluetooth",
                                "product": name_val,
                                "source": f"HKLM\\{bth_path}\\{addr}",
                                "status": "COLLECTED",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                        except Exception:
                            pass
                    winreg.CloseKey(key)
                except Exception:
                    pass

            # PnP Bluetooth Devices
            try:
                ps_cmd = 'Get-PnpDevice -Class Bluetooth -Status OK | Select-Object FriendlyName, InstanceId | ConvertTo-Json -Compress'
                out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_cmd], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=5)
                if out.strip():
                    data = json.loads(out)
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        fn = item.get("FriendlyName")
                        iid = item.get("InstanceId") or ""
                        if fn and not any(b.get("name") == fn for b in bt_list):
                            bid = f"BT-LIVE-{hashlib.md5(iid.encode()).hexdigest()[:10]}"
                            bt_list.append({
                                "id": bid,
                                "name": fn,
                                "address": iid.split("_")[-1] if "_" in iid else iid,
                                "vendor": "Bluetooth Adapter / Device",
                                "product": fn,
                                "source": "Windows PnP Bluetooth Subsystem",
                                "status": "COLLECTED",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
            except Exception:
                pass

        elif self.os_type == "Linux":
            if shutil.which("bluetoothctl"):
                try:
                    out = subprocess.check_output(["bluetoothctl", "devices"], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=5)
                    for line in out.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0] == "Device":
                            addr = parts[1]
                            name = " ".join(parts[2:])
                            bid = f"BT-LNX-{hashlib.md5(addr.encode()).hexdigest()[:10]}"
                            bt_list.append({
                                "id": bid,
                                "name": name,
                                "address": addr,
                                "vendor": "Bluetooth Device",
                                "product": name,
                                "source": "Linux bluetoothctl",
                                "status": "COLLECTED",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                except Exception:
                    pass

        return bt_list

    def collect_network_adapters(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Collect active network interfaces, MAC addresses, IPs, and stats."""
        adapters: List[Dict[str, Any]] = []
        network_info: Dict[str, Any] = {"interfaces": []}

        if psutil:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for iface_name, addr_list in addrs.items():
                mac = None
                ipv4 = None
                ipv6 = None
                for addr in addr_list:
                    if addr.family == psutil.AF_LINK or getattr(addr, "family", None) == -1:  # MAC
                        mac = addr.address
                    elif getattr(addr, "family", None) == 2:  # AF_INET
                        ipv4 = addr.address
                    elif getattr(addr, "family", None) == 23 or getattr(addr, "family", None) == 30:  # AF_INET6
                        ipv6 = addr.address

                if_stat = stats.get(iface_name)
                is_up = if_stat.isup if if_stat else False
                speed = if_stat.speed if if_stat else 0

                aid = f"NET-{hashlib.md5(iface_name.encode()).hexdigest()[:10]}"
                rec = {
                    "id": aid,
                    "name": iface_name,
                    "description": f"{iface_name} ({speed} Mbps)" if speed else iface_name,
                    "mac_address": mac or "N/A",
                    "ipv4": ipv4 or "N/A",
                    "ipv6": ipv6 or "N/A",
                    "is_up": is_up,
                    "speed_mbps": speed,
                    "type": "Wireless" if "wi-fi" in iface_name.lower() or "wlan" in iface_name.lower() else "Ethernet / Loopback",
                    "source": "psutil network interfaces",
                    "status": "COLLECTED",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                adapters.append(rec)
                network_info["interfaces"].append(rec)

        return adapters, network_info

    def collect_arp_table(self) -> List[Dict[str, Any]]:
        """Extract ARP neighbor cache."""
        arp_entries: List[Dict[str, Any]] = []
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=5)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    atype = parts[2]
                    # Simple IPv4 check
                    if ip.count(".") == 3 and any(c.isdigit() for c in ip):
                        arpid = f"ARP-{hashlib.md5(f'{ip}_{mac}'.encode()).hexdigest()[:10]}"
                        arp_entries.append({
                            "id": arpid,
                            "ip_address": ip,
                            "mac_address": mac,
                            "type": atype,
                            "source": "System ARP Cache (arp -a)",
                            "status": "COLLECTED",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
        except Exception:
            pass
        return arp_entries

    def collect_wifi_profiles(self) -> List[Dict[str, Any]]:
        """Collect Wi-Fi configured profiles (WITHOUT plaintext security keys)."""
        wifi_profiles: List[Dict[str, Any]] = []

        if self.os_type == "Windows":
            try:
                out = subprocess.check_output(["netsh", "wlan", "show", "profiles"], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=5)
                profile_names = []
                for line in out.splitlines():
                    if "All User Profile" in line or "User Profile" in line:
                        pname = line.split(":", 1)[1].strip()
                        if pname:
                            profile_names.append(pname)

                for pname in profile_names:
                    # Query metadata for profile without extracting key
                    wid = f"WIFI-{hashlib.md5(pname.encode()).hexdigest()[:10]}"
                    wifi_profiles.append({
                        "id": wid,
                        "ssid": pname,
                        "connection_mode": "Configured / Historical",
                        "authentication": "WPA2 / WPA3-Personal",
                        "security_key": "Protected (Not Extracted)",
                        "source": "Windows netsh wlan profiles",
                        "status": "COLLECTED",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
            except Exception:
                pass

        elif self.os_type == "Linux":
            if shutil.which("nmcli"):
                try:
                    out = subprocess.check_output(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=5)
                    for line in out.splitlines():
                        parts = line.split(":")
                        if len(parts) >= 2 and parts[1] in ("wifi", "802-11-wireless"):
                            pname = parts[0]
                            wid = f"WIFI-LNX-{hashlib.md5(pname.encode()).hexdigest()[:10]}"
                            wifi_profiles.append({
                                "id": wid,
                                "ssid": pname,
                                "connection_mode": "Configured",
                                "authentication": "WPA / WPA2",
                                "security_key": "Protected",
                                "source": "NetworkManager nmcli",
                                "status": "COLLECTED",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                except Exception:
                    pass

        return wifi_profiles

    def collect_printers(self) -> List[Dict[str, Any]]:
        """Collect local and network printers."""
        printers: List[Dict[str, Any]] = []

        if self.os_type == "Windows":
            try:
                ps_cmd = 'Get-CimInstance Win32_Printer | Select-Object Name, PortName, DriverName | ConvertTo-Json -Compress'
                out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_cmd], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=5)
                if out.strip():
                    data = json.loads(out)
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        pname = item.get("Name") or "Printer"
                        pid = f"PRT-{hashlib.md5(pname.encode()).hexdigest()[:10]}"
                        printers.append({
                            "id": pid,
                            "name": pname,
                            "port": item.get("PortName") or "N/A",
                            "driver": item.get("DriverName") or "N/A",
                            "source": "Win32_Printer",
                            "status": "COLLECTED",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
            except Exception:
                pass

        elif self.os_type in ("Linux", "Darwin"):
            if shutil.which("lpstat"):
                try:
                    out = subprocess.check_output(["lpstat", "-p"], text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=5)
                    for line in out.splitlines():
                        if line.startswith("printer"):
                            pname = line.split()[1]
                            pid = f"PRT-LNX-{hashlib.md5(pname.encode()).hexdigest()[:10]}"
                            printers.append({
                                "id": pid,
                                "name": pname,
                                "port": "CUPS Local Spool",
                                "driver": "CUPS Driver",
                                "source": "lpstat -p",
                                "status": "COLLECTED",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                except Exception:
                    pass

        return printers

    def collect_removable_media(self) -> List[Dict[str, Any]]:
        """Collect mounted storage volumes and removable disks."""
        media_list: List[Dict[str, Any]] = []

        if psutil:
            try:
                parts = psutil.disk_partitions(all=True)
                for p in parts:
                    opts = p.opts.lower()
                    is_removable = "removable" in opts or "cdrom" in opts or (self.os_type != "Windows" and ("/media" in p.mountpoint or "/Volumes" in p.mountpoint))

                    total_bytes = 0
                    free_bytes = 0
                    try:
                        usage = psutil.disk_usage(p.mountpoint)
                        total_bytes = usage.total
                        free_bytes = usage.free
                    except Exception:
                        pass

                    rid = f"DISK-{hashlib.md5(f'{p.device}_{p.mountpoint}'.encode()).hexdigest()[:10]}"
                    media_list.append({
                        "id": rid,
                        "name": f"Volume {p.device}",
                        "device": p.device,
                        "mountpoint": p.mountpoint,
                        "filesystem": p.fstype,
                        "options": p.opts,
                        "is_removable": is_removable,
                        "total_gb": round(total_bytes / (1024**3), 2) if total_bytes else 0,
                        "free_gb": round(free_bytes / (1024**3), 2) if free_bytes else 0,
                        "source": "psutil disk partitions",
                        "status": "COLLECTED",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
            except Exception:
                pass

        return media_list
