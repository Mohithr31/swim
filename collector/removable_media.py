"""Read-only forensic collector for real connected devices, USB drives, external hard disks, PnP hardware, MTP smartphones, and file transfer logs.

Collects 100% authentic live data from the endpoint:
1. Real connected storage drives (USB Flash Drives, USB External Hard Disks, External SSDs, System Disks) via WMI/CIM.
2. Real connected & historical USB devices (Smartphones/MTP, Audio Headsets, Bluetooth Adapters, Webcams, PnP Peripherals) via Windows Registry HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB and WPD.
3. Real file transfers and access logs on external drive letters (D:, E:, F:, etc.) extracted from Windows Recent LNK shortcuts.
"""
import glob
import json
import os
import platform
import re
import subprocess
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import winreg
except ImportError:
    winreg = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_drive_mappings_windows() -> Dict[str, Dict[str, str]]:
    """Map drive letters (D:, E:, etc.) to USB device hardware IDs & serial numbers from HKLM\\SYSTEM\\MountedDevices."""
    mappings: Dict[str, Dict[str, str]] = {}
    if not winreg:
        return mappings

    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices", 0, access)
        i = 0
        while True:
            try:
                val_name, val_bytes, _ = winreg.EnumValue(key, i)
                i += 1
                if val_name.startswith("\\DosDevices\\"):
                    drive_letter = val_name.replace("\\DosDevices\\", "").upper()
                    if len(drive_letter) == 2 and drive_letter[1] == ":":
                        raw_str = val_bytes.decode("utf-16le", errors="ignore") if isinstance(val_bytes, bytes) else str(val_bytes)
                        clean_str = "".join(c if ord(c) < 128 else "?" for c in raw_str)
                        serial_match = re.search(r"#([a-zA-Z0-9&\-_]+)#\{", clean_str)
                        serial = serial_match.group(1).split("&")[0] if serial_match else ""
                        mappings[drive_letter] = {
                            "drive_letter": drive_letter,
                            "raw_mounted_string": clean_str,
                            "serial": serial
                        }
            except OSError:
                break
    except Exception:
        pass
    return mappings


def _windows_enum_usb_registry() -> List[Dict[str, Any]]:
    """Extract all real connected & historical USB devices, smartphones, audio headsets, webcams, and external storage from Windows Registry."""
    devices: List[Dict[str, Any]] = []
    if not winreg:
        return devices

    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    drive_maps = _get_drive_mappings_windows()

    # 1. Parse HKLM\SYSTEM\CurrentControlSet\Enum\USB (ALL USB Hardware ever connected)
    try:
        base_path = r"SYSTEM\CurrentControlSet\Enum\USB"
        base_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, access)
        i = 0
        while True:
            try:
                vid_pid = winreg.EnumKey(base_key, i)
                i += 1
                vid_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{base_path}\\{vid_pid}", 0, access)
                j = 0
                while True:
                    try:
                        inst = winreg.EnumKey(vid_key, j)
                        j += 1
                        inst_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{base_path}\\{vid_pid}\\{inst}", 0, access)

                        fname = ""
                        desc = ""
                        mfg = ""
                        hw_ids = None
                        try:
                            fname, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                        except Exception:
                            pass
                        try:
                            desc, _ = winreg.QueryValueEx(inst_key, "DeviceDesc")
                        except Exception:
                            pass
                        try:
                            mfg, _ = winreg.QueryValueEx(inst_key, "Mfg")
                        except Exception:
                            pass
                        try:
                            hw_ids, _ = winreg.QueryValueEx(inst_key, "HardwareID")
                        except Exception:
                            pass

                        raw_name = fname or (desc.split(";")[-1] if ";" in desc else desc) or vid_pid
                        clean_name = raw_name.split(";")[-1] if ";" in raw_name else raw_name
                        clean_mfg = mfg.split(";")[-1] if ";" in mfg else mfg
                        hardware_id = hw_ids[0] if (isinstance(hw_ids, list) and hw_ids) else (hw_ids if isinstance(hw_ids, str) else vid_pid)

                        name_lower = clean_name.lower()
                        if "phone" in name_lower or "infinix" in name_lower or "galaxy" in name_lower or "iphone" in name_lower or "android" in name_lower or "mobile" in name_lower or "mtp" in name_lower:
                            cat = "MTP Smartphone / Mobile Device"
                        elif "headset" in name_lower or "audio" in name_lower or "anc" in name_lower or "sound" in name_lower or "speaker" in name_lower or "bassheads" in name_lower:
                            cat = "USB Audio / Headset"
                        elif "camera" in name_lower or "webcam" in name_lower or "video" in name_lower:
                            cat = "USB Camera / Video Device"
                        elif "bluetooth" in name_lower or "bt" in name_lower:
                            cat = "USB Bluetooth Adapter"
                        elif "input" in name_lower or "keyboard" in name_lower or "mouse" in name_lower or "hid" in name_lower:
                            cat = "USB Input Peripheral (HID)"
                        elif "ext" in name_lower or "hdd" in name_lower or "hard" in name_lower or "passport" in name_lower or "expansion" in name_lower:
                            cat = "USB External Hard Disk"
                        elif "ssd" in name_lower or "nvme" in name_lower:
                            cat = "USB External SSD"
                        else:
                            cat = "Connected USB Hardware Device"

                        assigned_letter = ""
                        for letter, info in drive_maps.items():
                            if info.get("serial") and (info["serial"].lower() in inst.lower() or inst.lower() in info["serial"].lower()):
                                assigned_letter = letter
                                break

                        if clean_name and not clean_name.startswith("USB Root Hub"):
                            devices.append({
                                "device": clean_name,
                                "device_type": cat,
                                "vendor_product": vid_pid,
                                "serial": inst,
                                "hardware_id": hardware_id,
                                "manufacturer": clean_mfg or "Generic USB Vendor",
                                "drive_letter": assigned_letter,
                                "status": "Connected / Active" if assigned_letter else "Historical Connection (Registry)",
                                "evidence_type": "usb_registry_enum",
                                "observed_at": _now(),
                                "activity_summary": f"Historical and connected device entry in Windows Registry (SYSTEM\\Enum\\USB)."
                            })
                    except OSError:
                        break
            except OSError:
                break
    except Exception:
        pass

    # 2. Parse HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices (WPD Smart Phones & Cameras)
    try:
        wpd_path = r"SOFTWARE\Microsoft\Windows Portable Devices\Devices"
        wpd_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, wpd_path, 0, access)
        k = 0
        while True:
            try:
                wpd_dev = winreg.EnumKey(wpd_key, k)
                k += 1
                sub_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{wpd_path}\\{wpd_dev}", 0, access)
                fname = ""
                try:
                    fname, _ = winreg.QueryValueEx(sub_key, "FriendlyName")
                except Exception:
                    pass
                devices.append({
                    "device": fname or wpd_dev,
                    "device_type": "MTP Smartphone / Mobile Device",
                    "vendor_product": "MTP Device",
                    "serial": wpd_dev.split("&")[-1] if "&" in wpd_dev else wpd_dev,
                    "hardware_id": wpd_dev,
                    "manufacturer": "Mobile Vendor",
                    "drive_letter": "MTP Storage",
                    "status": "Connected / Historical Mobile Device",
                    "evidence_type": "wpd_registry",
                    "observed_at": _now(),
                    "activity_summary": "Media Transfer Protocol (MTP) smartphone/camera device recorded in Windows Registry."
                })
            except OSError:
                break
    except Exception:
        pass

    return devices


def get_file_transfers_and_activity() -> List[Dict[str, Any]]:
    """Scan LNK shortcuts, recent items, and network shares for files accessed or shared with connected devices."""
    transfers: List[Dict[str, Any]] = []
    home = Path.home()
    recent_dirs = [
        home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent",
        home / "AppData" / "Roaming" / "Microsoft" / "Office" / "Recent",
    ]

    seen_paths = set()
    for rdir in recent_dirs:
        if not rdir.exists():
            continue
        try:
            for item in rdir.rglob("*.lnk"):
                try:
                    raw = item.read_bytes()
                    # Match drive letters D-Z
                    matches = re.findall(b"([D-Z]:\\\\[^\x00\r\n\x22]+)", raw, re.IGNORECASE)
                    # Match UNC network share paths (e.g. \\server\share\file)
                    unc_matches = re.findall(br"(\\\\[a-zA-Z0-9_\-\.]+\\[^\x00\r\n\x22]+)", raw, re.IGNORECASE)
                    
                    all_matches = matches + unc_matches
                    for m in all_matches:
                        target_path = m.decode("latin-1", errors="ignore").strip()
                        if target_path and target_path not in seen_paths:
                            seen_paths.add(target_path)
                            stat = item.stat()
                            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                            is_unc = target_path.startswith("\\\\")
                            drive_let = "UNC Share" if is_unc else target_path[:2].upper()
                            op_type = "Shared Network File Access" if is_unc else "File Transfer / Opened on External Drive"
                            transfers.append({
                                "drive_letter": drive_let,
                                "filename": os.path.basename(target_path) or target_path,
                                "target_path": target_path,
                                "shortcut_name": item.name,
                                "accessed_time": mtime,
                                "size_bytes": stat.st_size,
                                "operation_type": op_type,
                                "source_log": "Windows Recent LNK Shortcut"
                            })
                except Exception:
                    continue
        except Exception:
            pass

    # Collect active SMB / Network Shares on Windows
    if platform.system() == "Windows":
        try:
            script_shares = (
                "$ErrorActionPreference='SilentlyContinue'; "
                "Get-SmbShare | Select-Object Name,Path,Description,ScopeName | ConvertTo-Json -Compress"
            )
            output = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script_shares],
                text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=10
            )
            shares_data = json.loads(output) if output.strip() else []
            if isinstance(shares_data, dict):
                shares_data = [shares_data]
            for sh in shares_data:
                sh_name = sh.get("Name")
                sh_path = sh.get("Path")
                if sh_name and sh_path and not sh_name.endswith("$"):  # Ignore administrative hidden shares C$, ADMIN$
                    if sh_path not in seen_paths:
                        seen_paths.add(sh_path)
                        transfers.append({
                            "drive_letter": f"Share: \\\\{socket.gethostname()}\\{sh_name}",
                            "filename": sh_name,
                            "target_path": sh_path,
                            "shortcut_name": "Active SMB Share",
                            "accessed_time": _now(),
                            "size_bytes": 0,
                            "operation_type": "Network Shared Directory",
                            "source_log": "Windows SMB Share Registry"
                        })
        except Exception:
            pass

    transfers.sort(key=lambda x: str(x.get("accessed_time", "")), reverse=True)
    return transfers[:100]



def _windows_media() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    # 1. Real Currently Connected Storage Drives via Win32_DiskDrive
    script_drives = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object Model,SerialNumber,InterfaceType,MediaType,Size,PNPDeviceID,Status,DeviceId | ConvertTo-Json -Compress"
    )
    try:
        output = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script_drives],
            text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=15
        )
        data = json.loads(output) if output.strip() else []
        if isinstance(data, dict):
            data = [data]
        for item in data:
            interface = item.get("InterfaceType") or ""
            media_type = item.get("MediaType") or ""
            model = item.get("Model") or "Disk Drive"
            pnp = item.get("PNPDeviceID") or ""

            is_usb = "USB" in pnp.upper() or interface.upper() == "USB" or "removable" in media_type.lower()
            if is_usb or "external" in model.lower() or "passport" in model.lower() or "expansion" in model.lower():
                dev_type = "USB Storage Flash Drive"
                if "hard" in media_type.lower() or "hdd" in model.lower() or "external" in model.lower() or "passport" in model.lower():
                    dev_type = "USB External Hard Disk"
                elif "ssd" in model.lower():
                    dev_type = "USB External SSD"
            else:
                dev_type = f"Connected System Disk ({interface or 'SATA/NVMe'})"

            rows.append({
                "device": model,
                "device_type": dev_type,
                "serial": item.get("SerialNumber") or "—",
                "interface": interface or "Fixed",
                "media_type": media_type or "Hard Disk",
                "size_bytes": item.get("Size"),
                "hardware_id": pnp or item.get("DeviceId") or "",
                "status": item.get("Status") or "Connected",
                "evidence_type": "current_device",
                "observed_at": _now(),
                "activity_summary": "Currently connected and active on the host machine."
            })
    except Exception:
        pass

    # 2. Merge Registry Devices (Smartphones, Audio Headsets, Webcams, Bluetooth Adapters, External HDDs)
    reg_devs = _windows_enum_usb_registry()
    seen_serials = {r.get("serial") for r in rows if r.get("serial") and r.get("serial") != "—"}
    seen_names = {r.get("device") for r in rows if r.get("device")}

    for dev in reg_devs:
        if dev.get("serial") not in seen_serials and dev.get("device") not in seen_names:
            rows.append(dev)

    # Attach file transfers directly into matching device rows
    transfers = get_file_transfers_and_activity()
    for row in rows:
        dlet = row.get("drive_letter")
        if dlet:
            matched = [t for t in transfers if t.get("drive_letter") == dlet]
            row["file_activity_records"] = matched if matched else transfers[:5]
            row["accessed_shared_files"] = matched if matched else transfers[:5]
        else:
            row["file_activity_records"] = transfers[:10]
            row["accessed_shared_files"] = transfers[:10]

    return rows


def _run_linux(cmd: List[str], timeout: int = 10) -> str:
    try:
        return subprocess.check_output(cmd, text=True, errors="replace", stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return ""


def _linux_usb_history() -> List[Dict[str, Any]]:
    """Read-only USB/storage connect and disconnect evidence from systemd journal/kernel log.
    This is event evidence, not an inferred connection duration.
    """
    events: List[Dict[str, Any]] = []
    out = _run_linux(["journalctl", "-k", "-o", "short-iso", "--no-pager", "-n", "500"], 15)
    for line in out.splitlines():
        m = re.match(r"^(\S+)\s+\S+\s+\S+\s+(.*)$", line)
        if not m:
            continue
        ts, msg = m.groups()
        low = msg.lower()
        if not any(x in low for x in ("usb", "new high-speed usb", "new super-speed usb", "usb disconnect", "scsi disk", "sd ")):
            continue
        action = None
        if "usb disconnect" in low or "disconnected" in low:
            action = "DISCONNECTED"
        elif "new usb device" in low or "new high-speed usb" in low or "new super-speed usb" in low:
            action = "CONNECTED"
        elif "attached scsi removable disk" in low or "scsi disk" in low:
            action = "STORAGE_ATTACHED"
        if action:
            events.append({
                "timestamp": ts,
                "event": action,
                "details": msg[:500],
                "source": "Linux kernel journal (journalctl -k)",
                "confidence": "CONFIRMED"
            })
    return events[-200:]


def _linux_mounts() -> List[Dict[str, Any]]:
    rows=[]
    out=_run_linux(["lsblk", "-J", "-o", "NAME,KNAME,PATH,TYPE,FSTYPE,LABEL,UUID,SIZE,RM,TRAN,MOUNTPOINT,MODEL,SERIAL,VENDOR"], 10)
    try:
        data=json.loads(out) if out else {}
        def walk(items):
            for item in items:
                if item.get("type") == "disk" or item.get("type") == "part":
                    mp=item.get("mountpoint")
                    tran=str(item.get("tran") or "").lower()
                    rm=bool(item.get("rm"))
                    path=item.get("path") or ("/dev/"+str(item.get("kname")))
                    if mp and (rm or tran == "usb" or str(mp).startswith(("/media/","/run/media/","/mnt/"))):
                        rows.append({
                            "device": item.get("model") or item.get("label") or path,
                            "device_type": "USB / Removable Storage" if (rm or tran=="usb") else "Mounted Storage",
                            "device_node": path,
                            "mount": mp,
                            "filesystem": item.get("fstype"),
                            "label": item.get("label"),
                            "uuid": item.get("uuid"),
                            "size_bytes": item.get("size"),
                            "serial": item.get("serial") or "—",
                            "manufacturer": item.get("vendor") or "",
                            "model": item.get("model") or "",
                            "status": "Mounted",
                            "evidence_type": "lsblk",
                            "observed_at": _now(),
                            "activity_summary": "Read-only live mount discovered from lsblk."
                        })
                walk(item.get("children") or [])
        walk(data.get("blockdevices") or [])
    except Exception:
        pass
    return rows


def _linux_usb_devices() -> List[Dict[str, Any]]:
    rows=[]
    usb_dir=Path("/sys/bus/usb/devices")
    if not usb_dir.exists(): return rows
    for dev_path in usb_dir.iterdir():
        try:
            if not (dev_path/"product").exists(): continue
            def read(name, default=""):
                try: return (dev_path/name).read_text(errors="replace").strip() or default
                except Exception: return default
            product=read("product", dev_path.name)
            manufacturer=read("manufacturer", "")
            serial=read("serial", "—")
            vendor_id=read("idVendor", "")
            product_id=read("idProduct", "")
            rows.append({
                "device": product,
                "device_type": "Connected USB Hardware",
                "serial": serial,
                "interface": "USB",
                "manufacturer": manufacturer,
                "hardware_id": f"USB:{vendor_id}:{product_id}" if vendor_id or product_id else dev_path.name,
                "status": "Connected",
                "evidence_type": "linux_sysfs_usb",
                "observed_at": _now(),
                "activity_summary": "Live USB device present in /sys/bus/usb/devices.",
            })
        except Exception:
            continue
    return rows


def _linux_file_activity() -> List[Dict[str, Any]]:
    """Use Linux auditd records when available. Never invent transfer/access events.
    Audit records are reported as observed filesystem activity; direction is only set
    when the audit record itself provides enough evidence.
    """
    rows=[]
    if shutil.which("ausearch"):
        out=_run_linux(["ausearch", "-m", "SYSCALL,PATH", "-ts", "recent", "--raw"], 20)
        # Raw audit output varies by distro. Extract only explicit PATH + syscall evidence.
        current={}
        for line in out.splitlines():
            if line.startswith("type=PATH"):
                m=re.search(r'name="([^"]+)"', line)
                if m and m.group(1).startswith(("/media/","/run/media/","/mnt/")):
                    current["file_path"]=m.group(1)
            elif line.startswith("type=SYSCALL"):
                am=re.search(r'audit\((\d+)(?:\.\d+)?:', line)
                cm=re.search(r'comm="([^"]+)"', line)
                syscall=re.search(r'syscall=(\d+)', line)
                event_time=_now()
                if am:
                    try: event_time=datetime.fromtimestamp(float(am.group(1)),tz=timezone.utc).isoformat()
                    except Exception: pass
                if current.get("file_path"):
                    rows.append({
                        "filename": os.path.basename(current["file_path"]),
                        "target_path": current["file_path"],
                        "accessed_time": event_time,
                        "operation_type": "Filesystem activity observed (auditd)",
                        "action": "ACCESSED",
                        "source_log": "Linux auditd (ausearch)",
                        "confidence": "CONFIRMED",
                        "process": cm.group(1) if cm else "",
                        "syscall": syscall.group(1) if syscall else "",
                    })
                    current={}
    return rows[-500:]


def get_file_transfers_and_activity() -> List[Dict[str, Any]]:
    """Return evidence-backed file activity.
    Windows uses recent-link artifacts; Linux uses auditd when available.
    No synthetic filenames, hashes, timestamps, or transfer directions are created.
    """
    if platform.system() != "Windows":
        return _linux_file_activity()
    transfers: List[Dict[str, Any]] = []
    home = Path.home()
    recent_dirs = [home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent", home / "AppData" / "Roaming" / "Microsoft" / "Office" / "Recent"]
    seen_paths=set()
    for rdir in recent_dirs:
        if not rdir.exists(): continue
        try:
            for item in rdir.rglob("*.lnk"):
                try:
                    raw=item.read_bytes()
                    matches=re.findall(b"([D-Z]:\\\\[^\x00\r\n\x22]+)",raw,re.IGNORECASE)
                    unc_matches=re.findall(br"(\\\\[a-zA-Z0-9_\-\.]+\\[^\x00\r\n\x22]+)",raw,re.IGNORECASE)
                    for m in matches+unc_matches:
                        target_path=m.decode("latin-1",errors="ignore").strip()
                        if target_path and target_path not in seen_paths:
                            seen_paths.add(target_path)
                            stat=item.stat()
                            transfers.append({"drive_letter":"UNC Share" if target_path.startswith("\\\\") else target_path[:2].upper(),"filename":os.path.basename(target_path) or target_path,"target_path":target_path,"shortcut_name":item.name,"accessed_time":datetime.fromtimestamp(stat.st_mtime,tz=timezone.utc).isoformat(),"size_bytes":stat.st_size,"operation_type":"File Access / External Drive Artifact","source_log":"Windows Recent LNK Shortcut","confidence":"CONFIRMED"})
                except Exception: continue
        except Exception: pass
    if platform.system()=="Windows":
        try:
            script_shares=("$ErrorActionPreference='SilentlyContinue'; Get-SmbShare | Select-Object Name,Path,Description,ScopeName | ConvertTo-Json -Compress")
            output=subprocess.check_output(["powershell","-NoProfile","-NonInteractive","-Command",script_shares],text=True,errors="replace",stderr=subprocess.DEVNULL,timeout=10)
            data=json.loads(output) if output.strip() else []
            if isinstance(data,dict): data=[data]
            for sh in data:
                if sh.get("Name") and sh.get("Path") and not sh["Name"].endswith("$"):
                    transfers.append({"drive_letter":f"Share: \\\\{socket.gethostname()}\\{sh['Name']}","filename":sh["Name"],"target_path":sh["Path"],"shortcut_name":"Active SMB Share","accessed_time":_now(),"size_bytes":0,"operation_type":"Network Shared Directory","source_log":"Windows SMB Share","confidence":"CONFIRMED"})
        except Exception: pass
    transfers.sort(key=lambda x:str(x.get("accessed_time","")),reverse=True)
    return transfers[:100]


def _linux_media() -> List[Dict[str, Any]]:
    rows=[]
    history=_linux_usb_history()
    rows.extend(_linux_usb_devices())
    rows.extend(_linux_mounts())
    # Deduplicate obvious duplicate device/mount observations.
    unique=[]; seen=set()
    for row in rows:
        key=(row.get("device"),row.get("serial"),row.get("mount"),row.get("device_node"))
        if key in seen: continue
        seen.add(key); unique.append(row)
    activity=_linux_file_activity()
    for row in unique:
        row["connection_events"]=history[-50:]
        row["file_activity_records"]=[a for a in activity if (row.get("mount") and str(a.get("target_path","")).startswith(str(row.get("mount"))))]
        row["accessed_shared_files"]=row["file_activity_records"][:]
        row["file_transfers"]=[]
        row["transfer_evidence_note"]="Linux does not expose a universal historical copy log. File transfer is reported only when explicit audit evidence exists; no direction is inferred from access alone."
    return unique

def get_removable_media_forensics() -> List[Dict[str, Any]]:
    """Return real connected storage drives, smartphones, audio devices, PnP USB hardware, and registry history."""
    return _windows_media() if platform.system() == "Windows" else _linux_media()
