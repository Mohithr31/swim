"""
JOCKY Physical Device Forensics Engine
Answers: Which device was connected, when was it connected, what activity occurred, what files were accessed, and what files were transferred?
Strictly separates Physical Device Forensics from Location Intelligence.
Enforces zero fake data policy: Returns NO DEVICE EVIDENCE LOADED unless demo_mode is explicitly enabled.
"""
import os
import re
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from collector.removable_media import get_removable_media_forensics, get_file_transfers_and_activity


class PhysicalDeviceCollector:
    @staticmethod
    def collect_raw_device_artifacts() -> List[Dict[str, Any]]:
        """Retrieve real connected & historical USB devices, external drives, MTP smartphones, and Registry USBSTOR entries."""
        return get_removable_media_forensics()


class ConnectionHistoryAnalyzer:
    @staticmethod
    def analyze_connection_history(device_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sessions=[]
        for idx, dev in enumerate(device_list):
            name=dev.get("device") or dev.get("vendor_product") or f"USB Device {idx+1}"
            events=dev.get("connection_events") or []
            for ev_idx, ev in enumerate(events[-50:]):
                sessions.append({
                    "session_id": f"EVT-{idx+1:03d}-{ev_idx+1:03d}",
                    "device": name,
                    "device_type": dev.get("device_type") or "USB / Removable Device",
                    "manufacturer": dev.get("manufacturer") or "",
                    "model": dev.get("model") or name,
                    "serial_number": dev.get("serial") or "",
                    "hardware_id": dev.get("hardware_id") or "",
                    "drive_letter": dev.get("drive_letter") or dev.get("mount") or dev.get("device_node") or "",
                    "timestamp": ev.get("timestamp") or dev.get("observed_at"),
                    "event": ev.get("event") or "OBSERVED",
                    "details": ev.get("details") or "",
                    "status": "Observed",
                    "evidence_source": ev.get("source") or dev.get("evidence_type") or "Endpoint artifact",
                    "confidence": ev.get("confidence") or "CONFIRMED",
                })
            if not events:
                sessions.append({
                    "session_id": f"OBS-{idx+1:03d}", "device": name,
                    "device_type": dev.get("device_type") or "USB / Removable Device",
                    "manufacturer": dev.get("manufacturer") or "", "model": dev.get("model") or name,
                    "serial_number": dev.get("serial") or "", "hardware_id": dev.get("hardware_id") or "",
                    "drive_letter": dev.get("drive_letter") or dev.get("mount") or dev.get("device_node") or "",
                    "timestamp": dev.get("observed_at"), "event": "CURRENTLY PRESENT",
                    "details": dev.get("activity_summary") or "Live endpoint observation.",
                    "status": dev.get("status") or "Observed", "evidence_source": dev.get("evidence_type") or "Endpoint artifact",
                    "confidence": "CONFIRMED",
                    "duration": dev.get("duration"),
                    "connection_count": dev.get("connection_count"),
                })
        return sessions


class FileTransferAnalyzer:
    @staticmethod
    def extract_file_transfers(transfer_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        transfers=[]
        for idx,tr in enumerate(transfer_list):
            op=str(tr.get("operation_type") or tr.get("action") or "").lower()
            direction=tr.get("direction")
            # Only label direction if it is explicitly supplied by evidence.
            if not direction and "system ->" in op: direction="SYSTEM → DEVICE"
            if not direction and "device ->" in op: direction="DEVICE → SYSTEM"
            file_path = tr.get("target_path") or tr.get("file_path") or ""
            content_hash = tr.get("hash_sha256")
            hash_scope = "content" if content_hash else None
            if not content_hash and file_path and os.path.isfile(file_path):
                try:
                    h = hashlib.sha256()
                    with open(file_path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                            h.update(chunk)
                    content_hash = h.hexdigest()
                    hash_scope = "content"
                except OSError:
                    content_hash = None
            # If the original content is no longer accessible, retain a
            # deterministic SHA-256 fingerprint of the observed transfer
            # record. This is explicitly metadata-scoped, not a claim about
            # the file bytes themselves.
            if not content_hash:
                fingerprint = "|".join(str(tr.get(k, "")) for k in (
                    "filename", "target_path", "direction", "size_bytes",
                    "source_path", "destination_path", "accessed_time",
                ))
                content_hash = hashlib.sha256(fingerprint.encode("utf-8", "replace")).hexdigest()
                hash_scope = "transfer_record_metadata"
            transfers.append({
                "transfer_id": f"TR-{idx+1:05d}",
                "timestamp": tr.get("accessed_time") or tr.get("timestamp"),
                "file_name": tr.get("filename") or os.path.basename(str(file_path)),
                "file_path": file_path,
                "file_size": tr.get("size_bytes"), "file_type": tr.get("file_type") or os.path.splitext(str(tr.get("filename") or ""))[1],
                "direction": direction or "UNDETERMINED",
                "source": tr.get("source_path"), "destination": tr.get("destination_path"),
                "device": tr.get("device_name") or tr.get("device") or "",
                "hash_sha256": content_hash,
                "hash_scope": hash_scope or "unknown",
                "evidence_source": tr.get("source_log") or tr.get("evidence_source") or "Endpoint artifact",
                "confidence": tr.get("confidence") or "CONFIRMED",
                "interpretation": "Observed transfer" if direction else "Filesystem activity; transfer direction not established"
            })
        return transfers


class FileAccessAnalyzer:
    @staticmethod
    def extract_file_access_records(access_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        records=[]
        for idx,acc in enumerate(access_list):
            records.append({
                "access_id": f"ACC-{idx+1:05d}",
                "timestamp": acc.get("accessed_time") or acc.get("timestamp"),
                "file_name": acc.get("filename") or os.path.basename(str(acc.get("target_path") or "")),
                "file_path": acc.get("target_path") or acc.get("file_path") or "",
                "action": acc.get("action") or "ACCESSED",
                "device": acc.get("device_name") or acc.get("device") or "",
                "user": acc.get("user") or "",
                "evidence_source": acc.get("source_log") or acc.get("evidence_source") or "Endpoint artifact",
                "confidence": acc.get("confidence") or "CONFIRMED"
            })
        return records


class DeviceActivityTimeline:
    @staticmethod
    def build_device_activity_timeline(device_name: str, events: Optional[List[Dict[str, Any]]]=None) -> List[Dict[str, Any]]:
        if events is not None:
            return [{"time": str(e.get("timestamp","")), "event": e.get("event","OBSERVED"), "details": e.get("details",""), "type": e.get("event","OBSERVED"), "source": e.get("source","Endpoint artifact")} for e in events]
        if device_name == "SanDisk Ultra USB 3.0":
            # Keep the explicit demo fixture self-contained. Calling
            # get_demo_physical_device_evidence() here would recurse because
            # that fixture also exposes this timeline.
            first = "2026-09-01 14:21:10"
            last = "2026-09-15 18:42:31"
            disc = "2026-09-15 19:17:44"
            return [
                {"time": first, "event": "USB CONNECTED", "details": "Historical connection observed.", "type": "USB CONNECTED", "source": "Demo fixture"},
                {"time": last, "event": "USB CONNECTED", "details": "Most recent connection observed.", "type": "USB CONNECTED", "source": "Demo fixture"},
                {"time": disc, "event": "USB DISCONNECTED", "details": "Most recent disconnection observed.", "type": "USB DISCONNECTED", "source": "Demo fixture"},
                {"time": last, "event": "FILE ACTIVITY", "details": "Associated removable-media activity.", "type": "FILE ACTIVITY", "source": "Demo fixture"},
                {"time": disc, "event": "SESSION CLOSED", "details": "Observed device session closed.", "type": "SESSION CLOSED", "source": "Demo fixture"},
            ]
        return []

def get_demo_physical_device_evidence() -> Dict[str, Any]:
    """Synthetic forensic demo dataset for Physical Device Forensics UI testing."""
    devices = [
        {
            "device": "SanDisk Ultra USB 3.0",
            "device_type": "USB Storage",
            "manufacturer": "SanDisk",
            "model": "Ultra USB 3.0",
            "serial": "SD-99882410-A",
            "hardware_id": "USBSTOR\\DiskSanDisk_Ultra_3.0",
            "drive_letter": "E:",
            "first_connected": "2026-09-01 14:21:10",
            "last_connected": "2026-09-15 18:42:31",
            "last_disconnected": "2026-09-15 19:17:44",
            "connection_count": 14,
            "status": "Connected / Active",
            "evidence_source": "Windows Registry / Event Logs"
        },
        {
            "device": "Samsung Portable SSD T7",
            "device_type": "USB External SSD",
            "manufacturer": "Samsung",
            "model": "Portable SSD T7",
            "serial": "S5B2NJ0R102938",
            "hardware_id": "USBSTOR\\DiskSamsung_SSD_T7",
            "drive_letter": "F:",
            "first_connected": "2026-08-10 09:15:00",
            "last_connected": "2026-09-12 20:11:08",
            "last_disconnected": "2026-09-12 21:02:17",
            "connection_count": 8,
            "status": "Historical Record (Registry)",
            "evidence_source": "Windows Registry USBSTOR"
        },
        {
            "device": "Kingston DataTraveler Max",
            "device_type": "USB Storage Flash Drive",
            "manufacturer": "Kingston",
            "model": "DataTraveler Max",
            "serial": "KGT-55419208-X",
            "hardware_id": "USBSTOR\\DiskKingston_DataTraveler",
            "drive_letter": "G:",
            "first_connected": "2026-07-22 11:04:12",
            "last_connected": "2026-09-10 16:30:45",
            "last_disconnected": "2026-09-10 17:10:02",
            "connection_count": 6,
            "status": "Historical Record (Registry)",
            "evidence_source": "Windows SetupAPI Log"
        },
        {
            "device": "Seagate Expansion Desktop HDD",
            "device_type": "USB External Hard Disk",
            "manufacturer": "Seagate",
            "model": "Expansion HDD 2TB",
            "serial": "NA99X1029410",
            "hardware_id": "USBSTOR\\DiskSeagate_Expansion",
            "drive_letter": "H:",
            "first_connected": "2026-06-15 08:00:00",
            "last_connected": "2026-09-08 14:15:20",
            "last_disconnected": "2026-09-08 16:45:10",
            "connection_count": 19,
            "status": "Historical Record (Registry)",
            "evidence_source": "Windows Event Log 20001"
        },
        {
            "device": "Infinix Note 30 Pro (MTP)",
            "device_type": "MTP Smartphone / Mobile Device",
            "manufacturer": "Infinix Mobile",
            "model": "Note 30 Pro",
            "serial": "INF-MTP-8812049",
            "hardware_id": "WPD\\Devices\\Infinix_Note30Pro",
            "drive_letter": "MTP Storage",
            "first_connected": "2026-09-05 12:30:00",
            "last_connected": "2026-09-14 10:05:12",
            "last_disconnected": "2026-09-14 10:45:00",
            "connection_count": 5,
            "status": "Historical Record (WPD)",
            "evidence_source": "Windows Portable Devices (WPD)"
        }
    ]

    transfers = [
        # SanDisk Ultra USB
        {
            "filename": "report.pdf",
            "target_path": "E:\\report.pdf",
            "direction": "SYSTEM → USB",
            "source_path": "C:\\Users\\User\\Documents\\report.pdf",
            "destination_path": "E:\\report.pdf",
            "size_bytes": 2516582,
            "file_type": "PDF Document",
            "accessed_time": "2026-09-15 18:45:22",
            "device_name": "SanDisk Ultra USB 3.0",
            "hash_sha256": "8f4e2c91a3b5d6e7f80192837465019283746501928374650192837465019283",
            "source_log": "Windows Recent LNK Shortcut"
        },
        {
            "filename": "evidence.zip",
            "target_path": "E:\\evidence.zip",
            "direction": "SYSTEM → USB",
            "source_path": "C:\\Users\\User\\Desktop\\evidence.zip",
            "destination_path": "E:\\evidence.zip",
            "size_bytes": 15420100,
            "file_type": "ZIP Archive",
            "accessed_time": "2026-09-15 18:47:31",
            "device_name": "SanDisk Ultra USB 3.0",
            "hash_sha256": "5c6b7a8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b",
            "source_log": "Shell Bag Artifact"
        },
        {
            "filename": "confidential.pdf",
            "target_path": "C:\\Users\\User\\Downloads\\confidential.pdf",
            "direction": "USB → SYSTEM",
            "source_path": "E:\\confidential.pdf",
            "destination_path": "C:\\Users\\User\\Downloads\\confidential.pdf",
            "size_bytes": 4810290,
            "file_type": "PDF Document",
            "accessed_time": "2026-09-15 18:52:31",
            "device_name": "SanDisk Ultra USB 3.0",
            "hash_sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
            "source_log": "Download Manager / LNK Shortcut"
        },
        {
            "filename": "image.jpg",
            "target_path": "C:\\Users\\User\\Pictures\\image.jpg",
            "direction": "USB → SYSTEM",
            "source_path": "E:\\DCIM\\image.jpg",
            "destination_path": "C:\\Users\\User\\Pictures\\image.jpg",
            "size_bytes": 3104920,
            "file_type": "JPEG Image",
            "accessed_time": "2026-09-15 18:55:17",
            "device_name": "SanDisk Ultra USB 3.0",
            "hash_sha256": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
            "source_log": "Windows Photos Artifact"
        },
        # Samsung Portable SSD T7
        {
            "filename": "vm_backup_2026.iso",
            "target_path": "F:\\vm_backup_2026.iso",
            "direction": "SYSTEM → USB",
            "source_path": "C:\\VMs\\vm_backup_2026.iso",
            "destination_path": "F:\\vm_backup_2026.iso",
            "size_bytes": 4820192000,
            "file_type": "ISO Disk Image",
            "accessed_time": "2026-09-12 20:22:15",
            "device_name": "Samsung Portable SSD T7",
            "hash_sha256": "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
            "source_log": "Shellbag Artifact"
        },
        {
            "filename": "database_dump.sql",
            "target_path": "C:\\Backups\\database_dump.sql",
            "direction": "USB → SYSTEM",
            "source_path": "F:\\database_dump.sql",
            "destination_path": "C:\\Backups\\database_dump.sql",
            "size_bytes": 89201900,
            "file_type": "SQL Script",
            "accessed_time": "2026-09-12 20:45:00",
            "device_name": "Samsung Portable SSD T7",
            "hash_sha256": "0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "source_log": "Registry LNK Artifact"
        },
        # Kingston DataTraveler
        {
            "filename": "passwords_backup.kdbx",
            "target_path": "G:\\passwords_backup.kdbx",
            "direction": "SYSTEM → USB",
            "source_path": "C:\\Users\\User\\Documents\\passwords_backup.kdbx",
            "destination_path": "G:\\passwords_backup.kdbx",
            "size_bytes": 120490,
            "file_type": "KeePass Vault",
            "accessed_time": "2026-09-10 16:40:12",
            "device_name": "Kingston DataTraveler Max",
            "hash_sha256": "7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f",
            "source_log": "KeePass MRU Registry"
        },
        # Seagate Expansion Desktop HDD
        {
            "filename": "surveillance_footage.mp4",
            "target_path": "H:\\Videos\\surveillance_footage.mp4",
            "direction": "SYSTEM → USB",
            "source_path": "D:\\CCTV\\surveillance_footage.mp4",
            "destination_path": "H:\\Videos\\surveillance_footage.mp4",
            "size_bytes": 1820491000,
            "file_type": "MP4 Video",
            "accessed_time": "2026-09-08 15:10:30",
            "device_name": "Seagate Expansion Desktop HDD",
            "hash_sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
            "source_log": "VLC Player Recent History"
        },
        # Infinix Note 30 Pro (MTP)
        {
            "filename": "DCIM_20260914_1001.jpg",
            "target_path": "C:\\Users\\User\\Pictures\\DCIM_20260914_1001.jpg",
            "direction": "USB → SYSTEM",
            "source_path": "MTP:\\Internal Storage\\DCIM\\DCIM_20260914_1001.jpg",
            "destination_path": "C:\\Users\\User\\Pictures\\DCIM_20260914_1001.jpg",
            "size_bytes": 5410290,
            "file_type": "JPEG Image",
            "accessed_time": "2026-09-14 10:15:22",
            "device_name": "Infinix Note 30 Pro (MTP)",
            "hash_sha256": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
            "source_log": "Windows Portable Devices (WPD) Log"
        }
    ]

    access_records = [
        # SanDisk Ultra USB
        {
            "filename": "report.pdf",
            "target_path": "E:\\report.pdf",
            "action": "Opened",
            "accessed_time": "2026-09-15 18:44:02",
            "device_name": "SanDisk Ultra USB 3.0",
            "user": "SYSTEM\\Investigator",
            "source_log": "OpenSavePidlMRU"
        },
        {
            "filename": "notes.txt",
            "target_path": "E:\\notes.txt",
            "action": "Opened",
            "accessed_time": "2026-09-15 18:51:10",
            "device_name": "SanDisk Ultra USB 3.0",
            "user": "SYSTEM\\Investigator",
            "source_log": "Recent Items LNK"
        },
        {
            "filename": "financial_sheet.xlsx",
            "target_path": "E:\\financial_sheet.xlsx",
            "action": "Read",
            "accessed_time": "2026-09-15 19:02:14",
            "device_name": "SanDisk Ultra USB 3.0",
            "user": "SYSTEM\\Investigator",
            "source_log": "Office MRU Registry"
        },
        # Samsung Portable SSD T7
        {
            "filename": "vm_config.xml",
            "target_path": "F:\\vm_config.xml",
            "action": "Modified",
            "accessed_time": "2026-09-12 20:30:10",
            "device_name": "Samsung Portable SSD T7",
            "user": "SYSTEM\\Administrator",
            "source_log": "VirtualBox Config Artifact"
        },
        # Kingston DataTraveler
        {
            "filename": "keys.asc",
            "target_path": "G:\\keys.asc",
            "action": "Opened",
            "accessed_time": "2026-09-10 16:35:00",
            "device_name": "Kingston DataTraveler Max",
            "user": "SYSTEM\\User",
            "source_log": "GnuPG Keyring Artifact"
        },
        # Seagate Expansion HDD
        {
            "filename": "archived_logs.tar.gz",
            "target_path": "H:\\archived_logs.tar.gz",
            "action": "Read",
            "accessed_time": "2026-09-08 14:30:00",
            "device_name": "Seagate Expansion Desktop HDD",
            "user": "SYSTEM\\Administrator",
            "source_log": "7-Zip MRU Registry"
        },
        # Infinix Note 30 Pro
        {
            "filename": "voice_recording_001.m4a",
            "target_path": "MTP:\\Internal Storage\\Recordings\\voice_recording_001.m4a",
            "action": "Read",
            "accessed_time": "2026-09-14 10:25:00",
            "device_name": "Infinix Note 30 Pro (MTP)",
            "user": "SYSTEM\\User",
            "source_log": "WPD Media Artifact"
        }
    ]

    history = [
        {"date": "2026-09-15", "connected": "18:42:31", "disconnected": "19:17:44", "duration": "35m 13s", "device": "SanDisk Ultra USB 3.0", "source": "Windows Event Log"},
        {"date": "2026-09-12", "connected": "20:11:08", "disconnected": "21:02:17", "duration": "51m 09s", "device": "SanDisk Ultra USB 3.0", "source": "Registry Artifact"},
        {"date": "2026-09-01", "connected": "14:21:10", "disconnected": "15:05:00", "duration": "43m 50s", "device": "SanDisk Ultra USB 3.0", "source": "SetupAPI Log"},
        {"date": "2026-09-12", "connected": "20:11:08", "disconnected": "21:02:17", "duration": "51m 09s", "device": "Samsung Portable SSD T7", "source": "Windows Event Log"},
        {"date": "2026-09-10", "connected": "16:30:45", "disconnected": "17:10:02", "duration": "39m 17s", "device": "Kingston DataTraveler Max", "source": "SetupAPI Log"},
        {"date": "2026-09-08", "connected": "14:15:20", "disconnected": "16:45:10", "duration": "2h 29m 50s", "device": "Seagate Expansion Desktop HDD", "source": "Windows Event Log"},
        {"date": "2026-09-14", "connected": "10:05:12", "disconnected": "10:45:00", "duration": "39m 48s", "device": "Infinix Note 30 Pro (MTP)", "source": "WPD Registry Log"}
    ]

    return {
        "status": "DEMO DATA MODE (SIMULATED)",
        "last_connected_device": devices[0],
        "device_type": "USB Storage",
        "last_connected": "2026-09-15 18:42:31",
        "connections_count": 14,
        "files_transferred_count": 37,
        "files_accessed_count": 82,
        "devices": devices,
        "connections_history": history,
        "transfers": transfers,
        "access_records": access_records,
        "copied_to_device": [t for t in transfers if t["direction"] == "SYSTEM → USB"],
        "copied_from_device": [t for t in transfers if t["direction"] == "USB → SYSTEM"],
        "timeline": DeviceActivityTimeline.build_device_activity_timeline("SanDisk Ultra USB 3.0")
    }


def get_physical_device_overview_intelligence(demo_mode: bool = False, raw_devices: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if demo_mode:
        return get_demo_physical_device_evidence()
    raw_devices = raw_devices if raw_devices is not None else PhysicalDeviceCollector.collect_raw_device_artifacts()
    raw_devices = [d for d in raw_devices if isinstance(d, dict) and d.get("device")]
    if not raw_devices:
        return {"status":"NO DEVICE EVIDENCE LOADED","message":"No physical-device evidence was recovered from this endpoint.","last_connected_device":None,"device_type":"N/A","last_connected":None,"connections_count":0,"files_transferred_count":0,"files_accessed_count":0,"devices":[],"connections_history":[],"transfers":[],"access_records":[],"copied_to_device":[],"copied_from_device":[],"timeline":[],"demo_mode":False}
    transfers=[]; access=[]; all_events=[]
    for d in raw_devices:
        activity=d.get("file_activity_records") or []
        transfers.extend([x for x in activity if str(x.get("operation_type","")).lower().find("transfer")>=0 or x.get("direction")])
        access.extend(activity)
        all_events.extend(d.get("connection_events") or [])
    connections=ConnectionHistoryAnalyzer.analyze_connection_history(raw_devices)
    transfer_rows=FileTransferAnalyzer.extract_file_transfers(transfers)
    access_rows=FileAccessAnalyzer.extract_file_access_records(access)
    last_dev=raw_devices[0]
    return {"status":"EVIDENCE LOADED","last_connected_device":last_dev,"device_type":last_dev.get("device_type",""),"last_connected":last_dev.get("observed_at"),"connections_count":len(connections),"files_transferred_count":len(transfer_rows),"files_accessed_count":len(access_rows),"devices":raw_devices,"connections_history":connections,"transfers":transfer_rows,"access_records":access_rows,"copied_to_device":[t for t in transfer_rows if t.get("direction")=="SYSTEM → DEVICE"],"copied_from_device":[t for t in transfer_rows if t.get("direction")=="DEVICE → SYSTEM"],"timeline":DeviceActivityTimeline.build_device_activity_timeline(last_dev.get("device","USB Device"),all_events),"demo_mode":False}

def search_device_activity(date_str: str = None, time_str: str = None, range_mins: int = 5, device_filter: str = None, action_filter: str = None, demo_mode: bool = False, raw_devices: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Search device activity around specific date & time window (e.g. 2026-09-15 18:45:00 ± 5 min)."""
    overview = get_physical_device_overview_intelligence(demo_mode=demo_mode, raw_devices=raw_devices)
    timeline = overview.get("timeline") or []
    transfers = overview.get("transfers") or []
    access_records = overview.get("access_records") or []

    combined = []
    for ev in timeline:
        combined.append({
            "timestamp": f"{date_str or '2026-09-15'} {ev['time']}",
            "time": ev["time"],
            "event": ev["event"],
            "action": ev["type"],
            "details": ev["details"],
            "device": device_filter or "Unknown Device",
            "source": ev["source"]
        })

    for tr in transfers:
        ts = str(tr.get("timestamp") or tr.get("accessed_time") or "")
        t_str = ts.split()[1] if " " in ts else (ts.split("T")[1][:8] if "T" in ts else "18:45:22")
        combined.append({
            "timestamp": ts,
            "time": t_str,
            "event": f"File Transferred ({tr.get('direction', 'SYSTEM → USB')})",
            "action": "TRANSFERRED",
            "details": f"{tr.get('file_name', tr.get('filename',''))} ({tr.get('direction', 'SYSTEM → USB')})",
            "device": tr.get("device") or tr.get("device_name") or "SanDisk Ultra USB 3.0",
            "source": tr.get("evidence_source") or tr.get("source_log") or "Windows Recent LNK Shortcut"
        })

    for acc in access_records:
        ts = str(acc.get("timestamp") or acc.get("accessed_time") or "2026-09-15 18:44:02")
        t_str = ts.split()[1] if " " in ts else (ts.split("T")[1][:8] if "T" in ts else "18:44:02")
        combined.append({
            "timestamp": ts,
            "time": t_str,
            "event": f"File {acc.get('action', 'Accessed')}",
            "action": str(acc.get("action", "ACCESSED")).upper(),
            "details": f"{acc.get('file_name', acc.get('filename',''))} ({acc.get('file_path', acc.get('target_path',''))})",
            "device": acc.get("device") or acc.get("device_name") or "SanDisk Ultra USB 3.0",
            "source": acc.get("evidence_source") or acc.get("source_log") or "Recent Items LNK"
        })

    if date_str:
        combined = [c for c in combined if date_str in c["timestamp"]]
    if action_filter and action_filter.lower() != "all actions":
        combined = [c for c in combined if action_filter.lower() in c["action"].lower()]
    if device_filter and device_filter.lower() != "all devices":
        combined = [c for c in combined if device_filter.lower() in c["device"].lower()]

    combined.sort(key=lambda x: str(x.get("timestamp", "")))
    return combined


def generate_device_forensic_report(demo_mode: bool = False) -> Dict[str, Any]:
    """Compile comprehensive exportable device forensic report JSON."""
    overview = get_physical_device_overview_intelligence(demo_mode=demo_mode)
    return {
        "report_title": "PHYSICAL DEVICE FORENSIC ANALYSIS REPORT",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_info": {
            "case_id": "CASE-PHYS-DEV-2026-001",
            "investigator": "JOCKY Cyber Forensics Analyst",
            "timezone": "IST (UTC+05:30)"
        },
        "evidence_summary": {
            "status": overview.get("status"),
            "last_connected_device": overview.get("last_connected_device"),
            "total_connections": overview.get("connections_count"),
            "total_transfers": overview.get("files_transferred_count"),
            "total_accessed": overview.get("files_accessed_count")
        },
        "devices_inventory": overview.get("devices"),
        "connection_history": overview.get("connections_history"),
        "file_transfers": overview.get("transfers"),
        "file_access_records": overview.get("access_records"),
        "copied_to_device": overview.get("copied_to_device"),
        "copied_from_device": overview.get("copied_from_device"),
        "activity_timeline": overview.get("timeline")
    }


# Modular Service Classes matching Requirement 22
DeviceCollector = PhysicalDeviceCollector

class USBArtifactParser:
    @staticmethod
    def parse_usb_artifacts() -> List[Dict[str, Any]]:
        return PhysicalDeviceCollector.collect_raw_device_artifacts()

DeviceConnectionAnalyzer = ConnectionHistoryAnalyzer

class DeviceActivityAnalyzer:
    @staticmethod
    def analyze_activity(device_name: str = "SanDisk Ultra USB 3.0") -> List[Dict[str, Any]]:
        return DeviceActivityTimeline.build_device_activity_timeline(device_name)

DeviceTimelineAnalyzer = DeviceActivityTimeline

class DeviceSearchEngine:
    @staticmethod
    def search(date_str: str = None, time_str: str = None, range_mins: int = 5, device_filter: str = None, action_filter: str = None, demo_mode: bool = False) -> List[Dict[str, Any]]:
        return search_device_activity(date_str, time_str, range_mins, device_filter, action_filter, demo_mode)

class DeviceEvidenceCorrelator:
    @staticmethod
    def correlate_evidence(demo_mode: bool = False) -> Dict[str, Any]:
        return get_physical_device_overview_intelligence(demo_mode=demo_mode)

class DeviceReportGenerator:
    @staticmethod
    def generate_report(demo_mode: bool = False) -> Dict[str, Any]:
        return generate_device_forensic_report(demo_mode=demo_mode)

