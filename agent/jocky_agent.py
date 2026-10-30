#!/usr/bin/env python3
"""
JOCKY Forensic Agent Engine
"""
import os
import sys

# Delivery nonce — located and overwritten per-download by the JOCKY server.
# The JNONCE: prefix is the search marker. Do NOT edit this line manually.
# 64 bytes total: 7-byte prefix + 57 zero bytes.
_DELIVERY_NONCE = b'JNONCE:' + b'\x00' * 57
import time
import uuid
import platform
import socket
import json
import tarfile
import tempfile
import argparse
import base64
import mimetypes
import hashlib

try:
    from agent.masquerade import apply as _masquerade_apply
except ImportError:
    _masquerade_apply = None
import requests
from datetime import datetime, timezone
from typing import Dict, Any, List

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), ".env"))
except Exception:
    pass

from src.plan import validate_forensic_plan
from collector.manifest import ManifestGenerator
from security.evidence_crypto import EvidenceCrypto, encrypt_file

try:
    from agent.build_identity import BUILD_IDENTITY, BUILD_ID
except ImportError:
    BUILD_IDENTITY = {"build_id": "source-tree", "built_at": None}
    BUILD_ID = BUILD_IDENTITY["build_id"]

# Import only the collector for the current operating system.
# This is important for the single cross-platform ZIP: Linux-only modules may
# import POSIX modules such as pwd, which do not exist on Windows.
if platform.system() == "Windows":
    from collector.windows_collector import (
        get_windows_system_info, get_windows_processes, get_windows_network,
        get_windows_users, get_windows_services, get_windows_filesystem,
        get_windows_storage, get_windows_software, get_windows_scheduled_tasks,
        get_windows_environment, get_windows_logs, get_windows_memory_telemetry,
        get_windows_network_interfaces,
    )
else:
    from collector.linux_collector import (
        system_info as linux_system_info, processes as linux_processes, network as linux_network,
        users as linux_users, services as linux_services, filesystem as linux_filesystem,
        disk_usage as linux_disk_usage, scheduled_tasks as linux_scheduled_tasks,
        environment as linux_environment, logs as linux_logs, software as linux_software,
        network_config as linux_network_config, mounts as linux_mounts, memory as linux_memory,
        registry as linux_registry, live_events as linux_live_events, recovery as linux_recovery,
        offline as linux_offline, security_telemetry as linux_security_telemetry
    )


def _smart_file_preview(path):
    path=os.path.abspath(os.path.expanduser(path)); size=os.path.getsize(path); ext=os.path.splitext(path)[1].lower(); max_bytes=8*1024*1024
    with open(path,'rb') as handle: raw=handle.read(max_bytes+1)
    truncated=len(raw)>max_bytes; raw=raw[:max_bytes]; mime=mimetypes.guess_type(path)[0] or 'application/octet-stream'
    if raw.startswith(b'%PDF-'): mime='application/pdf'
    elif raw.startswith(b'\x89PNG\r\n\x1a\n'): mime='image/png'
    elif raw.startswith(b'\xff\xd8\xff'): mime='image/jpeg'
    elif raw.startswith((b'GIF87a',b'GIF89a')): mime='image/gif'
    elif raw.startswith(b'RIFF') and raw[8:12]==b'WEBP': mime='image/webp'
    if mime.startswith('image/'):
        return {'path':path,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'image_data_url':f'data:{mime};base64,{base64.b64encode(raw).decode("ascii")}','read_only':True}
    if mime=='application/pdf' or ext=='.pdf':
        return {'path':path,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':'application/pdf','pdf_data_url':f'data:application/pdf;base64,{base64.b64encode(raw).decode("ascii")}','read_only':True}
    if ext=='.docx':
        try:
            import zipfile, io, xml.etree.ElementTree as ET
            with zipfile.ZipFile(io.BytesIO(raw),'r') as zf:
                root=ET.fromstring(zf.read('word/document.xml')); texts=[]
                for para in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                    t=''.join((x.text or '') for x in para.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t')).strip()
                    if t: texts.append(t)
                return {'path':path,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','office_type':'docx','content':'\n\n'.join(texts)[:200000],'binary':False,'read_only':True}
        except Exception: pass
    if ext in {'.txt','.log','.csv','.json','.xml','.html','.htm','.md','.py','.sh','.js','.css','.yml','.yaml'} or mime.startswith('text/'):
        return {'path':path,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'content':raw.decode('utf-8',errors='replace')[:200000],'binary':False,'read_only':True}
    try: content=raw.decode('utf-8'); binary=False
    except UnicodeDecodeError: content=raw.decode('utf-8',errors='replace'); binary=True
    return {'path':path,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'content':content,'binary':binary,'read_only':True}

def _archive_member_preview(archive_path, member_name):
    archive_path=os.path.abspath(os.path.expanduser(archive_path)); name=str(member_name or '')
    lower=archive_path.lower(); raw=b''; size=None
    if lower.endswith('.zip'):
        import zipfile
        with zipfile.ZipFile(archive_path,'r') as zf:
            info=zf.getinfo(name); size=info.file_size
            with zf.open(info,'r') as fh: raw=fh.read(8*1024*1024+1)
    elif lower.endswith(('.tar','.tar.gz','.tgz','.tar.bz2','.tbz2','.tar.xz','.txz')):
        with tarfile.open(archive_path,'r:*') as tf:
            m=tf.getmember(name); size=m.size
            if not m.isfile(): return {'member':name,'size_bytes':m.size,'type':'directory' if m.isdir() else 'special','read_only':True}
            fh=tf.extractfile(m); raw=fh.read(8*1024*1024+1) if fh else b''
    elif lower.endswith('.gz'):
        import gzip
        with gzip.open(archive_path,'rb') as fh: raw=fh.read(8*1024*1024+1)
        size=len(raw)
    else: return {'error':'unsupported_archive'}
    truncated=len(raw)>8*1024*1024; raw=raw[:8*1024*1024]
    ext=os.path.splitext(name)[1].lower(); mime=mimetypes.guess_type(name)[0] or 'application/octet-stream'
    if raw.startswith(b'%PDF-'): mime='application/pdf'
    elif raw.startswith(b'\x89PNG\r\n\x1a\n'): mime='image/png'
    elif raw.startswith(b'\xff\xd8\xff'): mime='image/jpeg'
    elif raw.startswith((b'GIF87a',b'GIF89a')): mime='image/gif'
    elif raw.startswith(b'RIFF') and raw[8:12]==b'WEBP': mime='image/webp'
    if mime.startswith('image/'):
        return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'image_data_url':f'data:{mime};base64,{base64.b64encode(raw).decode("ascii")}','read_only':True}
    if mime=='application/pdf' or ext=='.pdf':
        return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':'application/pdf','pdf_data_url':f'data:application/pdf;base64,{base64.b64encode(raw).decode("ascii")}','read_only':True}
    if ext=='.docx':
        try:
            import zipfile, io, xml.etree.ElementTree as ET
            with zipfile.ZipFile(io.BytesIO(raw),'r') as zf:
                root=ET.fromstring(zf.read('word/document.xml')); texts=[]
                for para in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                    t=''.join((x.text or '') for x in para.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t')).strip()
                    if t: texts.append(t)
                return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','office_type':'docx','content':'\n\n'.join(texts)[:200000],'binary':False,'read_only':True}
        except Exception: pass
    if ext in {'.txt','.log','.csv','.json','.xml','.html','.htm','.md','.py','.sh','.js','.css','.yml','.yaml'} or mime.startswith('text/'):
        return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'content':raw.decode('utf-8',errors='replace')[:200000],'binary':False,'read_only':True}
    try: text=raw.decode('utf-8'); binary=False
    except UnicodeDecodeError: text=raw.decode('utf-8',errors='replace'); binary=True
    return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'content':text[:200000],'binary':binary,'read_only':True}

# Closed allowlisted python collectors
def collect_system_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_system_info(), indent=2)
    return json.dumps(linux_system_info(), indent=2)


def collect_processes_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_processes(), indent=2)
    return json.dumps(linux_processes(), indent=2)


def collect_network_data() -> str:
    """Collect real socket/flow observations plus resolver and interface context.
    No reputation verdicts or synthetic traffic are generated here.
    """
    if platform.system() == "Windows":
        from collector.windows_collector import get_windows_network_interfaces
        connections = get_windows_network()
        interfaces = get_windows_network_interfaces()
    else:
        from collector.linux_collector import get_linux_network_interfaces
        connections = linux_network()
        interfaces = get_linux_network_interfaces()
    dns_cache = []
    try:
        from collector.network_forensics import DNSCacheCollector
        dns_cache = DNSCacheCollector.collect_dns_cache()
    except Exception:
        pass
    return json.dumps({
        "connections": connections,
        "interfaces": interfaces,
        "dns_cache": dns_cache,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "reputation_assessment": "NOT_CONFIGURED"
    }, indent=2)


def collect_users_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_users(), indent=2)
    return json.dumps(linux_users(), indent=2)


def collect_services_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_services(), indent=2)
    return json.dumps(linux_services(), indent=2)


def collect_filesystem_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_filesystem("C:\\Windows"), indent=2)
    return json.dumps(linux_filesystem("/"), indent=2)


def collect_software_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_software(), indent=2)
    return json.dumps(linux_software(), indent=2)


def collect_disk_usage_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_storage(), indent=2)
    return json.dumps(linux_disk_usage(), indent=2)


def collect_scheduled_tasks_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_scheduled_tasks(), indent=2)
    return json.dumps(linux_scheduled_tasks(), indent=2)


def collect_environment_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_environment(), indent=2)
    safe_env = {k: v for k, v in os.environ.items() if "SECRET" not in k and "KEY" not in k and "PASS" not in k}
    return json.dumps(linux_environment(), indent=2)


def collect_logs_data() -> str:
    if platform.system() == "Windows":
        return json.dumps(get_windows_logs(), indent=2)
    return json.dumps(linux_logs(), indent=2)


def collect_location_data() -> str:
    from collector.location import get_location_telemetry
    from collector.location_intelligence import LocationCollector
    telemetry = get_location_telemetry()
    artifacts = LocationCollector.collect_raw_location_artifacts()
    return json.dumps({"telemetry": telemetry, "artifacts": artifacts}, indent=2)


def collect_drivers_data() -> str:
    from collector.driver_forensics import get_driver_forensics
    return json.dumps(get_driver_forensics(), indent=2)


def collect_security_events_data() -> str:
    from collector.security_telemetry import get_defender_security_telemetry
    return json.dumps(get_defender_security_telemetry(), indent=2)


def collect_browser_history_data() -> str:
    if platform.system() == "Windows":
        from collector.windows_collector import get_windows_browser_history
        return json.dumps(get_windows_browser_history(), indent=2)
    from collector.linux_collector import browser_history
    return json.dumps(browser_history(), indent=2)


def collect_email_data() -> str:
    from collector.email_forensics import get_email_forensics
    return json.dumps(get_email_forensics(), indent=2)


def collect_removable_media_data() -> str:
    from collector.removable_media import get_removable_media_forensics
    return json.dumps(get_removable_media_forensics(), indent=2)


def collect_logins_data() -> str:
    if platform.system() == "Windows":
        from collector.windows_collector import get_windows_login_events
        return json.dumps(get_windows_login_events(), indent=2)
    from collector.linux_collector import get_linux_login_events
    return json.dumps(get_linux_login_events(), indent=2)


def collect_network_interfaces_data() -> str:
    if platform.system() == "Windows":
        from collector.windows_collector import get_windows_network_interfaces
        return json.dumps(get_windows_network_interfaces(), indent=2)
    from collector.linux_collector import get_linux_network_interfaces
    return json.dumps(get_linux_network_interfaces(), indent=2)



COLLECTOR_DISPATCH = {
    "system": collect_system_data,
    "processes": collect_processes_data,
    "network": collect_network_data,
    "users": collect_users_data,
    "services": collect_services_data,
    "filesystem": collect_filesystem_data,
    "software": collect_software_data,
    "disk_usage": collect_disk_usage_data,
    "scheduled_tasks": collect_scheduled_tasks_data,
    "environment": collect_environment_data,
    "logs": collect_logs_data,
    "network_config": lambda: json.dumps(linux_network_config(), indent=2) if platform.system() != "Windows" else json.dumps(get_windows_network_interfaces(), indent=2),
    "mounts": lambda: json.dumps(linux_mounts(), indent=2) if platform.system() != "Windows" else json.dumps(get_windows_storage(), indent=2),
    "drivers": collect_drivers_data,
    "browser": collect_browser_history_data,
    "browser_history": lambda: json.dumps(__import__("collector.linux_collector", fromlist=["browser_history"]).browser_history(), indent=2) if platform.system() != "Windows" else collect_browser_history_data(),
    "email": collect_email_data,
    "removable_media": collect_removable_media_data,
    "memory": lambda: json.dumps(linux_memory(), indent=2) if platform.system() != "Windows" else json.dumps(get_windows_memory_telemetry(), indent=2),
    "registry": lambda: json.dumps(linux_registry(), indent=2) if platform.system() != "Windows" else json.dumps({"platform":"Windows","read_only":True}, indent=2),
    "live_events": lambda: json.dumps(linux_live_events(), indent=2) if platform.system() != "Windows" else json.dumps(get_windows_logs(), indent=2),
    "security_telemetry": lambda: json.dumps(linux_security_telemetry(), indent=2) if platform.system() != "Windows" else json.dumps(__import__("collector.security_telemetry", fromlist=["get_defender_security_telemetry"]).get_defender_security_telemetry(), indent=2),
    "location": collect_location_data,
    "recovery": lambda: json.dumps(linux_recovery(), indent=2) if platform.system() != "Windows" else json.dumps({"platform":"Windows","read_only":True}, indent=2),
    "offline": lambda: json.dumps(linux_offline(), indent=2) if platform.system() != "Windows" else json.dumps({"platform":"Windows","mode":"live-endpoint-read-only"}, indent=2),
}



class JockyAgent:
    def __init__(self, server_url: str = "http://127.0.0.1:5000", agent_id: str = None, passphrase: str = None, api_key: str = None):
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id or f"agent_{socket.gethostname()}_{uuid.uuid4().hex[:6]}"
        self.hostname = socket.gethostname()
        self.os_name = f"{platform.system()} {platform.release()}"
        self.passphrase = passphrase
        self.api_key = api_key or os.environ.get("JOCKY_API_KEY", "")

    def _headers(self) -> Dict[str, str]:
        return {"X-API-Key": self.api_key} if self.api_key else {}

    def register(self) -> bool:
        url = f"{self.server_url}/api/devices/register"
        payload = {
            "device_id": self.agent_id,
            "hostname": self.hostname,
            "os": self.os_name,
            "build_id": BUILD_ID,
        }
        try:
            res = requests.post(url, json=payload, headers=self._headers(), timeout=5)
            if res.status_code == 200:
                print(f"[JOCKY-AGENT] Registered successfully with server as '{self.agent_id}'")
                return True
            else:
                print(f"[JOCKY-AGENT-ERROR] Registration failed ({res.status_code}): {res.text}")
                return False
        except Exception as e:
            print(f"[JOCKY-AGENT-ERROR] Connection to server failed: {e}")
            return False

    def get_assigned_case(self) -> str:
        try:
            res = requests.get(f"{self.server_url}/api/devices/{self.agent_id}/assignment", headers=self._headers(), timeout=5)
            if res.status_code == 200:
                return res.json().get("case_id") or ""
        except requests.RequestException:
            pass
        return ""

    def poll_and_execute_job(self) -> bool:
        url = f"{self.server_url}/api/agents/{self.agent_id}/jobs"
        try:
            res = requests.get(url, headers=self._headers(), timeout=5)
            if res.status_code != 200:
                return False

            jobs = res.json()
            if not jobs:
                return False

            job = jobs[0]
            job_id = job["id"]
            session_id = job["session_id"]
            plan_json_str = job.get("plan_json", "{}")

            print(f"[JOCKY-AGENT] Received pending job '{job_id}' for session '{session_id}'")
            self.execute_job(job_id, session_id, plan_json_str)
            return True

        except Exception as e:
            print(f"[JOCKY-AGENT-ERROR] Polling jobs failed: {e}")
            return False

    def poll_filesystem_requests(self) -> None:
        """Serve explicit, bounded read-only filesystem requests from the dashboard."""
        url = f"{self.server_url}/api/agents/{self.agent_id}/filesystem/requests"
        try:
            response = requests.get(url, headers=self._headers(), timeout=5)
            if response.status_code != 200:
                return
            for request_data in response.json() or []:
                request_id = request_data.get("request_id")
                path = request_data.get("path") or "."
                kind = request_data.get("kind")
                if kind == "browse":
                    if platform.system() == "Windows":
                        rows = get_windows_filesystem(path)
                    else:
                        rows = linux_filesystem(path)
                    result = {"entries": rows, "read_only": True}
                elif kind == "deleted_scan":
                    from collector.recovery import scan_deleted_files
                    result = {"entries": scan_deleted_files(path), "read_only": True}
                elif kind == "metadata":
                    if not os.path.isfile(path):
                        result = {"error": "not_a_file", "path": path}
                    else:
                        import hashlib, stat as _stat
                        st=os.stat(path); h=hashlib.sha256()
                        with open(path,"rb") as handle:
                            for chunk in iter(lambda: handle.read(1024*1024), b""): h.update(chunk)
                        exif_gps = None
                        exif_present = False
                        if os.path.splitext(path)[1].lower() in {".jpg", ".jpeg", ".tif", ".tiff", ".webp"}:
                            try:
                                from collector.location_intelligence import GPSArtifactParser
                                with open(path, "rb") as image_file:
                                    header = image_file.read(2 * 1024 * 1024)
                                exif_gps = GPSArtifactParser.extract_exif_gps_from_bytes(header)
                                exif_present = b"Exif\x00\x00" in header
                            except Exception:
                                pass
                        result={"path":path,"name":os.path.basename(path),"size_bytes":st.st_size,"mode_octal":oct(st.st_mode & 0o7777),"uid":getattr(st,"st_uid",None),"gid":getattr(st,"st_gid",None),"inode":st.st_ino,"modified_time":datetime.fromtimestamp(st.st_mtime,timezone.utc).isoformat(),"change_time":datetime.fromtimestamp(st.st_ctime,timezone.utc).isoformat(),"access_time":datetime.fromtimestamp(st.st_atime,timezone.utc).isoformat(),"sha256":h.hexdigest(),"exif_present":exif_present,"exif_gps":exif_gps,"exif_gps_coordinates":(f"{exif_gps['latitude']}, {exif_gps['longitude']}" if exif_gps else None),"read_only":True}
                elif kind in ("deleted_content", "deleted_hex"):
                    from collector.recovery import scan_deleted_files, recover_deleted_file
                    candidates=scan_deleted_files(path)
                    cand=next((c for c in candidates if c.get("candidate_id")==request_data.get("candidate_id")),None)
                    if not cand:
                        result={"error":"deleted_candidate_not_found"}
                    else:
                        rec=recover_deleted_file(cand.get("candidate_id"),cand.get("original_path") or "",volume=path)
                        rp=rec.get("destination_path")
                        if not rp or not os.path.isfile(rp): result={"error":"deleted_file_not_recoverable","details":rec}
                        elif kind=="deleted_content":
                            with open(rp,"rb") as handle: raw=handle.read(256*1024+1)
                            trunc=len(raw)>256*1024; raw=raw[:256*1024]
                            try: content=raw.decode("utf-8"); encoding,binary="utf-8",False
                            except UnicodeDecodeError: content=raw.decode("utf-8",errors="replace"); encoding,binary="utf-8-with-replacement",True
                            result={"path":rp,"size_bytes":os.path.getsize(rp),"bytes_returned":len(raw),"truncated":trunc,"encoding":encoding,"binary":binary,"content":content,"read_only":True,"sha256":rec.get("sha256")}
                        else:
                            with open(rp,"rb") as handle: raw=handle.read(1024)
                            result={"path":rp,"size_bytes":os.path.getsize(rp),"bytes_returned":len(raw),"hex_dump":[{"offset":f"{i:08X}","hex":" ".join(f"{b:02X}" for b in raw[i:i+16]).ljust(47),"ascii":"".join(chr(b) if 32<=b<=126 else "." for b in raw[i:i+16])} for i in range(0,len(raw),16)],"read_only":True,"sha256":rec.get("sha256")}
                elif kind == "archive":
                    path = os.path.abspath(os.path.expanduser(path))
                    entries=[]
                    lower=path.lower()
                    if lower.endswith('.zip'):
                        import zipfile
                        with zipfile.ZipFile(path, 'r') as zf:
                            for info in zf.infolist():
                                entries.append({"name":info.filename,"size_bytes":int(info.file_size),"compressed_size":int(info.compress_size),"type":"directory" if info.is_dir() else "file","modified":f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} {info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}","crc":f"{info.CRC:08x}"})
                    elif lower.endswith(('.tar','.tar.gz','.tgz','.tar.bz2','.tbz2','.tar.xz','.txz')):
                        with tarfile.open(path,'r:*') as tf:
                            for m in tf.getmembers():
                                entries.append({"name":m.name,"size_bytes":int(m.size),"type":"directory" if m.isdir() else ("symlink" if m.issym() else "file"),"modified":datetime.fromtimestamp(m.mtime,timezone.utc).isoformat() if m.mtime else None,"mode":oct(m.mode) if m.mode else None})
                    elif lower.endswith('.gz'):
                        import gzip
                        with gzip.open(path,'rb') as gf: raw=gf.read(1024*1024+1)
                        entries.append({"name":os.path.basename(path)[:-3] or os.path.basename(path),"size_bytes":len(raw),"type":"decompressed stream","modified":None})
                    result={"path":path,"count":len(entries),"entries":entries,"read_only":True}
                elif kind == "archive_content":
                    result=_archive_member_preview(path, request_data.get("member"))
                elif kind == "preview":
                    path = os.path.abspath(os.path.expanduser(path))
                    if not os.path.isfile(path):
                        result={"error":"not_a_file","path":path}
                    else:
                        result=_smart_file_preview(path)
                elif kind == "content":
                    with open(path, "rb") as handle:
                        raw = handle.read(256 * 1024 + 1)
                    truncated = len(raw) > 256 * 1024
                    raw = raw[:256 * 1024]
                    try:
                        content = raw.decode("utf-8")
                        encoding, binary = "utf-8", False
                    except UnicodeDecodeError:
                        content = raw.decode("utf-8", errors="replace")
                        encoding, binary = "utf-8-with-replacement", True
                    import hashlib
                    h=hashlib.sha256()
                    with open(path,"rb") as full_handle:
                        for chunk in iter(lambda: full_handle.read(1024*1024), b""): h.update(chunk)
                    result = {"path": path, "size_bytes": os.path.getsize(path), "bytes_returned": len(raw), "truncated": truncated, "encoding": encoding, "binary": binary, "content": content, "sha256": h.hexdigest(), "read_only": True}
                elif kind == "hex":
                    with open(path, "rb") as handle:
                        raw = handle.read(1024)
                    hex_dump = []
                    for offset in range(0, len(raw), 16):
                        chunk = raw[offset:offset+16]
                        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
                        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                        hex_dump.append({"offset": f"{offset:08X}", "hex": hex_bytes.ljust(47), "ascii": ascii_repr})
                    result = {"path": path, "size_bytes": os.path.getsize(path), "bytes_returned": len(raw), "hex_dump": hex_dump, "read_only": True}
                else:
                    result = {"error": "unsupported_filesystem_request"}
                requests.post(f"{url}/{request_id}", json=result, headers=self._headers(), timeout=10)
        except (OSError, ValueError, requests.RequestException) as exc:
            if 'request_id' in locals() and request_id:
                requests.post(f"{url}/{request_id}", json={"error": "filesystem_request_failed", "message": str(exc)}, headers=self._headers(), timeout=10)


    def poll_email_requests(self) -> None:
        """Serve explicit endpoint email-collection requests from the investigator dashboard."""
        url = f"{self.server_url}/api/agents/{self.agent_id}/email/requests"
        try:
            response = requests.get(url, headers=self._headers(), timeout=5)
            if response.status_code != 200:
                return
            for req in response.json() or []:
                request_id = req.get("request_id")
                try:
                    from collector.email_forensics import get_email_forensics
                    result = get_email_forensics()
                except Exception as exc:
                    result = {"error": "email_collection_failed", "message": str(exc), "emails": []}
                requests.post(f"{url}/{request_id}", json=result, headers=self._headers(), timeout=15)
        except (requests.RequestException, ValueError):
            return

    def execute_job(self, job_id: str, session_id: str, plan_json_str: str) -> None:
        try:
            plan = json.loads(plan_json_str)
        except Exception as e:
            print(f"[JOCKY-AGENT-ERROR] Invalid plan JSON: {e}")
            self.report_status(job_id, "FAILED")
            return

        # Security boundary check
        if not validate_forensic_plan(plan):
            print(f"[JOCKY-AGENT-SECURITY] Plan validation failed or tampered! Refusing execution.")
            self.report_status(job_id, "FAILED")
            return

        print(f"[JOCKY-AGENT] Validated closed forensic plan '{plan['module']}'. Executing operations...")
        self.report_status(job_id, "RUNNING")

        with tempfile.TemporaryDirectory() as tmpdir:
            collection_dir = os.path.join(tmpdir, "collected")
            os.makedirs(collection_dir, exist_ok=True)

            # Execute allowlisted operations
            for op in plan["operations"]:
                op_type = op["type"].lower()
                collector_fn = COLLECTOR_DISPATCH.get(op_type)
                if collector_fn:
                    output_text = collector_fn()
                    outfile = os.path.join(collection_dir, f"{op_type}.txt")
                    with open(outfile, "w", encoding="utf-8") as f:
                        f.write(output_text)

            # Create archive
            archive_path = os.path.join(tmpdir, "archive.tar.gz")
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(collection_dir, arcname="collected")

            # Generate manifest
            manifest_gen = ManifestGenerator()
            manifest_path = os.path.join(tmpdir, "manifest.json")
            manifest = manifest_gen.generate_manifest(
                case_id="case_remote",
                session_id=session_id,
                job_id=job_id,
                agent_id=self.agent_id,
                files_dir=collection_dir,
                output_manifest_path=manifest_path
            )

            final_archive = archive_path
            is_encrypted = False

            if self.passphrase:
                enc_path = os.path.join(tmpdir, "archive.tar.gz.enc")
                encrypt_file(archive_path, enc_path, self.passphrase)
                final_archive = enc_path
                is_encrypted = True

            # Upload evidence
            self.upload_evidence(job_id, final_archive, manifest, is_encrypted)
            self.report_status(job_id, "COMPLETED")

    def upload_evidence(self, job_id: str, archive_path: str, manifest: Dict[str, Any], is_encrypted: bool) -> None:
        url = f"{self.server_url}/api/evidence"
        try:
            with open(archive_path, "rb") as f:
                files = {"file": (os.path.basename(archive_path), f, "application/octet-stream")}
                data = {
                    "job_id": job_id,
                    "manifest": json.dumps(manifest),
                    "is_encrypted": "1" if is_encrypted else "0"
                }
                res = requests.post(url, files=files, data=data, headers=self._headers(), timeout=30)
                if res.status_code == 201:
                    print(f"[JOCKY-AGENT] Successfully uploaded evidence for job '{job_id}'")
                else:
                    print(f"[JOCKY-AGENT-ERROR] Upload failed ({res.status_code}): {res.text}")
        except Exception as e:
            print(f"[JOCKY-AGENT-ERROR] Evidence upload exception: {e}")

    def report_status(self, job_id: str, status: str) -> None:
        url = f"{self.server_url}/api/jobs/{job_id}/status"
        try:
            requests.post(url, json={"status": status}, headers=self._headers(), timeout=5)
        except Exception as e:
            print(f"[JOCKY-AGENT-ERROR] Failed to report status: {e}")

    def send_live_events(self, events: List[Dict[str, Any]], case_id: str) -> bool:
        if not events:
            return True
        url = f"{self.server_url}/api/live/ingest"
        payload = {
            "agent_id": self.agent_id,
            "case_id": case_id,
            "events": events
        }
        try:
            res = requests.post(url, json=payload, headers=self._headers(), timeout=5)
            return res.status_code == 200
        except Exception:
            return False

    def send_rich_forensic_snapshot(self, case_id: str) -> bool:
        """Collect the feature-rich B1-B8 endpoint snapshot on the target OS.

        This is intentionally investigator/case scoped and runs once when a
        case is assigned.  It never runs the collector on the server host.
        """
        categories = {}
        try:
            from collector.system_collector import SystemForensicsCollector
            categories["system_forensics"] = SystemForensicsCollector(self.agent_id, case_id).collect_system_info()
        except Exception as exc:
            categories["system_forensics"] = {"status": "COLLECTION_ERROR", "error": str(exc), "case_id": case_id, "device_id": self.agent_id}
        collectors = [
            ("browser_forensics", lambda: __import__("collector.browser_forensics", fromlist=["BrowserForensicsCollector"]).BrowserForensicsCollector(self.agent_id, case_id).collect_all_browser_evidence()),
            ("applications_forensics", lambda: __import__("collector.application_forensics", fromlist=["ApplicationForensicsCollector"]).ApplicationForensicsCollector(self.agent_id, case_id).collect_all_application_evidence()),
            ("messaging_forensics", lambda: __import__("collector.messaging_forensics", fromlist=["MessagingForensicsCollector"]).MessagingForensicsCollector(self.agent_id, case_id).collect_all_messaging_evidence()),
            ("device_forensics", lambda: __import__("collector.device_forensics", fromlist=["DeviceForensicsCollector"]).DeviceForensicsCollector(self.agent_id, case_id).collect_all_device_evidence()),
            ("filesystem_forensics", lambda: __import__("collector.filesystem_forensics", fromlist=["FilesystemForensicsCollector"]).FilesystemForensicsCollector(self.agent_id, case_id, max_files_per_category=50).collect_all_filesystem_evidence()),
            ("email_forensics", lambda: __import__("collector.email_collector", fromlist=["EmailForensicsCollector"]).EmailForensicsCollector(self.agent_id, case_id).collect_all_email_evidence()),
        ]
        for category, fn in collectors:
            try:
                value = fn()
                categories[category] = value
            except Exception as exc:
                categories[category] = {"status": "COLLECTION_ERROR", "error": str(exc), "case_id": case_id, "device_id": self.agent_id}
        # Keep the existing proven OS-native collectors as a compatibility
        # layer for network/log/user/service pages.
        for category in ("network", "users", "services", "logs", "software", "network_config", "mounts", "memory", "scheduled_tasks", "environment"):
            fn = COLLECTOR_DISPATCH.get(category)
            if fn:
                try:
                    raw = fn()
                    categories[category] = json.loads(raw) if isinstance(raw, str) else raw
                except Exception as exc:
                    categories[category] = {"status": "COLLECTION_ERROR", "error": str(exc), "case_id": case_id, "device_id": self.agent_id}
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "case_id": case_id,
            "device_id": self.agent_id,
            "hostname": self.hostname,
            "os": self.os_name,
            "categories": categories,
        }
        url = f"{self.server_url}/api/devices/{self.agent_id}/telemetry"
        try:
            res = requests.post(url, json=payload, headers=self._headers(), timeout=120)
            if res.status_code == 200:
                print(f"[JOCKY-AGENT] Rich forensic snapshot uploaded ({len(categories)} categories)")
                return True
            print(f"[JOCKY-AGENT-ERROR] Rich telemetry upload failed ({res.status_code}): {res.text}")
        except Exception as exc:
            print(f"[JOCKY-AGENT-ERROR] Rich telemetry upload exception: {exc}")
        return False

    def send_telemetry_snapshot(self, selected_categories=None, case_id: str = None) -> bool:
        """Send a read-only endpoint snapshot so the dashboard is populated
        immediately, even when no forensic job has been created yet."""
        categories = {}
        # Keep this baseline focused on the dashboard's primary endpoint
        # views. The full forensic job still supports every allowlisted op.
        categories_to_collect = selected_categories or ("system", "processes", "network", "users", "services", "disk_usage", "memory", "browser_history",
                         "filesystem", "network_config", "mounts", "scheduled_tasks", "environment", "logs",
                         "software", "drivers", "memory", "browser_history", "email", "registry", "live_events", "security_telemetry",
                         "location", "removable_media", "recovery", "offline")
        for category in categories_to_collect:
            fn = COLLECTOR_DISPATCH.get(category)
            if not fn:
                continue
            try:
                raw = fn()
                categories[category] = json.loads(raw) if isinstance(raw, str) else raw
            except Exception as exc:
                categories[category] = {"error": str(exc), "read_only": True}
        if not categories:
            return False
        payload = {"timestamp": datetime.now(timezone.utc).isoformat(), "case_id": case_id, "device_id": self.agent_id, "hostname": self.hostname, "os": self.os_name, "categories": categories}
        url = f"{self.server_url}/api/devices/{self.agent_id}/telemetry"
        try:
            res = requests.post(url, json=payload, headers=self._headers(), timeout=20)
            if res.status_code == 200:
                print(f"[JOCKY-AGENT] Telemetry snapshot uploaded ({len(categories)} categories)")
                return True
            print(f"[JOCKY-AGENT-ERROR] Telemetry upload failed ({res.status_code}): {res.text}")
        except Exception as e:
            print(f"[JOCKY-AGENT-ERROR] Telemetry upload exception: {e}")
        return False

    def run_live_loop(self, interval: int = 2, case_id: str = None) -> None:
        from collector.live_monitor import LiveMonitorEngine
        print(f"[JOCKY-AGENT-LIVE] Agent detected by JOCKY. Waiting for investigator case assignment (agent: {self.agent_id})...")
        self.register()
        assigned_case = case_id or self.get_assigned_case()
        while not assigned_case:
            time.sleep(2)
            self.register()
            assigned_case = self.get_assigned_case()
        print(f"[JOCKY-AGENT-LIVE] Investigator assigned case '{assigned_case}'. Beginning authorized collection.")
        self.send_telemetry_snapshot(case_id=assigned_case)
        self.send_rich_forensic_snapshot(assigned_case)
        engine = LiveMonitorEngine(agent_id=self.agent_id, server_url=self.server_url)
        engine.start()

        telemetry_tick = 0
        try:
            while True:
                self.poll_and_execute_job()
                self.poll_filesystem_requests()
                self.poll_email_requests()
                telemetry_tick += 2
                if telemetry_tick >= 5:
                    self.send_telemetry_snapshot(("system", "processes", "network", "users", "services", "disk_usage", "memory"), case_id=assigned_case)
                if telemetry_tick >= 30:
                    self.send_telemetry_snapshot(("filesystem", "network_config", "mounts", "scheduled_tasks", "environment", "logs",
                                                    "software", "drivers", "memory", "browser_history", "email", "registry", "live_events",
                                                    "security_telemetry", "location", "removable_media", "recovery", "offline"), case_id=assigned_case)
                    telemetry_tick = 0
                new_events = engine.poll_cycle()
                spooled = engine.spool_queue.dequeue_all()
                all_events_to_send = spooled + new_events

                if all_events_to_send:
                    assigned_case = self.get_assigned_case() or assigned_case
                    if not assigned_case:
                        for evt in all_events_to_send:
                            engine.spool_queue.enqueue(evt)
                        time.sleep(interval)
                        continue
                    success = self.send_live_events(all_events_to_send, case_id=assigned_case)
                    if not success:
                        print(f"[JOCKY-AGENT-LIVE] Connection offline. Spooling {len(all_events_to_send)} events to disk queue...")
                        for evt in all_events_to_send:
                            engine.spool_queue.enqueue(evt)
                    else:
                        print(f"[JOCKY-AGENT-LIVE] Transmitted {len(all_events_to_send)} live telemetry events to central server.")

                time.sleep(interval)
        except KeyboardInterrupt:
            engine.stop()
            print("[JOCKY-AGENT-LIVE] Live monitoring stopped by user.")

    def run_loop(self, interval: int = 3) -> None:
        print(f"[JOCKY-AGENT] Agent starting loop (polling every {interval}s)...")
        registered = self.register()
        if not registered:
            print("[JOCKY-AGENT] Initial registration attempt failed, will retry in loop...")
        else:
            print(f"[JOCKY-AGENT] Agent detected. Waiting for investigator to create/assign a case for '{self.agent_id}'.")

        telemetry_tick = 0
        active_case = self.get_assigned_case() if registered else ""
        last_case = active_case
        while True:
            if not registered:
                registered = self.register()
                if registered:
                    active_case = self.get_assigned_case()
            active_case = self.get_assigned_case() if registered else ""

            # A case is assigned by the dashboard after agent registration.
            # Detect that transition and push a baseline snapshot immediately
            # instead of waiting for a later polling interval.
            if registered and active_case and active_case != last_case:
                print(f"[JOCKY-AGENT] Case '{active_case}' assigned. Uploading endpoint telemetry...")
                self.send_telemetry_snapshot(("system", "processes", "network", "users", "services", "disk_usage", "memory"), case_id=active_case)
                self.send_rich_forensic_snapshot(active_case)
                telemetry_tick = 0
            last_case = active_case

            if active_case:
                self.poll_and_execute_job()
                self.poll_filesystem_requests()
                self.poll_email_requests()
            telemetry_tick += interval
            # Fast-changing dashboard data is refreshed frequently. More
            # expensive forensic categories are refreshed less often.
            if registered and active_case and telemetry_tick >= 5:
                self.send_telemetry_snapshot(("system", "processes", "network", "users", "services", "disk_usage", "memory"), case_id=active_case)
                telemetry_tick = 0
            if registered and active_case and telemetry_tick >= 30:
                self.send_telemetry_snapshot(("filesystem", "network_config", "mounts", "scheduled_tasks", "environment", "logs",
                                                "software", "drivers", "memory", "browser_history", "email", "registry", "live_events",
                                                "security_telemetry", "location", "removable_media", "recovery", "offline"), case_id=active_case)
                telemetry_tick = 0
            time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="JOCKY Forensic Agent Engine & Triage Collector")
    parser.add_argument("--server", default="http://127.0.0.1:5000", help="Central server URL")
    parser.add_argument("--id", help="Agent identifier")
    parser.add_argument("--passphrase", help="Optional passphrase for AES-256-GCM evidence encryption")
    parser.add_argument("--api-key", help="Optional API key matching JOCKY_API_KEY on the server")
    parser.add_argument("--once", action="store_true", help="Poll once and exit")
    parser.add_argument("--snapshot", action="store_true", help="Collect all allowlisted endpoint telemetry once, upload it, and exit")
    parser.add_argument("--live", action="store_true", help="Run continuous live forensic monitoring & delta collection")
    parser.add_argument("--case-id", help="Optional case ID override")
    parser.add_argument("--case", help="Case ID for local collection (alias for --case-id)")
    parser.add_argument("--session-id", help="CLI mode session ID")
    parser.add_argument("--job-id", help="CLI mode job ID")
    parser.add_argument("--out", default="./evidence", help="Output evidence dir")
    parser.add_argument("--output", help="Output evidence dir (alias for --out)")

    # B1-B12 Collector Commands
    parser.add_argument("--collect", action="store_true", help="Run local B1-B12 forensic collection into SQLite")
    parser.add_argument("--local-snapshot", action="store_true", help="Take point-in-time local triage snapshot")
    parser.add_argument("--all", action="store_true", default=False, help="Collect all forensic artifact subsystems (default)")
    parser.add_argument("--browser", action="store_true", help="Collect B1 Browser Forensics")
    parser.add_argument("--applications", action="store_true", help="Collect B2 Application Forensics")
    parser.add_argument("--messaging", action="store_true", help="Collect B3 Messaging Forensics")
    parser.add_argument("--email", action="store_true", help="Collect B4 Email Forensics")
    parser.add_argument("--devices", action="store_true", help="Collect B6 Device Forensics")
    parser.add_argument("--filesystem", action="store_true", help="Collect B8 Filesystem Forensics")
    parser.add_argument("--network", action="store_true", help="Collect Network Forensics")
    parser.add_argument("--system", action="store_true", help="Collect B7 System Forensics")

    parser.add_argument(
        "--masquerade",
        default=None,
        metavar="NAME",
        help=("Disguise this process in ps/pstree as NAME. "
              "Use a known-good daemon name e.g. 'systemd-journald'. "
              "Authorized red-team / forensic deployments only.")
    )
    parser.add_argument(
        "--masquerade-profile",
        default=None,
        metavar="PROFILE",
        help="Shortcut key from masquerade.PROFILES (e.g. 'journal', 'netd', 'cron')"
    )
    args = parser.parse_args()

    # Apply process-name masquerade BEFORE anything else
    if _masquerade_apply and (args.masquerade or args.masquerade_profile):
        _masquerade_apply(name=args.masquerade, profile=args.masquerade_profile)
    elif _masquerade_apply and os.environ.get("JOCKY_PROC_NAME"):
        _masquerade_apply()

    # Handler for --collect or --local-snapshot
    if args.collect or args.local_snapshot:
        from agent.dfir_collector_runner import run_dfir_collection
        target_case = args.case or args.case_id or "CASE-001"
        target_out = args.output or args.out or "./evidence"

        # Default to all if no specific subsystem flag was provided
        has_specific = any([
            args.browser, args.applications, args.messaging, args.email,
            args.devices, args.filesystem, args.network, args.system
        ])
        do_all = args.all or not has_specific

        print("=" * 65)
        print(" TINY MONITOR — LOCAL FORENSIC TRIAGE COLLECTOR")
        print("=" * 65)
        print(f" Target Case ID  : {target_case}")
        print(f" Output Location : {target_out}")
        print(f" Mode            : {'All Subsystems' if do_all else 'Selective Subsystems'}")
        print("-" * 65)

        report = run_dfir_collection(
            case_id=target_case,
            device_id=args.id,
            output_dir=target_out,
            collect_all=do_all,
            collect_browser=args.browser,
            collect_apps=args.applications,
            collect_messaging=args.messaging,
            collect_email=args.email,
            collect_devices=args.devices,
            collect_filesystem=args.filesystem,
            collect_network=args.network,
            collect_system=args.system,
        )

        print("\n" + "=" * 65)
        print(" COLLECTION SUMMARY & ARTIFACT PROVENANCE")
        print("=" * 65)
        for mod, st in report.get("modules", {}).items():
            print(f" [{st:<16}] {mod}")
        print("-" * 65)
        print(f" Total Artifacts Collected : {report.get('total_artifacts', 0)}")
        print(f" Package Archive           : {report.get('package_zip')}")
        print(f" SHA-256 Checksum          : {report.get('package_hash')}")
        print("=" * 65)
        return

    agent = JockyAgent(server_url=args.server, agent_id=args.id, passphrase=args.passphrase, api_key=args.api_key)
    
    if args.live:
        agent.run_live_loop(case_id=args.case_id)
    elif args.snapshot:
        if agent.register():
            raise SystemExit(0 if agent.send_telemetry_snapshot() else 1)
        raise SystemExit(1)
    elif args.once:
        agent.register()
        agent.poll_and_execute_job()
    else:
        agent.run_loop()


if __name__ == "__main__":
    main()
