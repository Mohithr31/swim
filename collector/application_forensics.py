"""
Tiny Monitor — B2 Application Forensics Engine
Real local application discovery across Windows, Linux, and macOS.
Collects: Installed applications, running processes, execution evidence,
prefetch artifacts, UserAssist, AmCache, recent files, Recycle Bin metadata,
and Zone.Identifier alternate data streams.
Enforces authentic state labeling: COLLECTED, NOT_PRESENT, NOT_ACCESSIBLE,
PERMISSION_REQUIRED, NOT_SUPPORTED, NO_EVIDENCE_FOUND, COLLECTION_ERROR.
"""
import os
import sys
import glob
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


def _hash_file(path: str, max_size_mb: int = 15) -> Optional[str]:
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > max_size_mb * 1024 * 1024:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _rot13(s: str) -> str:
    """ROT13 decode helper for Windows UserAssist entries."""
    import codecs
    return codecs.decode(s, "rot_13")


class ApplicationForensicsCollector:
    """B2 Application Forensics Engine."""

    def __init__(self, device_id: str = "DEV-LOCAL", case_id: str = "CAS-DEFAULT"):
        self.device_id = device_id
        self.case_id = case_id
        self.os_type = platform.system()

    def collect_all_application_evidence(self) -> Dict[str, Any]:
        """Collect all B2 application evidence and return categorized records."""
        results = {
            "status": "NO_EVIDENCE_FOUND",
            "installed_applications": [],
            "running_processes": [],
            "execution_evidence": [],
            "recent_files": [],
            "recycle_bin": [],
            "zone_identifier": [],
            "prefetch": {"status": "NOT_SUPPORTED", "items": [], "count": 0},
            "userassist": {"status": "NOT_SUPPORTED", "items": [], "count": 0},
            "amcache": {"status": "NOT_SUPPORTED", "items": [], "count": 0},
        }

        # 1. Installed Applications
        results["installed_applications"] = self.collect_installed_applications()

        # 2. Running Processes
        results["running_processes"] = self.collect_running_processes()

        # 3. Prefetch (Windows)
        if self.os_type == "Windows":
            results["prefetch"] = self.collect_windows_prefetch()
            results["userassist"] = self.collect_windows_userassist()
            results["amcache"] = self.collect_windows_amcache()
            results["recycle_bin"] = self.collect_windows_recycle_bin()
            results["zone_identifier"] = self.collect_zone_identifier_files()
        else:
            results["prefetch"] = {"status": "NOT_SUPPORTED", "items": [], "count": 0, "message": "Prefetch is a Windows artifact."}
            results["userassist"] = {"status": "NOT_SUPPORTED", "items": [], "count": 0, "message": "UserAssist is a Windows artifact."}
            results["amcache"] = {"status": "NOT_SUPPORTED", "items": [], "count": 0, "message": "AmCache is a Windows artifact."}
            results["recycle_bin"] = self.collect_posix_trash()
            results["zone_identifier"] = []

        # 4. Recent Files
        results["recent_files"] = self.collect_recent_files()

        # 5. Execution Evidence summary (combines Prefetch, UserAssist, and Running Processes)
        for p in results["running_processes"][:50]:
            results["execution_evidence"].append({
                "type": "RUNNING_PROCESS",
                "name": p.get("name"),
                "path": p.get("executable_path"),
                "timestamp": p.get("start_time"),
                "status": "LIVE_EXECUTION",
                "sha256": p.get("sha256"),
                "source": "Process Table"
            })

        for pf in results["prefetch"].get("items", [])[:50]:
            results["execution_evidence"].append({
                "type": "PREFETCH_ARTIFACT",
                "name": pf.get("name"),
                "path": pf.get("path"),
                "timestamp": pf.get("timestamp"),
                "status": "HISTORICAL_EXECUTION",
                "sha256": pf.get("sha256"),
                "source": "C:\\Windows\\Prefetch"
            })

        for ua in results["userassist"].get("items", [])[:50]:
            results["execution_evidence"].append({
                "type": "USERASSIST_ENTRY",
                "name": ua.get("name"),
                "path": ua.get("raw_name"),
                "timestamp": ua.get("timestamp"),
                "status": "USER_INTERACTION",
                "sha256": None,
                "source": "Registry UserAssist"
            })

        total_collected = (len(results["installed_applications"]) +
                           len(results["running_processes"]) +
                           len(results["recent_files"]))
        results["status"] = "COLLECTED" if total_collected > 0 else "NO_EVIDENCE_FOUND"
        return results

    def collect_installed_applications(self) -> List[Dict[str, Any]]:
        """Collect installed applications based on host OS."""
        apps: List[Dict[str, Any]] = []

        if self.os_type == "Windows" and winreg:
            uninstall_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "Registry HKLM (64-bit)"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "Registry HKLM (32-bit)"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "Registry HKCU (User)"),
            ]
            seen_names = set()

            for hive, subkey_path, source_desc in uninstall_keys:
                try:
                    key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
                    count_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(count_subkeys):
                        try:
                            sk_name = winreg.EnumKey(key, i)
                            sk = winreg.OpenKey(key, sk_name)
                            try:
                                disp_name, _ = winreg.QueryValueEx(sk, "DisplayName")
                            except Exception:
                                disp_name = None

                            if not disp_name or not str(disp_name).strip():
                                winreg.CloseKey(sk)
                                continue

                            disp_name = str(disp_name).strip()
                            if disp_name in seen_names:
                                winreg.CloseKey(sk)
                                continue
                            seen_names.add(disp_name)

                            def _get_val(k, name):
                                try:
                                    v, _ = winreg.QueryValueEx(k, name)
                                    return str(v) if v is not None else ""
                                except Exception:
                                    return ""

                            version = _get_val(sk, "DisplayVersion") or "N/A"
                            publisher = _get_val(sk, "Publisher") or "N/A"
                            install_loc = _get_val(sk, "InstallLocation") or ""
                            install_date = _get_val(sk, "InstallDate") or ""
                            uninstall_str = _get_val(sk, "UninstallString") or ""

                            # Normalize install date if YYYYMMDD
                            normalized_date = install_date
                            if len(install_date) == 8 and install_date.isdigit():
                                normalized_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}T00:00:00Z"

                            # Calculate hash of executable in install_location if accessible
                            exe_sha256 = None
                            if install_loc and os.path.isdir(install_loc):
                                for cand in glob.glob(os.path.join(install_loc, "*.exe"))[:3]:
                                    h = _hash_file(cand)
                                    if h:
                                        exe_sha256 = h
                                        break

                            app_id = f"APP-{hashlib.md5(f'{disp_name}_{version}'.encode()).hexdigest()[:12]}"
                            apps.append({
                                "id": app_id,
                                "device_id": self.device_id,
                                "case_id": self.case_id,
                                "name": disp_name,
                                "version": version,
                                "publisher": publisher,
                                "install_path": install_loc,
                                "install_date": normalized_date,
                                "uninstall_string": uninstall_str,
                                "category": "Installed Application",
                                "source": source_desc,
                                "status": "COLLECTED",
                                "sha256": exe_sha256,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                            winreg.CloseKey(sk)
                        except Exception:
                            continue
                    winreg.CloseKey(key)
                except Exception:
                    continue

        elif self.os_type == "Linux":
            # dpkg
            if shutil.which("dpkg-query"):
                try:
                    out = subprocess.check_output(
                        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"],
                        text=True, errors="replace", stderr=subprocess.DEVNULL
                    )
                    for line in out.splitlines()[:500]:
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            p_name = parts[0]
                            p_ver = parts[1]
                            p_pub = parts[2] if len(parts) > 2 else "Linux Package"
                            app_id = f"APP-{hashlib.md5(f'{p_name}_{p_ver}'.encode()).hexdigest()[:12]}"
                            apps.append({
                                "id": app_id,
                                "device_id": self.device_id,
                                "case_id": self.case_id,
                                "name": p_name,
                                "version": p_ver,
                                "publisher": p_pub,
                                "install_path": f"/usr/bin/{p_name}",
                                "install_date": "N/A",
                                "uninstall_string": f"apt remove {p_name}",
                                "category": "dpkg package",
                                "source": "dpkg-query",
                                "status": "COLLECTED",
                                "sha256": None,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                except Exception:
                    pass

            # rpm
            if shutil.which("rpm") and not apps:
                try:
                    out = subprocess.check_output(
                        ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"],
                        text=True, errors="replace", stderr=subprocess.DEVNULL
                    )
                    for line in out.splitlines()[:500]:
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            p_name = parts[0]
                            p_ver = parts[1]
                            p_pub = parts[2] if len(parts) > 2 else "Linux Package"
                            app_id = f"APP-{hashlib.md5(f'{p_name}_{p_ver}'.encode()).hexdigest()[:12]}"
                            apps.append({
                                "id": app_id,
                                "device_id": self.device_id,
                                "case_id": self.case_id,
                                "name": p_name,
                                "version": p_ver,
                                "publisher": p_pub,
                                "install_path": f"/usr/bin/{p_name}",
                                "install_date": "N/A",
                                "uninstall_string": f"rpm -e {p_name}",
                                "category": "rpm package",
                                "source": "rpm",
                                "status": "COLLECTED",
                                "sha256": None,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                except Exception:
                    pass

        elif self.os_type == "Darwin":  # macOS
            app_dirs = ["/Applications", "/System/Applications", os.path.expanduser("~/Applications")]
            for adir in app_dirs:
                if os.path.isdir(adir):
                    for entry in os.listdir(adir):
                        if entry.endswith(".app"):
                            full_app = os.path.join(adir, entry)
                            app_name = entry[:-4]
                            app_id = f"APP-{hashlib.md5(f'{app_name}_{full_app}'.encode()).hexdigest()[:12]}"
                            apps.append({
                                "id": app_id,
                                "device_id": self.device_id,
                                "case_id": self.case_id,
                                "name": app_name,
                                "version": "N/A",
                                "publisher": "Apple / Third Party",
                                "install_path": full_app,
                                "install_date": "N/A",
                                "uninstall_string": f"rm -rf '{full_app}'",
                                "category": "macOS Application Bundle",
                                "source": adir,
                                "status": "COLLECTED",
                                "sha256": None,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })

        return apps

    def collect_running_processes(self) -> List[Dict[str, Any]]:
        """Collect live process table with hashes and parent relationships."""
        processes: List[Dict[str, Any]] = []

        if psutil:
            hash_cache: Dict[str, Optional[str]] = {}
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'status', 'cpu_percent', 'memory_info', 'num_threads', 'create_time']):
                try:
                    info = proc.info
                    exe = info.get('exe') or ''
                    if exe and exe not in hash_cache:
                        hash_cache[exe] = _hash_file(exe, max_size_mb=5) if os.path.isfile(exe) else None
                    exe_sha256 = hash_cache.get(exe) if exe else None
                    cmdline = " ".join(info.get('cmdline') or [])
                    try:
                        cwd = proc.cwd()
                    except Exception:
                        cwd = None
                    mem_kb = round(info['memory_info'].rss / 1024) if info.get('memory_info') else 0
                    start_iso = datetime.fromtimestamp(info['create_time'], tz=timezone.utc).isoformat() if info.get('create_time') else "N/A"

                    proc_id = f"PROC-{info['pid']}-{hashlib.md5(f'{exe}_{start_iso}'.encode()).hexdigest()[:8]}"
                    processes.append({
                        "id": proc_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "pid": info['pid'],
                        "ppid": info.get('ppid', 0),
                        "name": info.get('name', 'unknown'),
                        "executable_path": exe,
                        "working_directory": cwd,
                        "command_line": cmdline,
                        "user": info.get('username') or "N/A",
                        "cpu_percent": info.get('cpu_percent', 0.0) or 0.0,
                        "memory_kb": mem_kb,
                        "threads": info.get('num_threads', 1),
                        "state": info.get('status', 'running'),
                        "start_time": start_iso,
                        "sha256": exe_sha256,
                        "source": "psutil Process Table",
                        "status": "COLLECTED",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        return sorted(processes, key=lambda x: x["pid"])

    def collect_windows_prefetch(self) -> Dict[str, Any]:
        """Check and parse C:\\Windows\\Prefetch directory."""
        prefetch_dir = r"C:\Windows\Prefetch"
        if not os.path.exists(prefetch_dir):
            return {"status": "NOT_PRESENT", "items": [], "count": 0, "path": prefetch_dir}

        try:
            files = os.listdir(prefetch_dir)
        except PermissionError:
            return {
                "status": "PERMISSION_REQUIRED",
                "items": [],
                "count": 0,
                "path": prefetch_dir,
                "message": "Access to C:\\Windows\\Prefetch requires Administrator privileges."
            }
        except Exception as e:
            return {"status": "COLLECTION_ERROR", "items": [], "count": 0, "error": str(e)}

        pf_files = [f for f in files if f.upper().endswith(".PF")]
        if not pf_files:
            return {"status": "NO_EVIDENCE_FOUND", "items": [], "count": 0, "path": prefetch_dir}

        items = []
        for pf in pf_files[:150]:
            full_p = os.path.join(prefetch_dir, pf)
            try:
                st = os.stat(full_p)
                items.append({
                    "name": pf,
                    "path": full_p,
                    "size_bytes": st.st_size,
                    "timestamp": _to_iso(st.st_mtime),
                    "created": _to_iso(st.st_ctime),
                    "sha256": _hash_file(full_p),
                    "source": "C:\\Windows\\Prefetch",
                    "status": "COLLECTED"
                })
            except Exception:
                continue

        return {
            "status": "COLLECTED" if items else "NO_EVIDENCE_FOUND",
            "items": items,
            "count": len(items),
            "total_detected": len(pf_files),
            "path": prefetch_dir
        }

    def collect_windows_userassist(self) -> Dict[str, Any]:
        """Parse HKCU UserAssist for application execution and run counts."""
        if not winreg:
            return {"status": "NOT_SUPPORTED", "items": [], "count": 0}

        ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        items = []
        try:
            ua_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_path, 0, winreg.KEY_READ)
            num_guids = winreg.QueryInfoKey(ua_key)[0]
            for i in range(num_guids):
                guid_name = winreg.EnumKey(ua_key, i)
                try:
                    count_key = winreg.OpenKey(ua_key, f"{guid_name}\\Count", 0, winreg.KEY_READ)
                    num_values = winreg.QueryInfoKey(count_key)[1]
                    for j in range(num_values):
                        val_name, val_data, _ = winreg.EnumValue(count_key, j)
                        decoded_name = _rot13(val_name)
                        # Extract run count if raw data is binary (44 or 72 bytes)
                        run_count = None
                        last_exec = None
                        if isinstance(val_data, bytes):
                            if len(val_data) >= 8:
                                import struct
                                # Bytes 4-8 usually contain run count in Win7+
                                run_count = struct.unpack_from("<I", val_data, 4)[0]
                            if len(val_data) >= 68:
                                # Windows 7/10/11 72-byte structure has FILETIME at byte 60
                                ft = struct.unpack_from("<Q", val_data, 60)[0]
                                if ft > 0:
                                    # Convert Windows FILETIME (100-ns intervals since 1601)
                                    epoch_s = (ft / 10000000.0) - 11644473600
                                    if epoch_s > 0:
                                        last_exec = datetime.fromtimestamp(epoch_s, tz=timezone.utc).isoformat()

                        items.append({
                            "name": os.path.basename(decoded_name),
                            "raw_name": decoded_name,
                            "guid": guid_name,
                            "run_count": run_count,
                            "timestamp": last_exec or datetime.now(timezone.utc).isoformat(),
                            "source": f"HKCU\\{ua_path}\\{guid_name}\\Count",
                            "status": "COLLECTED"
                        })
                    winreg.CloseKey(count_key)
                except Exception:
                    continue
            winreg.CloseKey(ua_key)
        except Exception as e:
            return {"status": "COLLECTION_ERROR", "items": [], "count": 0, "error": str(e)}

        return {
            "status": "COLLECTED" if items else "NO_EVIDENCE_FOUND",
            "items": items,
            "count": len(items)
        }

    def collect_windows_amcache(self) -> Dict[str, Any]:
        """Check C:\\Windows\\appcompat\\Programs\\Amcache.hve."""
        amcache_path = r"C:\Windows\appcompat\Programs\Amcache.hve"
        if not os.path.exists(amcache_path):
            return {"status": "NOT_PRESENT", "items": [], "count": 0, "path": amcache_path}

        try:
            st = os.stat(amcache_path)
            f_hash = _hash_file(amcache_path)
            return {
                "status": "COLLECTED",
                "items": [{
                    "name": "Amcache.hve",
                    "path": amcache_path,
                    "size_bytes": st.st_size,
                    "modified": _to_iso(st.st_mtime),
                    "created": _to_iso(st.st_ctime),
                    "sha256": f_hash,
                    "source": "Windows AppCompat Programs Hive",
                    "status": "COLLECTED"
                }],
                "count": 1,
                "path": amcache_path
            }
        except PermissionError:
            return {
                "status": "PERMISSION_REQUIRED",
                "items": [],
                "count": 0,
                "path": amcache_path,
                "message": "Administrator privileges required to inspect Amcache.hve directly."
            }
        except Exception as e:
            return {"status": "COLLECTION_ERROR", "items": [], "count": 0, "error": str(e)}

    def collect_recent_files(self) -> List[Dict[str, Any]]:
        """Collect recent file shortcuts or recent documents."""
        recent_items: List[Dict[str, Any]] = []

        if self.os_type == "Windows":
            appdata = os.environ.get("APPDATA", "")
            recent_dir = os.path.join(appdata, "Microsoft", "Windows", "Recent")
            if os.path.isdir(recent_dir):
                try:
                    for f in os.listdir(recent_dir)[:200]:
                        full_f = os.path.join(recent_dir, f)
                        if os.path.isfile(full_f):
                            st = os.stat(full_f)
                            recent_items.append({
                                "id": f"REC-{hashlib.md5(f.encode()).hexdigest()[:10]}",
                                "name": f,
                                "path": full_f,
                                "size_bytes": st.st_size,
                                "modified": _to_iso(st.st_mtime),
                                "created": _to_iso(st.st_ctime),
                                "source": recent_dir,
                                "status": "COLLECTED",
                                "timestamp": _to_iso(st.st_mtime)
                            })
                except Exception:
                    pass

        elif self.os_type == "Linux":
            xbel = os.path.expanduser("~/.local/share/recently-used.xbel")
            if os.path.isfile(xbel):
                try:
                    st = os.stat(xbel)
                    recent_items.append({
                        "id": f"REC-{hashlib.md5(xbel.encode()).hexdigest()[:10]}",
                        "name": "recently-used.xbel",
                        "path": xbel,
                        "size_bytes": st.st_size,
                        "modified": _to_iso(st.st_mtime),
                        "source": xbel,
                        "status": "COLLECTED",
                        "timestamp": _to_iso(st.st_mtime)
                    })
                except Exception:
                    pass

        return recent_items

    def collect_windows_recycle_bin(self) -> List[Dict[str, Any]]:
        """Inspect $Recycle.Bin on Windows."""
        rb_items: List[Dict[str, Any]] = []
        drives = ["C:\\"]
        for d in drives:
            rb_dir = os.path.join(d, "$Recycle.Bin")
            if not os.path.isdir(rb_dir):
                continue
            try:
                count = 0
                for root, dirs, files in os.walk(rb_dir):
                    for f in files:
                        if count >= 50:
                            break
                        full_f = os.path.join(root, f)
                        try:
                            st = os.stat(full_f)
                            rb_items.append({
                                "id": f"RB-{hashlib.md5(full_f.encode()).hexdigest()[:10]}",
                                "name": f,
                                "path": full_f,
                                "size_bytes": st.st_size,
                                "modified": _to_iso(st.st_mtime),
                                "source": "$Recycle.Bin",
                                "status": "COLLECTED",
                                "sha256": _hash_file(full_f, max_size_mb=2) if st.st_size <= 2*1024*1024 else None,
                                "timestamp": _to_iso(st.st_mtime)
                            })
                            count += 1
                        except Exception:
                            continue
                    if count >= 50:
                        break
            except PermissionError:
                rb_items.append({
                    "id": f"RB-PERM-{hashlib.md5(rb_dir.encode()).hexdigest()[:10]}",
                    "name": "$Recycle.Bin",
                    "path": rb_dir,
                    "status": "PERMISSION_REQUIRED",
                    "source": "$Recycle.Bin",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            except Exception:
                pass
        return rb_items

    def collect_posix_trash(self) -> List[Dict[str, Any]]:
        """Check POSIX user Trash (~/.local/share/Trash)."""
        trash_dir = os.path.expanduser("~/.local/share/Trash/files")
        items: List[Dict[str, Any]] = []
        if os.path.isdir(trash_dir):
            try:
                for f in os.listdir(trash_dir):
                    full_p = os.path.join(trash_dir, f)
                    if os.path.isfile(full_p):
                        st = os.stat(full_p)
                        items.append({
                            "id": f"TRASH-{hashlib.md5(f.encode()).hexdigest()[:10]}",
                            "name": f,
                            "path": full_p,
                            "size_bytes": st.st_size,
                            "modified": _to_iso(st.st_mtime),
                            "source": trash_dir,
                            "status": "COLLECTED",
                            "timestamp": _to_iso(st.st_mtime)
                        })
            except Exception:
                pass
        return items

    def collect_zone_identifier_files(self) -> List[Dict[str, Any]]:
        """Scan user Downloads directory for files containing Zone.Identifier ADS."""
        zone_items: List[Dict[str, Any]] = []
        user_prof = os.environ.get("USERPROFILE", "")
        downloads_dir = os.path.join(user_prof, "Downloads")
        if not os.path.isdir(downloads_dir):
            return zone_items

        try:
            for fname in os.listdir(downloads_dir)[:200]:
                full_path = os.path.join(downloads_dir, fname)
                if not os.path.isfile(full_path):
                    continue
                ads = full_path + ":Zone.Identifier"
                try:
                    if os.path.exists(ads):
                        with open(ads, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        lines = [l.strip() for l in content.splitlines() if l.strip()]
                        zone_dict = {}
                        for l in lines:
                            if "=" in l:
                                k, v = l.split("=", 1)
                                zone_dict[k.strip()] = v.strip()

                        st = os.stat(full_path)
                        zid = f"ZI-{hashlib.md5(full_path.encode()).hexdigest()[:10]}"
                        zone_items.append({
                            "id": zid,
                            "name": fname,
                            "path": full_path,
                            "zone_id": zone_dict.get("ZoneId", "3"),
                            "referrer_url": zone_dict.get("ReferrerUrl", ""),
                            "host_url": zone_dict.get("HostUrl", ""),
                            "size_bytes": st.st_size,
                            "sha256": _hash_file(full_path) if st.st_size <= 10*1024*1024 else None,
                            "source": f"{full_path}:Zone.Identifier",
                            "status": "COLLECTED",
                            "timestamp": _to_iso(st.st_mtime)
                        })
                except Exception:
                    continue
        except Exception:
            pass

        return zone_items
