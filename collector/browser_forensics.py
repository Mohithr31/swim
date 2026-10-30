"""
Tiny Monitor — B1 Browser Forensics Engine
Real local browser artifact collection for Chrome, Edge, Brave, Opera, Vivaldi, Firefox.
Safely copies SQLite databases to temporary files, handles locks, read-only pragmas,
extracts history, downloads, bookmarks, search activity, profiles, domain/login evidence,
and Windows Zone.Identifier metadata.
"""
import os
import sys
import glob
import json
import shutil
import sqlite3
import tempfile
import urllib.parse
import hashlib
import platform
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple


def _to_iso(dt_or_ts) -> str:
    """Normalize timestamp to ISO-8601 UTC string."""
    if not dt_or_ts:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(dt_or_ts, datetime):
        if dt_or_ts.tzinfo is None:
            dt_or_ts = dt_or_ts.replace(tzinfo=timezone.utc)
        return dt_or_ts.astimezone(timezone.utc).isoformat()
    # Unix timestamp
    try:
        ts = float(dt_or_ts)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return str(dt_or_ts)


def _webkit_to_iso(microseconds: int) -> str:
    """Convert WebKit/Chromium timestamp (microseconds since 1601-01-01) to ISO-8601 UTC."""
    if not microseconds or microseconds <= 0:
        return datetime.now(timezone.utc).isoformat()
    try:
        # 11644473600 is seconds between 1601-01-01 and 1970-01-01
        epoch_seconds = (microseconds / 1000000.0) - 11644473600
        if epoch_seconds < 0:
            return datetime.now(timezone.utc).isoformat()
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _prtime_to_iso(microseconds: int) -> str:
    """Convert Firefox PRTime (microseconds since Unix epoch) to ISO-8601 UTC."""
    if not microseconds or microseconds <= 0:
        return datetime.now(timezone.utc).isoformat()
    try:
        epoch_seconds = microseconds / 1000000.0
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _hash_file(path: str) -> Optional[str]:
    """Calculate SHA-256 for a file safely."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _safe_sqlite_copy(src_path: str) -> Optional[str]:
    """Copy a potentially locked SQLite database to a temporary location for safe querying."""
    if not os.path.isfile(src_path):
        return None
    try:
        temp_dir = tempfile.gettempdir()
        temp_filename = f"jocky_browser_{hashlib.md5(src_path.encode()).hexdigest()}_{os.path.basename(src_path)}"
        dest_path = os.path.join(temp_dir, temp_filename)
        # Attempt copy
        shutil.copy2(src_path, dest_path)
        # Also copy WAL and SHM if present
        for ext in ["-wal", "-shm"]:
            wal_src = src_path + ext
            if os.path.exists(wal_src):
                try:
                    shutil.copy2(wal_src, dest_path + ext)
                except Exception:
                    pass
        return dest_path
    except Exception:
        # If locked or inaccessible directly, attempt byte read or fail gracefully
        return None


def extract_search_query(url: str) -> Optional[Dict[str, str]]:
    """Extract search terms from URL query strings."""
    if not url:
        return None
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        query_params = urllib.parse.parse_qs(parsed.query)

        search_providers = [
            ("google.", "q", "Google Search"),
            ("bing.com", "q", "Bing Search"),
            ("duckduckgo.com", "q", "DuckDuckGo"),
            ("yahoo.com", "p", "Yahoo Search"),
            ("youtube.com", "search_query", "YouTube Search"),
            ("github.com", "q", "GitHub Search"),
            ("reddit.com", "q", "Reddit Search"),
            ("wikipedia.org", "search", "Wikipedia Search"),
            ("amazon.", "k", "Amazon Search"),
            ("twitter.com", "q", "X / Twitter Search"),
            ("x.com", "q", "X Search"),
            ("baidu.com", "wd", "Baidu Search"),
            ("yandex.", "text", "Yandex Search"),
        ]

        for domain_pattern, param, name in search_providers:
            if domain_pattern in netloc and param in query_params:
                term = query_params[param][0].strip()
                if term:
                    return {
                        "search_provider": name,
                        "query": term,
                        "url": url,
                        "domain": parsed.netloc
                    }
    except Exception:
        pass
    return None


def is_login_url(url: str) -> bool:
    """Identify login, authentication, or sign-in pages defensively without passwords."""
    if not url:
        return False
    lower = url.lower()
    login_keywords = [
        "/login", "/signin", "/sign-in", "/log-in", "/authenticate", "/auth/",
        "/oauth", "/sso/", "/saml/", "accounts.google.com", "login.microsoftonline.com",
        "github.com/login", "auth0.com", "okta.com", "identity", "/session/new"
    ]
    return any(kw in lower for kw in login_keywords)


def parse_zone_identifier(file_path: str) -> Optional[Dict[str, str]]:
    """On Windows, parse Alternate Data Stream :Zone.Identifier for downloaded files."""
    if platform.system() != "Windows" or not file_path:
        return None
    ads_path = file_path + ":Zone.Identifier"
    try:
        if os.path.exists(ads_path):
            with open(ads_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            data = {}
            for line in content.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip()
            return data
    except Exception:
        pass
    return None


class BrowserForensicsCollector:
    """Comprehensive B1 Browser Forensics Collector."""

    def __init__(self, device_id: str = "DEV-LOCAL", case_id: str = "CAS-DEFAULT"):
        self.device_id = device_id
        self.case_id = case_id
        self.os_type = platform.system()

    def get_browser_search_paths(self) -> Dict[str, Dict[str, Any]]:
        """Resolve standard browser user data roots across Windows, Linux, and macOS."""
        browsers: Dict[str, Dict[str, Any]] = {}

        if self.os_type == "Windows":
            local_appdata = os.environ.get("LOCALAPPDATA", "")
            appdata = os.environ.get("APPDATA", "")

            browsers["Google Chrome"] = {
                "type": "chromium",
                "root": os.path.join(local_appdata, "Google", "Chrome", "User Data"),
            }
            browsers["Microsoft Edge"] = {
                "type": "chromium",
                "root": os.path.join(local_appdata, "Microsoft", "Edge", "User Data"),
            }
            browsers["Brave"] = {
                "type": "chromium",
                "root": os.path.join(local_appdata, "BraveSoftware", "Brave-Browser", "User Data"),
            }
            browsers["Opera"] = {
                "type": "opera",
                "root": os.path.join(appdata, "Opera Software", "Opera Stable"),
            }
            browsers["Vivaldi"] = {
                "type": "chromium",
                "root": os.path.join(local_appdata, "Vivaldi", "User Data"),
            }
            browsers["Mozilla Firefox"] = {
                "type": "firefox",
                "root": os.path.join(appdata, "Mozilla", "Firefox"),
            }

        elif self.os_type == "Linux":
            home = os.path.expanduser("~")
            browsers["Google Chrome"] = {
                "type": "chromium",
                "root": os.path.join(home, ".config", "google-chrome"),
            }
            browsers["Microsoft Edge"] = {
                "type": "chromium",
                "root": os.path.join(home, ".config", "microsoft-edge"),
            }
            browsers["Brave"] = {
                "type": "chromium",
                "root": os.path.join(home, ".config", "BraveSoftware", "Brave-Browser"),
            }
            browsers["Opera"] = {
                "type": "opera",
                "root": os.path.join(home, ".config", "opera"),
            }
            browsers["Vivaldi"] = {
                "type": "chromium",
                "root": os.path.join(home, ".config", "vivaldi"),
            }
            browsers["Mozilla Firefox"] = {
                "type": "firefox",
                "root": os.path.join(home, ".mozilla", "firefox"),
            }

        elif self.os_type == "Darwin":  # macOS
            home = os.path.expanduser("~")
            app_support = os.path.join(home, "Library", "Application Support")
            browsers["Google Chrome"] = {
                "type": "chromium",
                "root": os.path.join(app_support, "Google", "Chrome"),
            }
            browsers["Microsoft Edge"] = {
                "type": "chromium",
                "root": os.path.join(app_support, "Microsoft Edge"),
            }
            browsers["Brave"] = {
                "type": "chromium",
                "root": os.path.join(app_support, "BraveSoftware", "Brave-Browser"),
            }
            browsers["Opera"] = {
                "type": "opera",
                "root": os.path.join(app_support, "com.operasoftware.Opera"),
            }
            browsers["Vivaldi"] = {
                "type": "chromium",
                "root": os.path.join(app_support, "Vivaldi"),
            }
            browsers["Mozilla Firefox"] = {
                "type": "firefox",
                "root": os.path.join(app_support, "Firefox"),
            }

        return browsers

    def discover_profiles(self, browser_name: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover profile directories for a given browser."""
        root = config.get("root", "")
        btype = config.get("type", "")
        profiles = []

        if not root or not os.path.isdir(root):
            return profiles

        if btype == "chromium":
            # Check Default profile
            default_dir = os.path.join(root, "Default")
            if os.path.isdir(default_dir):
                profiles.append({"name": "Default", "path": default_dir, "browser": browser_name})

            # Check Profile 1, Profile 2, etc.
            for item in os.listdir(root):
                if item.startswith("Profile ") and os.path.isdir(os.path.join(root, item)):
                    profiles.append({"name": item, "path": os.path.join(root, item), "browser": browser_name})

        elif btype == "opera":
            # Opera typically stores everything in root directly
            profiles.append({"name": "Default", "path": root, "browser": browser_name})

        elif btype == "firefox":
            # Parse profiles.ini if present
            profiles_ini = os.path.join(root, "profiles.ini")
            found_any = False
            if os.path.isfile(profiles_ini):
                try:
                    import configparser
                    cp = configparser.ConfigParser()
                    cp.read(profiles_ini, encoding="utf-8")
                    for sec in cp.sections():
                        if sec.startswith("Profile") or sec.startswith("Install"):
                            path_val = cp.get(sec, "Path", fallback=None)
                            name_val = cp.get(sec, "Name", fallback=sec)
                            if path_val:
                                is_relative = cp.get(sec, "IsRelative", fallback="1") == "1"
                                full_p = os.path.join(root, path_val) if is_relative else path_val
                                if os.path.isdir(full_p):
                                    profiles.append({"name": name_val, "path": full_p, "browser": browser_name})
                                    found_any = True
                except Exception:
                    pass

            if not found_any:
                # Fallback to directory scan
                prof_dir = os.path.join(root, "Profiles")
                scan_dir = prof_dir if os.path.isdir(prof_dir) else root
                try:
                    for entry in os.listdir(scan_dir):
                        full_entry = os.path.join(scan_dir, entry)
                        if os.path.isdir(full_entry) and ("default" in entry.lower() or "release" in entry.lower()):
                            profiles.append({"name": entry, "path": full_entry, "browser": browser_name})
                except Exception:
                    pass

        return profiles

    def collect_all_browser_evidence(self) -> Dict[str, Any]:
        """Execute complete B1 browser artifact collection."""
        results = {
            "status": "NO_EVIDENCE_FOUND",
            "browser_summary": {},
            "history": [],
            "downloads": [],
            "bookmarks": [],
            "search_activity": [],
            "profiles": [],
            "artifact_files": [],
            "origin_domains": {},
            "login_evidence": [],
        }

        browser_configs = self.get_browser_search_paths()

        for bname, bconf in browser_configs.items():
            b_root = bconf.get("root", "")
            if not os.path.exists(b_root):
                results["browser_summary"][bname] = {
                    "status": "NOT_PRESENT",
                    "installed": False,
                    "profiles_count": 0,
                    "root_path": b_root
                }
                continue

            # Browser directory exists
            try:
                profiles = self.discover_profiles(bname, bconf)
            except PermissionError:
                results["browser_summary"][bname] = {
                    "status": "PERMISSION_REQUIRED",
                    "installed": True,
                    "profiles_count": 0,
                    "root_path": b_root
                }
                continue
            except Exception as e:
                results["browser_summary"][bname] = {
                    "status": "COLLECTION_ERROR",
                    "installed": True,
                    "profiles_count": 0,
                    "root_path": b_root,
                    "error": str(e)
                }
                continue

            if not profiles:
                results["browser_summary"][bname] = {
                    "status": "NO_EVIDENCE_FOUND",
                    "installed": True,
                    "profiles_count": 0,
                    "root_path": b_root
                }
                continue

            b_type = bconf.get("type")
            b_history_count = 0
            b_downloads_count = 0
            b_bookmarks_count = 0

            for prof in profiles:
                pname = prof["name"]
                ppath = prof["path"]

                # Register Profile Record
                prof_id = f"PROF-{hashlib.md5(f'{bname}_{pname}_{ppath}'.encode()).hexdigest()[:10]}"
                prof_record = {
                    "id": prof_id,
                    "device_id": self.device_id,
                    "case_id": self.case_id,
                    "browser": bname,
                    "profile": pname,
                    "path": ppath,
                    "status": "COLLECTED",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                results["profiles"].append(prof_record)

                if b_type in ("chromium", "opera"):
                    h_cnt, d_cnt = self._collect_chromium_history_and_downloads(bname, pname, ppath, results)
                    bm_cnt = self._collect_chromium_bookmarks(bname, pname, ppath, results)
                    self._collect_chromium_artifact_files(bname, pname, ppath, results)
                    b_history_count += h_cnt
                    b_downloads_count += d_cnt
                    b_bookmarks_count += bm_cnt
                elif b_type == "firefox":
                    h_cnt, d_cnt, bm_cnt = self._collect_firefox_places(bname, pname, ppath, results)
                    self._collect_firefox_artifact_files(bname, pname, ppath, results)
                    b_history_count += h_cnt
                    b_downloads_count += d_cnt
                    b_bookmarks_count += bm_cnt

            results["browser_summary"][bname] = {
                "status": "COLLECTED" if (b_history_count > 0 or b_downloads_count > 0 or b_bookmarks_count > 0) else "NO_EVIDENCE_FOUND",
                "installed": True,
                "profiles_count": len(profiles),
                "history_count": b_history_count,
                "downloads_count": b_downloads_count,
                "bookmarks_count": b_bookmarks_count,
                "root_path": b_root
            }

        # Calculate overall status
        total_items = (len(results["history"]) + len(results["downloads"]) +
                       len(results["bookmarks"]) + len(results["profiles"]))
        if total_items > 0:
            results["status"] = "COLLECTED"
        else:
            any_installed = any(s.get("installed") for s in results["browser_summary"].values())
            results["status"] = "NO_EVIDENCE_FOUND" if any_installed else "NOT_PRESENT"

        return results

    def _collect_chromium_history_and_downloads(
        self, browser: str, profile: str, profile_path: str, results: Dict[str, Any]
    ) -> Tuple[int, int]:
        """Collect History and Downloads from Chromium SQLite database."""
        history_file = os.path.join(profile_path, "History")
        if not os.path.isfile(history_file):
            return 0, 0

        temp_db = _safe_sqlite_copy(history_file)
        if not temp_db:
            return 0, 0

        h_count = 0
        d_count = 0

        conn = None
        try:
            conn = sqlite3.connect(temp_db, timeout=5.0)
            conn.row_factory = sqlite3.Row

            # 1. Query History URLs
            cur = conn.cursor()
            try:
                cur.execute("""
                    SELECT u.id, u.url, u.title, u.visit_count, u.typed_count, u.last_visit_time,
                           v.visit_time, v.from_visit
                    FROM urls u
                    LEFT JOIN visits v ON u.id = v.url
                    ORDER BY u.last_visit_time DESC
                    LIMIT 2000
                """)
                rows = cur.fetchall()
                seen_urls = set()
                for row in rows:
                    url = row["url"] or ""
                    if not url:
                        continue
                    v_time = row["visit_time"] or row["last_visit_time"] or 0
                    iso_time = _webkit_to_iso(v_time)
                    domain = urllib.parse.urlparse(url).netloc

                    item_id = f"BH-{hashlib.md5(f'{browser}_{profile}_{url}_{v_time}'.encode()).hexdigest()[:12]}"
                    if item_id in seen_urls:
                        continue
                    seen_urls.add(item_id)

                    rec = {
                        "id": item_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "browser": browser,
                        "profile": profile,
                        "url": url,
                        "title": row["title"] or "",
                        "visit_count": row["visit_count"] or 1,
                        "typed_count": row["typed_count"] or 0,
                        "timestamp": iso_time,
                        "source": f"Chromium History: {history_file}",
                        "status": "COLLECTED",
                        "sha256": None,
                        "domain": domain
                    }
                    results["history"].append(rec)
                    h_count += 1

                    # Track domain evidence
                    if domain:
                        dom_info = results["origin_domains"].setdefault(domain, {
                            "domain": domain, "visit_count": 0, "first_seen": iso_time,
                            "last_seen": iso_time, "browser": browser, "profile": profile
                        })
                        dom_info["visit_count"] += 1
                        if iso_time < dom_info["first_seen"]:
                            dom_info["first_seen"] = iso_time
                        if iso_time > dom_info["last_seen"]:
                            dom_info["last_seen"] = iso_time

                    # Search Activity
                    sq = extract_search_query(url)
                    if sq:
                        results["search_activity"].append({
                            "id": f"SQ-{hashlib.md5(f'{browser}_{profile}_{url}'.encode()).hexdigest()[:10]}",
                            "device_id": self.device_id,
                            "case_id": self.case_id,
                            "browser": browser,
                            "profile": profile,
                            "search_provider": sq["search_provider"],
                            "query": sq["query"],
                            "url": url,
                            "domain": sq["domain"],
                            "timestamp": iso_time,
                            "status": "COLLECTED"
                        })

                    # Login Evidence
                    if is_login_url(url):
                        results["login_evidence"].append({
                            "browser": browser,
                            "profile": profile,
                            "domain": domain,
                            "url": url,
                            "timestamp": iso_time,
                            "evidence_type": "LOGIN_PAGE_VISITED",
                            "status": "COLLECTED"
                        })

            except sqlite3.OperationalError:
                pass

            # 2. Query Downloads
            try:
                # downloads table structure in Chromium: current_path, target_path, start_time, end_time, total_bytes, received_bytes, state, mime_type
                cur.execute("""
                    SELECT d.id, d.current_path, d.target_path, d.start_time, d.end_time,
                           d.total_bytes, d.received_bytes, d.state, d.mime_type,
                           u.url
                    FROM downloads d
                    LEFT JOIN downloads_url_chains u ON d.id = u.id AND u.chain_index = 0
                    ORDER BY d.start_time DESC
                    LIMIT 500
                """)
                for drow in cur.fetchall():
                    target = drow["target_path"] or drow["current_path"] or ""
                    fn = os.path.basename(target) if target else "unknown"
                    start_iso = _webkit_to_iso(drow["start_time"] or 0)
                    end_iso = _webkit_to_iso(drow["end_time"] or 0) if drow["end_time"] else None
                    url = drow["url"] or ""

                    # Check Zone.Identifier on Windows
                    zone_info = parse_zone_identifier(target) if target and os.path.exists(target) else None
                    zone_json = json.dumps(zone_info) if zone_info else None
                    target_sha256 = _hash_file(target) if target and os.path.isfile(target) and os.path.getsize(target) <= 10*1024*1024 else None

                    dl_raw_id = f"{browser}_{profile}_{target}_{drow['start_time']}"
                    dl_id = f"BD-{hashlib.md5(dl_raw_id.encode()).hexdigest()[:12]}"
                    dl_rec = {
                        "id": dl_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "browser": browser,
                        "profile": profile,
                        "url": url,
                        "target_path": target,
                        "filename": fn,
                        "total_bytes": drow["total_bytes"] or 0,
                        "received_bytes": drow["received_bytes"] or 0,
                        "start_time": start_iso,
                        "end_time": end_iso,
                        "mime_type": drow["mime_type"] or "",
                        "state": str(drow["state"]),
                        "timestamp": start_iso,
                        "source": f"Chromium Downloads: {history_file}",
                        "status": "COLLECTED",
                        "sha256": target_sha256,
                        "zone_identifier": zone_json
                    }
                    results["downloads"].append(dl_rec)
                    d_count += 1
            except sqlite3.OperationalError:
                pass

        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except Exception:
                    pass

        return h_count, d_count

    def _collect_chromium_bookmarks(self, browser: str, profile: str, profile_path: str, results: Dict[str, Any]) -> int:
        """Parse Chromium Bookmarks JSON file."""
        bm_file = os.path.join(profile_path, "Bookmarks")
        if not os.path.isfile(bm_file):
            return 0

        bm_count = 0
        try:
            with open(bm_file, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            roots = data.get("roots", {})

            def _traverse(node, folder_name=""):
                nonlocal bm_count
                if not isinstance(node, dict):
                    return
                ntype = node.get("type")
                name = node.get("name", "")
                if ntype == "url":
                    url = node.get("url", "")
                    date_added = _webkit_to_iso(int(node.get("date_added", 0)))
                    bm_id = f"BM-{hashlib.md5(f'{browser}_{profile}_{url}_{name}'.encode()).hexdigest()[:12]}"
                    results["bookmarks"].append({
                        "id": bm_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "browser": browser,
                        "profile": profile,
                        "title": name,
                        "url": url,
                        "folder": folder_name or "Bookmarks",
                        "date_added": date_added,
                        "timestamp": date_added,
                        "source": f"Chromium Bookmarks: {bm_file}",
                        "status": "COLLECTED"
                    })
                    bm_count += 1
                elif ntype == "folder":
                    sub_folder = f"{folder_name}/{name}" if folder_name else name
                    for child in node.get("children", []):
                        _traverse(child, sub_folder)

            for root_key in ["bookmark_bar", "other", "synced"]:
                if root_key in roots:
                    _traverse(roots[root_key], roots[root_key].get("name", root_key))

        except Exception:
            pass

        return bm_count

    def _collect_chromium_artifact_files(self, browser: str, profile: str, profile_path: str, results: Dict[str, Any]) -> None:
        """Collect file metadata for critical browser database/config files."""
        targets = ["History", "Bookmarks", "Preferences", "Cookies", "Login Data", "Web Data", "Network Action Predictor"]
        for target in targets:
            fpath = os.path.join(profile_path, target)
            if os.path.isfile(fpath):
                try:
                    st = os.stat(fpath)
                    f_hash = _hash_file(fpath) if st.st_size <= 20 * 1024 * 1024 else None
                    art_id = f"ART-BRW-{hashlib.md5(f'{browser}_{profile}_{target}'.encode()).hexdigest()[:10]}"
                    results["artifact_files"].append({
                        "id": art_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "browser": browser,
                        "profile": profile,
                        "name": target,
                        "path": fpath,
                        "size_bytes": st.st_size,
                        "modified": _to_iso(st.st_mtime),
                        "sha256": f_hash,
                        "source": "Filesystem metadata",
                        "status": "COLLECTED"
                    })
                except Exception:
                    pass

    def _collect_firefox_places(
        self, browser: str, profile: str, profile_path: str, results: Dict[str, Any]
    ) -> Tuple[int, int, int]:
        """Collect History, Downloads, and Bookmarks from Firefox places.sqlite."""
        places_file = os.path.join(profile_path, "places.sqlite")
        if not os.path.isfile(places_file):
            return 0, 0, 0

        temp_db = _safe_sqlite_copy(places_file)
        if not temp_db:
            return 0, 0, 0

        h_count = 0
        d_count = 0
        bm_count = 0

        conn = None
        try:
            conn = sqlite3.connect(temp_db, timeout=5.0)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # 1. Firefox History
            try:
                cur.execute("""
                    SELECT p.id, p.url, p.title, p.visit_count, p.typed, p.last_visit_date,
                           h.visit_date
                    FROM moz_places p
                    LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                    ORDER BY p.last_visit_date DESC
                    LIMIT 2000
                """)
                seen_places = set()
                for row in cur.fetchall():
                    url = row["url"] or ""
                    if not url:
                        continue
                    v_date = row["visit_date"] or row["last_visit_date"] or 0
                    iso_time = _prtime_to_iso(v_date)
                    domain = urllib.parse.urlparse(url).netloc

                    item_id = f"FFH-{hashlib.md5(f'{browser}_{profile}_{url}_{v_date}'.encode()).hexdigest()[:12]}"
                    if item_id in seen_places:
                        continue
                    seen_places.add(item_id)

                    results["history"].append({
                        "id": item_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "browser": browser,
                        "profile": profile,
                        "url": url,
                        "title": row["title"] or "",
                        "visit_count": row["visit_count"] or 1,
                        "typed_count": row["typed"] or 0,
                        "timestamp": iso_time,
                        "source": f"Firefox places.sqlite: {places_file}",
                        "status": "COLLECTED",
                        "sha256": None,
                        "domain": domain
                    })
                    h_count += 1

                    # Domain tracking
                    if domain:
                        dom_info = results["origin_domains"].setdefault(domain, {
                            "domain": domain, "visit_count": 0, "first_seen": iso_time,
                            "last_seen": iso_time, "browser": browser, "profile": profile
                        })
                        dom_info["visit_count"] += 1

                    # Search Activity
                    sq = extract_search_query(url)
                    if sq:
                        results["search_activity"].append({
                            "id": f"FFSQ-{hashlib.md5(f'{browser}_{profile}_{url}'.encode()).hexdigest()[:10]}",
                            "device_id": self.device_id,
                            "case_id": self.case_id,
                            "browser": browser,
                            "profile": profile,
                            "search_provider": sq["search_provider"],
                            "query": sq["query"],
                            "url": url,
                            "domain": sq["domain"],
                            "timestamp": iso_time,
                            "status": "COLLECTED"
                        })

                    # Login Evidence
                    if is_login_url(url):
                        results["login_evidence"].append({
                            "browser": browser,
                            "profile": profile,
                            "domain": domain,
                            "url": url,
                            "timestamp": iso_time,
                            "evidence_type": "LOGIN_PAGE_VISITED",
                            "status": "COLLECTED"
                        })

            except sqlite3.OperationalError:
                pass

            # 2. Firefox Bookmarks
            try:
                cur.execute("""
                    SELECT b.id, b.title, b.dateAdded, p.url
                    FROM moz_bookmarks b
                    JOIN moz_places p ON b.fk = p.id
                    WHERE b.type = 1
                    LIMIT 1000
                """)
                for brow in cur.fetchall():
                    url = brow["url"] or ""
                    title = brow["title"] or url
                    added_iso = _prtime_to_iso(brow["dateAdded"] or 0)
                    bm_id = f"FFBM-{hashlib.md5(f'{browser}_{profile}_{url}_{title}'.encode()).hexdigest()[:12]}"
                    results["bookmarks"].append({
                        "id": bm_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "browser": browser,
                        "profile": profile,
                        "title": title,
                        "url": url,
                        "folder": "Bookmarks",
                        "date_added": added_iso,
                        "timestamp": added_iso,
                        "source": f"Firefox Bookmarks: {places_file}",
                        "status": "COLLECTED"
                    })
                    bm_count += 1
            except sqlite3.OperationalError:
                pass

        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except Exception:
                    pass

        return h_count, d_count, bm_count

    def _collect_firefox_artifact_files(self, browser: str, profile: str, profile_path: str, results: Dict[str, Any]) -> None:
        """Collect Firefox artifact file metadata."""
        targets = ["places.sqlite", "favicons.sqlite", "cookies.sqlite", "formhistory.sqlite", "key4.db", "logins.json", "prefs.js"]
        for target in targets:
            fpath = os.path.join(profile_path, target)
            if os.path.isfile(fpath):
                try:
                    st = os.stat(fpath)
                    f_hash = _hash_file(fpath) if st.st_size <= 20 * 1024 * 1024 else None
                    art_id = f"ART-FF-{hashlib.md5(f'{browser}_{profile}_{target}'.encode()).hexdigest()[:10]}"
                    results["artifact_files"].append({
                        "id": art_id,
                        "device_id": self.device_id,
                        "case_id": self.case_id,
                        "browser": browser,
                        "profile": profile,
                        "name": target,
                        "path": fpath,
                        "size_bytes": st.st_size,
                        "modified": _to_iso(st.st_mtime),
                        "sha256": f_hash,
                        "source": "Filesystem metadata",
                        "status": "COLLECTED"
                    })
                except Exception:
                    pass
