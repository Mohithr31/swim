"""
JOCKY Browser Artifact & Delta Collector Module
Parses Chrome and Edge SQLite history and download databases safely via temporary copies.
Tracks last visited `rowid` and `visit_time` to ingest ONLY NEW OR CHANGED RECORDS.
Extracts Google search query parameters (https://www.google.com/search?q=...).
"""
import os
import shutil
import sqlite3
import tempfile
import json
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


class BrowserDeltaCollector:
    """Safely inspects local browser history and download SQLite databases with delta tracking."""

    def __init__(self, state_file_path: Optional[str] = None):
        self.state_file = state_file_path or os.path.join(tempfile.gettempdir(), "jocky_browser_state.json")
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"last_chrome_rowid": 0, "last_edge_rowid": 0, "last_visit_time": 0}

    def _save_state(self) -> None:
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def extract_search_query(url: str) -> Optional[Dict[str, str]]:
        """Parses Google / Bing search queries from URLs."""
        if not url:
            return None
        try:
            parsed = urllib.parse.urlparse(url)
            if "google." in parsed.netloc or "bing." in parsed.netloc or "duckduckgo." in parsed.netloc:
                qs = urllib.parse.parse_qs(parsed.query)
                q_list = qs.get("q") or qs.get("p")
                if q_list and q_list[0]:
                    return {
                        "search_provider": "Google Search" if "google" in parsed.netloc else "Search Engine",
                        "query": q_list[0],
                        "raw_url": url
                    }
        except Exception:
            pass
        return None

    def collect_browser_deltas(self) -> Dict[str, Any]:
        """Collects newly added browser history and download records."""
        history_records = []
        download_records = []
        search_queries = []

        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
        chrome_db = os.path.join(user_profile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History")
        edge_db = os.path.join(user_profile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History")

        for browser_name, db_path, state_key in [("Google Chrome", chrome_db, "last_chrome_rowid"), ("Microsoft Edge", edge_db, "last_edge_rowid")]:
            if os.path.exists(db_path):
                last_rowid = self.state.get(state_key, 0)
                new_urls, new_downloads, max_rowid = self._parse_sqlite_delta(db_path, last_rowid, browser_name)

                for item in new_urls:
                    history_records.append(item)
                    sq = self.extract_search_query(item.get("url", ""))
                    if sq:
                        search_queries.append({
                            "timestamp": item.get("timestamp"),
                            "browser": browser_name,
                            "profile": "Default",
                            "search_provider": sq["search_provider"],
                            "query": sq["query"],
                            "source_url": sq["raw_url"],
                            "source": "Local Browser History Artifact"
                        })

                for dl in new_downloads:
                    download_records.append(dl)

                if max_rowid > last_rowid:
                    self.state[state_key] = max_rowid

        self._save_state()

        return {
            "mode": "DELTA_COLLECTION",
            "new_history_count": len(history_records),
            "new_downloads_count": len(download_records),
            "new_searches_count": len(search_queries),
            "history": history_records,
            "downloads": download_records,
            "searches": search_queries
        }

    def _parse_sqlite_delta(self, db_path: str, last_rowid: int, browser_name: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
        urls = []
        downloads = []
        max_id = last_rowid

        with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as tmp:
            tmp_path = tmp.name

        try:
            shutil.copy2(db_path, tmp_path)
            conn = sqlite3.connect(tmp_path)
            cursor = conn.cursor()

            # Query URLs delta
            cursor.execute("SELECT id, url, title, visit_count, last_visit_time FROM urls WHERE id > ? ORDER BY id ASC LIMIT 200", (last_rowid,))
            rows = cursor.fetchall()
            for r in rows:
                row_id, url_val, title_val, visit_cnt, last_visit = r
                if row_id > max_id:
                    max_id = row_id

                # Chromium timestamp to ISO string conversion (microseconds since 1601-01-01)
                ts_iso = datetime.now(timezone.utc).isoformat()
                if last_visit and last_visit > 0:
                    try:
                        us = last_visit - 11644473600000000
                        if us > 0:
                            ts_iso = datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc).isoformat()
                    except Exception:
                        pass

                urls.append({
                    "row_id": row_id,
                    "browser": browser_name,
                    "profile": "Default",
                    "url": url_val,
                    "title": title_val or "Untitled",
                    "visit_count": visit_cnt,
                    "timestamp": ts_iso,
                    "source": "LOCAL_BROWSER_ARTIFACT"
                })

            # Query Downloads delta
            try:
                cursor.execute("SELECT id, target_path, tab_url, total_bytes, start_time FROM downloads WHERE id > ? ORDER BY id ASC LIMIT 50", (last_rowid,))
                drows = cursor.fetchall()
                for dr in drows:
                    did, tpath, tab_url, bytes_sz, stime = dr
                    downloads.append({
                        "download_id": did,
                        "browser": browser_name,
                        "filename": os.path.basename(tpath),
                        "file_path": tpath,
                        "url": tab_url,
                        "size_bytes": bytes_sz,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source": "LOCAL_BROWSER_DOWNLOAD_ARTIFACT"
                    })
            except Exception:
                pass

            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

        return urls, downloads, max_id


def collect_browser_delta_telemetry() -> Dict[str, Any]:
    collector = BrowserDeltaCollector()
    return collector.collect_browser_deltas()
