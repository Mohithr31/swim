"""
Unit & Integration Tests for JOCKY Live Continuous Monitoring & Browser Delta Collection Subsystem
"""
import os
import json
import tempfile
import sqlite3
import pytest
from datetime import datetime, timezone

from collector.browser_delta import BrowserDeltaCollector
from collector.live_monitor import LiveSpoolQueue, LiveMonitorEngine
from server.database import init_db
from server.models import LiveEventModel, BrowserArtifactModel
import server.server as srv
from server.server import app


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    init_db(db_path)
    old_env = os.environ.get("JOCKY_DB")
    old_srv_db = srv.DB_PATH
    os.environ["JOCKY_DB"] = db_path
    srv.DB_PATH = db_path
    yield db_path
    if old_env is not None:
        os.environ["JOCKY_DB"] = old_env
    else:
        os.environ.pop("JOCKY_DB", None)
    srv.DB_PATH = old_srv_db
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass




def test_browser_search_query_extraction():
    url = "https://www.google.com/search?q=dfir+forensic+investigation+tools&hl=en"
    res = BrowserDeltaCollector.extract_search_query(url)
    assert res is not None
    assert res["search_provider"] == "Google Search"
    assert res["query"] == "dfir forensic investigation tools"

    bing_url = "https://www.bing.com/search?q=mimikatz+detection+rules"
    res_bing = BrowserDeltaCollector.extract_search_query(bing_url)
    assert res_bing is not None
    assert res_bing["query"] == "mimikatz detection rules"


def test_browser_delta_deduplication():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as state_tmp:
        state_file = state_tmp.name

    collector = BrowserDeltaCollector(state_file_path=state_file)
    assert collector.state["last_chrome_rowid"] == 0

    # Simulate fake SQLite db with 100 historical rows + 3 new rows
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as db_tmp:
        sqlite_db = db_tmp.name

    conn = sqlite3.connect(sqlite_db)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
    cursor.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, total_bytes INTEGER, start_time INTEGER)")

    # Insert 100 baseline records
    for i in range(1, 101):
        cursor.execute("INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, 1, 0)",
                       (i, f"https://example.com/page{i}", f"Page {i}"))
    conn.commit()

    # Pass 1: Baseline parse
    urls1, _, max_id1 = collector._parse_sqlite_delta(sqlite_db, 0, "Test Browser")
    assert len(urls1) == 100
    assert max_id1 == 100

    # Insert 3 NEW records
    cursor.execute("INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (101, 'https://www.google.com/search?q=kernel+driver', 'Google Search', 1, 0)")
    cursor.execute("INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (102, 'https://example.com/malware', 'Malware Sample', 1, 0)")
    cursor.execute("INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (103, 'https://example.com/report', 'Forensic Report', 1, 0)")
    conn.commit()
    conn.close()

    # Pass 2: Delta parse from rowid 100 -> MUST return exactly 3 items
    urls2, _, max_id2 = collector._parse_sqlite_delta(sqlite_db, 100, "Test Browser")
    assert len(urls2) == 3
    assert max_id2 == 103

    if os.path.exists(state_file):
        os.remove(state_file)
    if os.path.exists(sqlite_db):
        os.remove(sqlite_db)


def test_offline_spool_queue():
    with tempfile.NamedTemporaryFile(suffix=".spool", delete=False) as tmp:
        spool_path = tmp.name

    queue = LiveSpoolQueue(spool_file=spool_path)
    assert queue.count() == 0

    evt1 = {"category": "PROCESS", "event_type": "PROCESS_START", "pid": 1234, "process_name": "cmd.exe"}
    evt2 = {"category": "BROWSER", "event_type": "BROWSER_VISIT", "url": "https://google.com"}

    queue.enqueue(evt1)
    queue.enqueue(evt2)
    assert queue.count() == 2

    dequeued = queue.dequeue_all()
    assert len(dequeued) == 2
    assert dequeued[0]["process_name"] == "cmd.exe"
    assert dequeued[1]["url"] == "https://google.com"
    assert queue.count() == 0

    if os.path.exists(spool_path):
        os.remove(spool_path)


def test_live_ingest_and_status_api(temp_db):
    app.config["TESTING"] = True
    with app.test_client() as client:
        # Ingest events
        payload = {
            "agent_id": "test_agent_001",
            "case_id": "case_test_live",
            "events": [
                {
                    "category": "PROCESS",
                    "event_type": "PROCESS_START",
                    "pid": 9999,
                    "process_name": "powershell.exe",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                {
                    "category": "BROWSER",
                    "event_type": "BROWSER_SEARCH",
                    "browser": "Google Chrome",
                    "query": "how to detect BYOVD attacks",
                    "source_url": "https://www.google.com/search?q=how+to+detect+BYOVD+attacks",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            ]
        }

        os.environ["JOCKY_DB"] = temp_db
        res = client.post("/api/live/ingest", json=payload)
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "success"
        assert data["data"]["ingested_count"] == 2

        # Check status API
        res_status = client.get("/api/live/status?case_id=case_test_live")
        assert res_status.status_code == 200
        sdata = res_status.get_json()
        assert sdata["metrics"]["processes_count"] == 1
        assert sdata["metrics"]["browser_artifacts_count"] == 1

        # Query browser artifacts API
        res_browser = client.get("/api/cases/case_test_live/browser_artifacts")
        assert res_browser.status_code == 200
        bdata = res_browser.get_json()
        assert bdata["count"] >= 1
        assert any("BYOVD" in str(art) for art in bdata["artifacts"])
