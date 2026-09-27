"""
JOCKY Live Continuous Forensic Collector Subsystem
Event-driven process, filesystem, and event log monitoring combined with periodic delta collection.
Includes local offline spool queue (.jockyspool) for server disconnect resilience.
"""
import os
import sys
import time
import json
import socket
import tempfile
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from collector.browser_delta import BrowserDeltaCollector


class LiveSpoolQueue:
    """Manages local persistent event queue when server connection is offline."""

    def __init__(self, spool_file: Optional[str] = None):
        self.spool_file = spool_file or os.path.join(tempfile.gettempdir(), "jocky_live.spool")

    def enqueue(self, event: Dict[str, Any]) -> None:
        try:
            with open(self.spool_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

    def dequeue_all(self) -> List[Dict[str, Any]]:
        return self.pop_all()

    def pop_all(self) -> List[Dict[str, Any]]:
        events = []
        if os.path.exists(self.spool_file):
            try:
                with open(self.spool_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            events.append(json.loads(line.strip()))
                os.remove(self.spool_file)
            except Exception:
                pass
        return events

    def count(self) -> int:
        if not os.path.exists(self.spool_file):
            return 0
        try:
            with open(self.spool_file, "r", encoding="utf-8") as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0


class LiveMonitorEngine:
    """Continuous forensic monitoring engine running event listeners and delta pollers."""

    def __init__(self, agent_id: str, server_url: str = "http://127.0.0.1:5000"):
        self.agent_id = agent_id
        self.server_url = server_url.rstrip("/")
        self.spool_queue = LiveSpoolQueue()
        self.browser_collector = BrowserDeltaCollector()
        self.running = False
        self._known_pids = set()
        self._lock = threading.Lock()
        self.events_collected_count = 0
        self.artifacts_collected_count = 0
        self._known_physical_devices = {}

    def start(self) -> None:
        self.running = True
        print(f"[JOCKY-LIVE] Starting continuous forensic monitoring engine for agent '{self.agent_id}'...")
        # Populate initial PIDs baseline
        self._reconcile_pids()
        try:
            from collector.removable_media import get_removable_media_forensics
            self._known_physical_devices={self._physical_key(d): d for d in get_removable_media_forensics()}
        except Exception:
            self._known_physical_devices={}

    def stop(self) -> None:
        self.running = False
        print(f"[JOCKY-LIVE] Continuous forensic monitoring engine stopped.")

    def poll_cycle(self) -> List[Dict[str, Any]]:
        """Runs a single live monitoring cycle returning newly detected forensic telemetry events."""
        new_events = []
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Process Start / Termination Monitoring
        proc_events = self._check_process_changes(now_str)
        new_events.extend(proc_events)

        # 1b. Physical USB/removable-device attach/detach monitoring
        new_events.extend(self._check_physical_device_changes(now_str))

        # 2. Browser Artifact Delta Ingestion
        browser_data = self.browser_collector.collect_browser_deltas()
        for h in browser_data.get("history", []):
            new_events.append({
                "category": "BROWSER",
                "event_type": "BROWSER_VISIT",
                "timestamp": h.get("timestamp", now_str),
                "browser": h.get("browser"),
                "url": h.get("url"),
                "title": h.get("title"),
                "source": "Local Browser SQLite History"
            })
            self.artifacts_collected_count += 1

        for sq in browser_data.get("searches", []):
            new_events.append({
                "category": "BROWSER",
                "event_type": "BROWSER_SEARCH",
                "timestamp": sq.get("timestamp", now_str),
                "browser": sq.get("browser"),
                "search_provider": sq.get("search_provider"),
                "query": sq.get("query"),
                "source_url": sq.get("source_url"),
                "source": "Local Browser History Query Parameter"
            })
            self.artifacts_collected_count += 1

        for dl in browser_data.get("downloads", []):
            new_events.append({
                "category": "BROWSER",
                "event_type": "BROWSER_DOWNLOAD",
                "timestamp": dl.get("timestamp", now_str),
                "browser": dl.get("browser"),
                "filename": dl.get("filename"),
                "file_path": dl.get("file_path"),
                "url": dl.get("url"),
                "size_bytes": dl.get("size_bytes"),
                "source": "Local Browser Download Database"
            })
            self.artifacts_collected_count += 1

        with self._lock:
            self.events_collected_count += len(new_events)

        return new_events

    @staticmethod
    def _physical_key(device: Dict[str, Any]) -> str:
        return "|".join(str(device.get(k) or "") for k in ("device", "serial", "hardware_id", "device_node", "mount"))

    def _check_physical_device_changes(self, timestamp_str: str) -> List[Dict[str, Any]]:
        try:
            from collector.removable_media import get_removable_media_forensics
            current={self._physical_key(d): d for d in get_removable_media_forensics()}
        except Exception:
            return []
        events=[]
        for key,dev in current.items():
            if key not in self._known_physical_devices:
                events.append({"category":"DEVICE","event_type":"PHYSICAL_DEVICE_CONNECTED","timestamp":timestamp_str,"device":dev.get("device"),"serial":dev.get("serial"),"mount":dev.get("mount") or dev.get("device_node"),"device_type":dev.get("device_type"),"source":dev.get("evidence_type") or "Linux physical-device collector"})
        for key,dev in self._known_physical_devices.items():
            if key not in current:
                events.append({"category":"DEVICE","event_type":"PHYSICAL_DEVICE_DISCONNECTED","timestamp":timestamp_str,"device":dev.get("device"),"serial":dev.get("serial"),"mount":dev.get("mount") or dev.get("device_node"),"device_type":dev.get("device_type"),"source":dev.get("evidence_type") or "Linux physical-device collector"})
        self._known_physical_devices=current
        return events

    def _reconcile_pids(self) -> set:
        from agent.jocky_agent import collect_processes_data
        try: procs = json.loads(collect_processes_data())
        except Exception: procs = []
        self._known_pids = {p.get("pid") for p in procs if p.get("pid")}
        return self._known_pids

    def _check_process_changes(self, timestamp_str: str) -> List[Dict[str, Any]]:
        from agent.jocky_agent import collect_processes_data
        events = []
        try: current_procs = json.loads(collect_processes_data())
        except Exception: current_procs = []
        current_map = {p.get("pid"): p for p in current_procs if p.get("pid")}
        current_pids = set(current_map.keys())

        # Process starts
        new_pids = current_pids - self._known_pids
        for pid in new_pids:
            pinfo = current_map[pid]
            events.append({
                "category": "PROCESS",
                "event_type": "PROCESS_START",
                "pid": pid,
                "process_name": pinfo.get("name"),
                "executable": pinfo.get("executable"),
                "user": pinfo.get("user"),
                "command_line": pinfo.get("command_line"),
                "timestamp": timestamp_str,
                "source": "Endpoint Process Enumeration"
            })

        # Process terminations
        exited_pids = self._known_pids - current_pids
        for pid in list(exited_pids)[:20]:
            events.append({
                "category": "PROCESS",
                "event_type": "PROCESS_EXIT",
                "pid": pid,
                "process_name": f"PID_{pid}",
                "timestamp": timestamp_str,
                "source": "Endpoint Process Enumeration"
            })

        self._known_pids = current_pids
        return events
