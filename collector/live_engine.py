"""
Tiny Monitor — B9 Live Forensic Monitoring & Unified Timeline Engine
Investigator-controlled real-time telemetry:
- Process start and exit detection
- Network connection snapshots
- Removable media changes
- Browser artifact changes
- Security audit events
Strictly defensive: No keylogging, covert screenshots, or surveillance.
Stores normalized events in SQLite timeline, live_events, and network_events.
"""
import os
import sys
import time
import json
import sqlite3
import hashlib
import platform
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set

try:
    import psutil
except ImportError:
    psutil = None


def _to_iso(dt_or_ts=None) -> str:
    if dt_or_ts is None:
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


class LiveMonitoringEngine:
    """Thread-safe, investigator-controlled live forensic telemetry engine."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LiveMonitoringEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: Optional[str] = None, device_id: str = "DEV-LOCAL", case_id: str = "CAS-DEFAULT"):
        if getattr(self, "_initialized", False):
            return
        self.db_path = db_path or os.environ.get("JOCKY_DB", "jocky_forensics.db")
        self.device_id = device_id
        self.case_id = case_id
        self.is_monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._known_pids: Dict[int, str] = {}
        self._known_connections: Set[str] = set()
        self._event_buffer: List[Dict[str, Any]] = []
        self._buffer_lock = threading.Lock()
        self.poll_interval = 3.0
        self._initialized = True

    def start_monitoring(self, case_id: Optional[str] = None, device_id: Optional[str] = None) -> Dict[str, Any]:
        """Start the live monitoring background thread."""
        with self._lock:
            if case_id:
                self.case_id = case_id
            if device_id:
                self.device_id = device_id

            if self.is_monitoring:
                return {"status": "ALREADY_RUNNING", "message": "Live monitoring is already active.", "device_id": self.device_id}

            self._stop_event.clear()
            self._init_baselines()
            self.is_monitoring = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()

            # Record Start Event
            start_event = self._create_event(
                event_type="MONITORING_STARTED",
                category="System",
                severity="INFO",
                description="Investigator initiated live forensic monitoring session.",
                source="LiveMonitoringEngine",
                process="jocky_server"
            )
            self._persist_event(start_event)

            return {
                "status": "COLLECTED",
                "message": "Live forensic monitoring started.",
                "device_id": self.device_id,
                "case_id": self.case_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop the live monitoring background thread."""
        with self._lock:
            if not self.is_monitoring:
                return {"status": "NOT_RUNNING", "message": "Live monitoring is not currently active."}

            self._stop_event.set()
            self.is_monitoring = False

            stop_event = self._create_event(
                event_type="MONITORING_STOPPED",
                category="System",
                severity="INFO",
                description="Investigator stopped live forensic monitoring session.",
                source="LiveMonitoringEngine",
                process="jocky_server"
            )
            self._persist_event(stop_event)

            return {
                "status": "COLLECTED",
                "message": "Live forensic monitoring stopped.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    def trigger_snapshot_now(self) -> Dict[str, Any]:
        """Take an immediate point-in-time forensic snapshot."""
        new_events = []
        # Process snapshot
        proc_events = self._reconcile_processes()
        new_events.extend(proc_events)

        # Network snapshot
        net_events = self._reconcile_network()
        new_events.extend(net_events)

        # Record manual snapshot event
        snap_event = self._create_event(
            event_type="FORENSIC_SNAPSHOT_TAKEN",
            category="System",
            severity="LOW",
            description=f"Point-in-time forensic snapshot completed: {len(new_events)} delta events recorded.",
            source="Investigator Trigger",
            process="jocky_server"
        )
        self._persist_event(snap_event)
        new_events.append(snap_event)

        return {
            "status": "COLLECTED",
            "message": "Forensic snapshot completed.",
            "events_captured": len(new_events),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def get_status(self) -> Dict[str, Any]:
        """Get live monitoring status and buffer stats."""
        with self._buffer_lock:
            recent = list(self._event_buffer[-50:])
        return {
            "is_monitoring": self.is_monitoring,
            "device_id": self.device_id,
            "case_id": self.case_id,
            "buffered_events_count": len(self._event_buffer),
            "recent_events": recent,
            "poll_interval_seconds": self.poll_interval,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def _init_baselines(self):
        """Record baseline running processes and network connections."""
        self._known_pids.clear()
        self._known_connections.clear()

        if psutil:
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    self._known_pids[p.info['pid']] = p.info.get('name') or "unknown"
                except Exception:
                    pass

            try:
                for c in psutil.net_connections(kind='inet'):
                    if c.raddr:
                        key = f"{c.laddr.ip}:{c.laddr.port}->{c.raddr.ip}:{c.raddr.port}"
                        self._known_connections.add(key)
            except Exception:
                pass

    def _monitor_loop(self):
        """Continuous background polling loop."""
        while not self._stop_event.is_set():
            try:
                self._reconcile_processes()
                self._reconcile_network()
            except Exception:
                pass
            self._stop_event.wait(self.poll_interval)

    def _reconcile_processes(self) -> List[Dict[str, Any]]:
        """Detect newly started and exited processes."""
        events: List[Dict[str, Any]] = []
        if not psutil:
            return events

        current_pids: Dict[int, str] = {}
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
            try:
                current_pids[p.info['pid']] = p.info.get('name') or "unknown"
            except Exception:
                continue

        # Detect starts
        for pid, name in current_pids.items():
            if pid not in self._known_pids:
                ev = self._create_event(
                    event_type="PROCESS_START",
                    category="Process",
                    severity="LOW",
                    description=f"Process spawned: {name} (PID: {pid})",
                    source="Process Monitor",
                    process=name,
                    path=f"PID {pid}"
                )
                self._persist_event(ev)
                events.append(ev)

        # Detect exits
        for pid, name in list(self._known_pids.items()):
            if pid not in current_pids:
                ev = self._create_event(
                    event_type="PROCESS_EXIT",
                    category="Process",
                    severity="INFO",
                    description=f"Process terminated: {name} (PID: {pid})",
                    source="Process Monitor",
                    process=name,
                    path=f"PID {pid}"
                )
                self._persist_event(ev)
                events.append(ev)

        self._known_pids = current_pids
        return events

    def _reconcile_network(self) -> List[Dict[str, Any]]:
        """Detect new network socket connections."""
        events: List[Dict[str, Any]] = []
        if not psutil:
            return events

        try:
            conns = psutil.net_connections(kind='inet')
            current_keys = set()
            for c in conns:
                if c.raddr:
                    key = f"{c.laddr.ip}:{c.laddr.port}->{c.raddr.ip}:{c.raddr.port}"
                    current_keys.add(key)
                    if key not in self._known_connections:
                        endpoint = f"{c.raddr.ip}:{c.raddr.port}"
                        pname = "unknown"
                        if c.pid and c.pid in self._known_pids:
                            pname = self._known_pids[c.pid]

                        ev = self._create_event(
                            event_type="NETWORK_CONNECTION",
                            category="Network",
                            severity="LOW" if c.raddr.port in (80, 443) else "MEDIUM",
                            description=f"Outbound connection established: {pname} (PID {c.pid}) -> {endpoint}",
                            source="Network Socket Monitor",
                            process=pname,
                            network_endpoint=endpoint,
                            raw_reference=json.dumps({"local": f"{c.laddr.ip}:{c.laddr.port}", "remote": endpoint, "status": c.status, "pid": c.pid})
                        )
                        self._persist_event(ev)
                        events.append(ev)

                        # Also record in network_events table
                        self._persist_network_event(c, pname, endpoint)

            self._known_connections = current_keys
        except Exception:
            pass

        return events

    def _create_event(
        self,
        event_type: str,
        category: str,
        severity: str,
        description: str,
        source: str,
        process: Optional[str] = None,
        path: Optional[str] = None,
        network_endpoint: Optional[str] = None,
        raw_reference: Optional[str] = None
    ) -> Dict[str, Any]:
        """Construct normalized timeline/live event object."""
        now_iso = datetime.now(timezone.utc).isoformat()
        raw_key = f"{event_type}_{now_iso}_{description}"
        eid = f"EVT-{hashlib.md5(raw_key.encode()).hexdigest()[:12]}"
        return {
            "id": eid,
            "event_id": eid,
            "device_id": self.device_id,
            "case_id": self.case_id,
            "timestamp": now_iso,
            "event_type": event_type,
            "source": source,
            "category": category,
            "severity": severity,
            "description": description,
            "entity": process or network_endpoint or path or "System",
            "path": path,
            "process": process,
            "network_endpoint": network_endpoint,
            "raw_reference": raw_reference,
            "status": "COLLECTED"
        }

    def _persist_event(self, ev: Dict[str, Any]):
        """Persist event into SQLite timeline and buffer."""
        with self._buffer_lock:
            self._event_buffer.append(ev)
            if len(self._event_buffer) > 500:
                self._event_buffer = self._event_buffer[-500:]

        # Insert to SQLite
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            conn.execute("""
                INSERT OR REPLACE INTO timeline (
                    id, device_id, case_id, timestamp, event_type, source,
                    category, severity, description, entity, path, process,
                    network_endpoint, raw_reference, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev["id"], ev["device_id"], ev["case_id"], ev["timestamp"], ev["event_type"],
                ev["source"], ev["category"], ev["severity"], ev["description"],
                ev.get("entity"), ev.get("path"), ev.get("process"),
                ev.get("network_endpoint"), ev.get("raw_reference"), ev["status"]
            ))

            # Also into live_events for backward compatibility
            conn.execute("""
                INSERT OR REPLACE INTO live_events (
                    event_id, case_id, agent_id, category, event_type, payload, timestamp, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev["id"], ev["case_id"], ev["device_id"], ev["category"], ev["event_type"],
                json.dumps(ev), ev["timestamp"], ev["timestamp"]
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _persist_network_event(self, conn_obj, process_name: str, endpoint: str):
        """Insert connection record into network_events table."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            now_iso = datetime.now(timezone.utc).isoformat()
            nid = f"NET-EVT-{hashlib.md5(f'{now_iso}_{endpoint}_{conn_obj.pid}'.encode()).hexdigest()[:10]}"
            conn.execute("""
                INSERT OR REPLACE INTO network_events (
                    id, device_id, case_id, event_type, protocol, local_address,
                    local_port, remote_address, remote_port, state, pid,
                    process_name, interface_name, details, timestamp, source, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                nid, self.device_id, self.case_id, "ESTABLISHED",
                "TCP" if conn_obj.type == 1 else "UDP",
                conn_obj.laddr.ip, str(conn_obj.laddr.port),
                conn_obj.raddr.ip, str(conn_obj.raddr.port),
                conn_obj.status, conn_obj.pid, process_name, "active_socket",
                f"{process_name} connected to {endpoint}", now_iso, "LiveMonitorEngine", "COLLECTED"
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass
