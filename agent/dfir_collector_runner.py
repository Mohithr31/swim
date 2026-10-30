"""
Tiny Monitor — Comprehensive Forensic Collection Runner
Orchestrates B1-B10 artifact collectors, normalizes evidence records,
writes directly into SQLite database using fast batch transactions,
and generates evidence packaging with manifest.json.
Enforces authentic forensic states: COLLECTED, NOT_PRESENT, NOT_ACCESSIBLE,
PERMISSION_REQUIRED, NOT_SUPPORTED, NO_EVIDENCE_FOUND, COLLECTION_ERROR.
"""
import os
import sys
import json
import sqlite3
import hashlib
import platform
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from server.database import get_db_connection, init_db_schema
from collector.system_collector import SystemForensicsCollector
from collector.browser_forensics import BrowserForensicsCollector
from collector.application_forensics import ApplicationForensicsCollector
from collector.messaging_forensics import MessagingForensicsCollector
from collector.email_collector import EmailForensicsCollector
from collector.web_activity_mapper import WebActivityMapper
from collector.device_forensics import DeviceForensicsCollector
from collector.filesystem_forensics import FilesystemForensicsCollector
from collector.live_engine import LiveMonitoringEngine
from collector.packaging import EvidencePackager


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


def run_dfir_collection(
    case_id: str = "CASE-001",
    device_id: Optional[str] = None,
    output_dir: str = "evidence",
    db_path: Optional[str] = None,
    collect_all: bool = True,
    collect_browser: bool = False,
    collect_apps: bool = False,
    collect_messaging: bool = False,
    collect_email: bool = False,
    collect_devices: bool = False,
    collect_filesystem: bool = False,
    collect_network: bool = False,
    collect_system: bool = False,
) -> Dict[str, Any]:
    """Execute complete B1-B10 defensive forensic collection and store in SQLite."""
    start_time = datetime.now(timezone.utc).isoformat()
    dev_id = device_id or f"DEV-{hashlib.md5(socket.gethostname().encode()).hexdigest()[:8].upper()}"

    db_target = db_path or os.environ.get("JOCKY_DB", "jocky_forensics.db")
    conn = get_db_connection(db_target)
    conn.execute("PRAGMA busy_timeout = 20000;")
    init_db_schema(conn)

    # 1. Register or update Device
    hostname = socket.gethostname()
    os_name = f"{platform.system()} {platform.release()}"
    conn.execute("""
        INSERT INTO devices (id, hostname, os, ip_address, status, last_seen)
        VALUES (?, ?, ?, ?, 'ACTIVE', ?)
        ON CONFLICT(id) DO UPDATE SET hostname=excluded.hostname, os=excluded.os, last_seen=excluded.last_seen
    """, (dev_id, hostname, os_name, "127.0.0.1", start_time))

    # 2. Register Case
    conn.execute("""
        INSERT INTO cases (id, name, description, created_at, status)
        VALUES (?, ?, ?, ?, 'OPEN')
        ON CONFLICT(id) DO UPDATE SET status='OPEN'
    """, (case_id, f"Investigation {case_id}", "Local Forensic Triage Collection", start_time))
    conn.commit()

    collection_report = {
        "case_id": case_id,
        "device_id": dev_id,
        "start_time": start_time,
        "modules": {},
        "counts": {}
    }

    total_artifacts = 0

    # Determine what to run
    do_all = collect_all or not (collect_browser or collect_apps or collect_messaging or
                                collect_email or collect_devices or collect_filesystem or
                                collect_network or collect_system)

    # --- B7: SYSTEM FORENSICS ---
    if do_all or collect_system:
        print("[JOCKY-COLLECTOR] Collecting B7: System Forensics...", flush=True)
        sys_col = SystemForensicsCollector(device_id=dev_id, case_id=case_id)
        sys_info = sys_col.collect_system_info()
        conn.execute("""
            INSERT OR REPLACE INTO artifacts (
                id, device_id, case_id, artifact_type, category, name, path,
                source, status, sha256, size_bytes, timestamp, raw_metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"SYS-{dev_id}", dev_id, case_id, "SYSTEM_INFO", "System", hostname,
            "OS", "System Forensics Collector", sys_info["status"], None, 0,
            sys_info["timestamp"], json.dumps(sys_info)
        ))
        conn.commit()
        collection_report["modules"]["B7_System"] = sys_info["status"]
        collection_report["counts"]["system"] = 1
        total_artifacts += 1

    # --- B1: BROWSER FORENSICS ---
    b_history = []
    if do_all or collect_browser:
        print("[JOCKY-COLLECTOR] Collecting B1: Browser Forensics...", flush=True)
        brw_col = BrowserForensicsCollector(device_id=dev_id, case_id=case_id)
        brw_res = brw_col.collect_all_browser_evidence()

        # Batch Ingest Browser History
        b_history = brw_res.get("history", [])
        if b_history:
            history_rows = [
                (h["id"], dev_id, case_id, h["browser"], h["profile"], h["url"],
                 h.get("title"), h.get("visit_count", 1), h.get("typed_count", 0),
                 h["timestamp"], h["source"], h["status"], h.get("sha256"), h.get("domain"))
                for h in b_history
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO browser_history (
                    id, device_id, case_id, browser, profile, url, title,
                    visit_count, typed_count, timestamp, source, status, sha256, domain
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, history_rows)

        # Batch Ingest Browser Downloads
        b_downloads = brw_res.get("downloads", [])
        if b_downloads:
            download_rows = [
                (d["id"], dev_id, case_id, d["browser"], d["profile"], d.get("url"),
                 d.get("target_path"), d.get("filename"), d.get("total_bytes", 0),
                 d.get("received_bytes", 0), d.get("start_time"), d.get("end_time"),
                 d.get("mime_type"), d.get("state"), d["timestamp"], d["source"],
                 d["status"], d.get("sha256"), d.get("zone_identifier"))
                for d in b_downloads
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO browser_downloads (
                    id, device_id, case_id, browser, profile, url, target_path,
                    filename, total_bytes, received_bytes, start_time, end_time,
                    mime_type, state, timestamp, source, status, sha256, zone_identifier
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, download_rows)

        # Batch Ingest Browser Bookmarks
        b_bookmarks = brw_res.get("bookmarks", [])
        if b_bookmarks:
            bookmark_rows = [
                (bm["id"], dev_id, case_id, bm["browser"], bm["profile"], bm.get("title"),
                 bm["url"], bm.get("folder"), bm.get("date_added"), bm["timestamp"],
                 bm["source"], bm["status"])
                for bm in b_bookmarks
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO browser_bookmarks (
                    id, device_id, case_id, browser, profile, title, url,
                    folder, date_added, timestamp, source, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, bookmark_rows)

        # Ingest Artifact files metadata
        b_artfiles = brw_res.get("artifact_files", [])
        if b_artfiles:
            artfile_rows = [
                (af["id"], dev_id, case_id, "BROWSER_ARTIFACT_FILE", "Browser", af["name"],
                 af["path"], af["source"], af["status"], af.get("sha256"),
                 af.get("size_bytes", 0), af["modified"], json.dumps(af))
                for af in b_artfiles
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO artifacts (
                    id, device_id, case_id, artifact_type, category, name, path,
                    source, status, sha256, size_bytes, timestamp, raw_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, artfile_rows)

        conn.commit()
        collection_report["modules"]["B1_Browser"] = brw_res["status"]
        collection_report["counts"]["browser_history"] = len(b_history)
        collection_report["counts"]["browser_downloads"] = len(b_downloads)
        collection_report["counts"]["browser_bookmarks"] = len(b_bookmarks)
        total_artifacts += len(b_history) + len(b_downloads)

    # --- B5: WEB / SOCIAL ACTIVITY MAPPING ---
    if do_all or collect_browser:
        print("[JOCKY-COLLECTOR] Mapping B5: Web & Social Activity...", flush=True)
        mapper = WebActivityMapper(device_id=dev_id, case_id=case_id)
        web_res = mapper.map_from_history(b_history)
        web_items = web_res.get("items", [])
        if web_items:
            web_rows = [
                (w["id"], dev_id, case_id, w["platform"], w["domain"], w["first_seen"],
                 w["last_seen"], w["visit_count"], w["evidence_type"], w["browser"],
                 w["profile"], w["source"], w["status"], w["timestamp"])
                for w in web_items
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO web_activity (
                    id, device_id, case_id, platform, domain, first_seen,
                    last_seen, visit_count, evidence_type, browser, profile,
                    source, status, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, web_rows)
            conn.commit()

        collection_report["modules"]["B5_WebActivity"] = web_res["status"]
        collection_report["counts"]["web_activity"] = len(web_items)
        total_artifacts += len(web_items)

    # --- B2: APPLICATION FORENSICS ---
    if do_all or collect_apps:
        print("[JOCKY-COLLECTOR] Collecting B2: Application Forensics...", flush=True)
        app_col = ApplicationForensicsCollector(device_id=dev_id, case_id=case_id)
        app_res = app_col.collect_all_application_evidence()

        # Batch Ingest Installed Apps
        installed_apps = app_res.get("installed_applications", [])
        if installed_apps:
            app_rows = [
                (app["id"], dev_id, case_id, app["name"], app.get("version"),
                 app.get("publisher"), app.get("install_path"), app.get("install_date"),
                 app.get("uninstall_string"), app.get("category"), app["source"],
                 app["status"], app.get("sha256"), app["timestamp"])
                for app in installed_apps
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO applications (
                    id, device_id, case_id, name, version, publisher,
                    install_path, install_date, uninstall_string, category,
                    source, status, sha256, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, app_rows)

        # Batch Ingest Running Processes
        running_procs = app_res.get("running_processes", [])
        if running_procs:
            proc_rows = [
                (p["id"], dev_id, case_id, p["pid"], p.get("ppid", 0), p["name"],
                 p.get("executable_path"), p.get("command_line"), p.get("user"),
                 p.get("cpu_percent", 0.0), p.get("memory_kb", 0), p.get("threads", 1),
                 p.get("state"), p.get("start_time"), p.get("sha256"), p["source"],
                 p["status"], p["timestamp"])
                for p in running_procs
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO processes (
                    id, device_id, case_id, pid, ppid, name, executable_path,
                    command_line, user, cpu_percent, memory_kb, threads,
                    state, start_time, sha256, source, status, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, proc_rows)

        # Ingest Prefetch / UserAssist
        pf_items = app_res.get("prefetch", {}).get("items", [])
        if pf_items:
            pf_rows = [
                (f"PF-{hashlib.md5(pf['path'].encode()).hexdigest()[:10]}",
                 dev_id, case_id, "PREFETCH", "Application", pf["name"], pf["path"],
                 pf["source"], pf["status"], pf.get("sha256"), pf.get("size_bytes", 0),
                 pf["timestamp"], json.dumps(pf))
                for pf in pf_items
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO artifacts (
                    id, device_id, case_id, artifact_type, category, name, path,
                    source, status, sha256, size_bytes, timestamp, raw_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, pf_rows)

        ua_items = app_res.get("userassist", {}).get("items", [])
        if ua_items:
            ua_rows = [
                (f"UA-{hashlib.md5(ua['raw_name'].encode()).hexdigest()[:10]}",
                 dev_id, case_id, "USERASSIST", "Application", ua["name"], ua["raw_name"],
                 ua["source"], ua["status"], None, 0, ua["timestamp"], json.dumps(ua))
                for ua in ua_items
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO artifacts (
                    id, device_id, case_id, artifact_type, category, name, path,
                    source, status, sha256, size_bytes, timestamp, raw_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ua_rows)

        conn.commit()
        collection_report["modules"]["B2_Applications"] = app_res["status"]
        collection_report["counts"]["applications"] = len(installed_apps)
        collection_report["counts"]["processes"] = len(running_procs)
        total_artifacts += len(installed_apps) + len(running_procs)

    # --- B3: MESSAGING FORENSICS ---
    if do_all or collect_messaging:
        print("[JOCKY-COLLECTOR] Collecting B3: Messaging Forensics...", flush=True)
        msg_col = MessagingForensicsCollector(device_id=dev_id, case_id=case_id)
        msg_res = msg_col.collect_all_messaging_evidence()
        msgs = msg_res.get("messages", [])
        if msgs:
            msg_rows = [
                (m["id"], dev_id, case_id, m["app_name"], m.get("profile_dir"),
                 m.get("db_path"), m.get("message_id"), m.get("conversation_id"),
                 m.get("sender"), m.get("recipient"), m.get("direction"),
                 m.get("text_snippet"), m.get("message_count", 1),
                 m.get("attachment_names"), m.get("attachment_metadata"),
                 m["timestamp"], m["source"], m["status"], m.get("sha256"))
                for m in msgs
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO messages (
                    id, device_id, case_id, app_name, profile_dir, db_path,
                    message_id, conversation_id, sender, recipient, direction,
                    text_snippet, message_count, attachment_names, attachment_metadata,
                    timestamp, source, status, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, msg_rows)
            conn.commit()

        collection_report["modules"]["B3_Messaging"] = msg_res["status"]
        collection_report["counts"]["messages"] = len(msgs)
        total_artifacts += len(msgs)

    # --- B4: EMAIL FORENSICS ---
    if do_all or collect_email:
        print("[JOCKY-COLLECTOR] Collecting B4: Email Forensics...", flush=True)
        eml_col = EmailForensicsCollector(device_id=dev_id, case_id=case_id)
        eml_res = eml_col.collect_all_email_evidence()
        eml_msgs = eml_res.get("messages", [])
        if eml_msgs:
            eml_rows = [
                (em["id"], dev_id, case_id, em["client_name"], em.get("mailbox_name"),
                 em.get("mailbox_path"), em.get("message_id"), em.get("from_addr"),
                 em.get("to_addr"), em.get("cc_addr"), em.get("subject"),
                 em.get("date"), em.get("body_snippet"), em.get("has_attachments", 0),
                 em["timestamp"], em["source"], em["status"], em.get("sha256"))
                for em in eml_msgs
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO email_messages (
                    id, device_id, case_id, client_name, mailbox_name, mailbox_path,
                    message_id, from_addr, to_addr, cc_addr, subject, date,
                    body_snippet, has_attachments, timestamp, source, status, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, eml_rows)
            conn.commit()

        collection_report["modules"]["B4_Email"] = eml_res["status"]
        collection_report["counts"]["email_messages"] = len(eml_msgs)
        total_artifacts += len(eml_msgs)

    # --- B6: DEVICE FORENSICS ---
    if do_all or collect_devices:
        print("[JOCKY-COLLECTOR] Collecting B6: Device Forensics...", flush=True)
        dev_col = DeviceForensicsCollector(device_id=dev_id, case_id=case_id)
        dev_res = dev_col.collect_all_device_evidence()
        dev_items = dev_res.get("unified_records", [])
        if dev_items:
            dev_rows = [
                (d["id"], dev_id, case_id, d["device_type"], d["device_name"],
                 d.get("vendor"), d.get("product"), d.get("serial_number"),
                 d.get("hardware_id"), d.get("drive_letter"), d.get("interface"),
                 d["status"], d.get("connection_time"), d.get("disconnection_time"),
                 d.get("raw_details"), d["source"], d["timestamp"])
                for d in dev_items
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO devices_artifacts (
                    id, device_id, case_id, device_type, device_name, vendor,
                    product, serial_number, hardware_id, drive_letter, interface,
                    status, connection_time, disconnection_time, raw_details,
                    source, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, dev_rows)
            conn.commit()

        collection_report["modules"]["B6_Devices"] = dev_res["status"]
        collection_report["counts"]["device_artifacts"] = len(dev_items)
        total_artifacts += len(dev_items)

    # --- B8: FILESYSTEM FORENSICS ---
    if do_all or collect_filesystem:
        print("[JOCKY-COLLECTOR] Collecting B8: Filesystem Forensics...", flush=True)
        fs_col = FilesystemForensicsCollector(device_id=dev_id, case_id=case_id, max_files_per_category=50)
        fs_res = fs_col.collect_all_filesystem_evidence()
        fs_files = fs_res.get("files", [])
        if fs_files:
            fs_rows = [
                (f["id"], dev_id, case_id, f["path"], f["filename"], f.get("extension"),
                 f.get("size_bytes", 0), f.get("created_time"), f.get("modified_time"),
                 f.get("accessed_time"), f.get("file_type"), f.get("owner"),
                 f.get("permissions"), f.get("sha256"), f.get("is_directory", 0),
                 f.get("is_deleted", 0), f["source"], f["status"], f["timestamp"])
                for f in fs_files
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO filesystem (
                    id, device_id, case_id, path, filename, extension,
                    size_bytes, created_time, modified_time, accessed_time,
                    file_type, owner, permissions, sha256, is_directory,
                    is_deleted, source, status, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, fs_rows)
            conn.commit()

        collection_report["modules"]["B8_Filesystem"] = fs_res["status"]
        collection_report["counts"]["filesystem"] = len(fs_files)
        total_artifacts += len(fs_files)

    # --- B9: LIVE SNAPSHOT & TIMELINE ---
    if do_all or collect_network:
        print("[JOCKY-COLLECTOR] Capturing B9: Live Telemetry Snapshot & Timeline...", flush=True)
        live_eng = LiveMonitoringEngine(db_path=db_target, device_id=dev_id, case_id=case_id)
        snap_res = live_eng.trigger_snapshot_now()
        collection_report["modules"]["B9_LiveTimeline"] = snap_res["status"]
        collection_report["counts"]["live_events"] = snap_res.get("events_captured", 0)
        total_artifacts += snap_res.get("events_captured", 0)

    # Correlate initial findings
    conn.execute("""
        INSERT OR REPLACE INTO findings (
            id, device_id, case_id, title, category, severity, description,
            evidence_refs, recommendations, mitre_technique, timestamp, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        f"FIND-{case_id}-001", dev_id, case_id,
        "Point-in-Time Forensic Triage Baseline Established",
        "Triage", "INFO",
        f"Collector captured {total_artifacts} total artifacts across endpoint subsystems.",
        "artifacts, processes, browser_history",
        "Review high-activity domains and external media connections.",
        "T1082 - System Information Discovery",
        datetime.now(timezone.utc).isoformat(), "CONFIRMED"
    ))

    end_time = datetime.now(timezone.utc).isoformat()
    collection_report["end_time"] = end_time
    collection_report["total_artifacts"] = total_artifacts

    # Record Collection Run in database
    conn.execute("""
        INSERT OR REPLACE INTO collection_runs (
            id, device_id, case_id, start_time, end_time, status,
            collector_version, platform, options, total_artifacts, summary_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        f"RUN-{case_id}-{hashlib.md5(start_time.encode()).hexdigest()[:8]}",
        dev_id, case_id, start_time, end_time, "COMPLETED",
        "5.2.0-DFIR-PRO", platform.system(),
        json.dumps({"all": do_all, "browser": collect_browser}),
        total_artifacts, json.dumps(collection_report)
    ))
    conn.commit()
    conn.close()

    # --- B10: EVIDENCE PACKAGING ---
    print("[JOCKY-COLLECTOR] Packaging B10: Evidence Package with SHA-256 Manifest...", flush=True)
    packager = EvidencePackager(output_dir=output_dir)
    manifest = packager.create_evidence_package(
        case_id=case_id,
        device_id=dev_id,
        db_path=db_target,
        start_time=start_time,
        end_time=end_time
    )

    collection_report["manifest"] = manifest
    collection_report["package_zip"] = manifest.get("package_zip_path")
    collection_report["package_hash"] = manifest.get("package_hash")

    return collection_report
