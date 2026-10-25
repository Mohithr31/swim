"""
JOCKY Server Models & Helper Functions
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from server.database import get_db_connection


class DeviceModel:
    @staticmethod
    def register_or_update(device_id: str, hostname: str, os_name: str, ip_address: str, db_path: str = None) -> Dict[str, Any]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        cursor.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE devices SET hostname = ?, os = ?, ip_address = ?, last_seen = ?, status = 'ACTIVE'
                WHERE id = ?
            """, (hostname, os_name, ip_address, now, device_id))
        else:
            cursor.execute("""
                INSERT INTO devices (id, hostname, os, ip_address, status, last_seen)
                VALUES (?, ?, ?, ?, 'ACTIVE', ?)
            """, (device_id, hostname, os_name, ip_address, now))

        conn.commit()
        conn.close()

        return {
            "id": device_id,
            "hostname": hostname,
            "os": os_name,
            "ip_address": ip_address,
            "status": "ACTIVE",
            "last_seen": now
        }

    @staticmethod
    def list_all(db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def assign_case(device_id: str, case_id: str, db_path: str = None) -> Dict[str, Any]:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("UPDATE devices SET active_case_id = ?, status = 'ACTIVE' WHERE id = ?", (case_id, device_id))
        conn.commit()
        cur.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            raise ValueError("device_not_found")
        return dict(row)

    @staticmethod
    def get_assignment(device_id: str, db_path: str = None) -> Optional[str]:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("SELECT active_case_id FROM devices WHERE id = ?", (device_id,))
        row = cur.fetchone()
        conn.close()
        return row["active_case_id"] if row and row["active_case_id"] else None

    @staticmethod
    def delete(device_id: str, db_path: str = None) -> bool:
        """Delete a device and all associated telemetry from the database."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        try:
            # Check device exists first
            cursor.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
            if not cursor.fetchone():
                conn.close()
                return False
            # Remove all device telemetry (device_telemetry uses agent_id column)
            cursor.execute("DELETE FROM device_telemetry WHERE agent_id = ?", (device_id,))
            # Remove the device record itself
            cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            conn.commit()
            return True
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            return False
        finally:
            conn.close()


class CaseModel:
    @staticmethod
    def create(name: str, description: str = "", db_path: str = None, **metadata) -> Dict[str, Any]:
        case_id = f"case_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO cases
            (id, name, description, created_at, status, investigator_name, investigator_org,
             subject_name, authorization_ref, evidence_source, investigation_notes)
            VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?)""",
            (case_id, name, description, now, metadata.get('investigator_name',''),
             metadata.get('investigator_org',''), metadata.get('subject_name',''),
             metadata.get('authorization_ref',''), metadata.get('evidence_source',''),
             metadata.get('investigation_notes','')))
        conn.commit()
        conn.close()
        return {"id": case_id, "name": name, "description": description, "created_at": now, "status": "OPEN",
                "investigator_name": metadata.get('investigator_name',''), "investigator_org": metadata.get('investigator_org',''),
                "subject_name": metadata.get('subject_name',''), "authorization_ref": metadata.get('authorization_ref',''),
                "evidence_source": metadata.get('evidence_source',''), "investigation_notes": metadata.get('investigation_notes','')}

    @staticmethod
    def list_all(db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_id(case_id: str, db_path: str = None) -> Optional[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None


class SessionModel:
    @staticmethod
    def create(case_id: str, name: str, db_path: str = None) -> Dict[str, Any]:
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO sessions (id, case_id, name, created_at) VALUES (?, ?, ?, ?)",
                       (session_id, case_id, name, now))
        conn.commit()
        conn.close()
        return {"id": session_id, "case_id": case_id, "name": name, "created_at": now}

    @staticmethod
    def list_all(case_id: Optional[str] = None, db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if case_id:
            cursor.execute("SELECT * FROM sessions WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
        else:
            cursor.execute("SELECT * FROM sessions ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]


class JobModel:
    @staticmethod
    def create(session_id: str, agent_id: str, plan_hash: str, db_path: str = None) -> Dict[str, Any]:
        job_id = f"job_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO jobs (id, session_id, agent_id, plan_hash, status, created_at)
            VALUES (?, ?, ?, ?, 'PENDING', ?)
        """, (job_id, session_id, agent_id, plan_hash, now))
        conn.commit()
        conn.close()
        return {"id": job_id, "session_id": session_id, "agent_id": agent_id, "plan_hash": plan_hash, "status": "PENDING", "created_at": now}

    @staticmethod
    def get_pending_for_agent(agent_id: str, db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT j.*, p.plan_json FROM jobs j
            JOIN plans p ON j.plan_hash = p.plan_hash
            WHERE j.agent_id = ? AND j.status = 'PENDING'
            ORDER BY j.created_at ASC
        """, (agent_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def update_status(job_id: str, status: str, db_path: str = None) -> None:
        now = datetime.now(timezone.utc).isoformat() if status in ["COMPLETED", "FAILED"] else None
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if now:
            cursor.execute("UPDATE jobs SET status = ?, completed_at = ? WHERE id = ?", (status, now, job_id))
        else:
            cursor.execute("UPDATE jobs SET status = ? WHERE id = ?", (status, job_id))
        conn.commit()
        conn.close()

    @staticmethod
    def list_all(db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM jobs ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_id(job_id: str, db_path: str = None) -> Optional[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None


class LiveEventModel:
    @staticmethod
    def ingest_events(agent_id: str, case_id: str, events: List[Dict[str, Any]], db_path: str = None) -> Dict[str, Any]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        inserted_count = 0

        for evt in events:
            evt_id = f"evt_{uuid.uuid4().hex[:12]}"
            category = evt.get("category", "SYSTEM")
            event_type = evt.get("event_type", "GENERIC_EVENT")
            ts = evt.get("timestamp", now)
            payload_str = json.dumps(evt)

            try:
                cursor.execute("""
                    INSERT INTO live_events (event_id, case_id, agent_id, category, event_type, payload, timestamp, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (evt_id, case_id, agent_id, category, event_type, payload_str, ts, now))
                inserted_count += 1
            except Exception:
                pass

            # Ingest into browser_artifacts if category is BROWSER
            if category == "BROWSER":
                art_id = f"art_{uuid.uuid4().hex[:12]}"
                b_name = evt.get("browser", "Browser")
                b_type = event_type
                b_url = evt.get("url") or evt.get("source_url")
                b_title = evt.get("title")
                b_query = evt.get("query")
                b_file = evt.get("file_path") or evt.get("filename")

                try:
                    cursor.execute("""
                        INSERT INTO browser_artifacts (artifact_id, case_id, agent_id, browser, type, url, title, query, file_path, timestamp, raw_payload)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (art_id, case_id, agent_id, b_name, b_type, b_url, b_title, b_query, b_file, ts, payload_str))
                except Exception:
                    pass

        conn.commit()
        conn.close()
        return {"ingested_count": inserted_count, "agent_id": agent_id, "case_id": case_id}

    @staticmethod
    def get_recent_agent_events(agent_id: str, limit: int = 200, db_path: str = None) -> List[Dict[str, Any]]:
        conn=get_db_connection(db_path); rows=conn.execute("SELECT * FROM live_events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?", (agent_id,limit)).fetchall(); conn.close()
        out=[]
        for r in rows:
            d=dict(r)
            try: d["payload"]=json.loads(d.get("payload") or "{}")
            except Exception: pass
            out.append(d)
        return out

    @staticmethod
    def get_recent_events(case_id: Optional[str] = None, limit: int = 100, db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if case_id:
            cursor.execute("""
                SELECT * FROM live_events WHERE case_id = ? ORDER BY id DESC LIMIT ?
            """, (case_id, limit))
        else:
            cursor.execute("""
                SELECT * FROM live_events ORDER BY id DESC LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d["payload"])
            except Exception:
                pass
            results.append(d)
        return results

    @staticmethod
    def get_live_counts(case_id: Optional[str] = None, db_path: str = None) -> Dict[str, int]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        if case_id:
            cursor.execute("SELECT COUNT(*) FROM live_events WHERE case_id = ? AND category = 'PROCESS'", (case_id,))
            proc_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM live_events WHERE case_id = ? AND category = 'NETWORK'", (case_id,))
            net_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM browser_artifacts WHERE case_id = ?", (case_id,))
            browser_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM live_events WHERE case_id = ?", (case_id,))
            timeline_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM evidence", ())
            evd_cnt = cursor.fetchone()[0]
        else:
            cursor.execute("SELECT COUNT(*) FROM live_events WHERE category = 'PROCESS'")
            proc_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM live_events WHERE category = 'NETWORK'")
            net_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM browser_artifacts")
            browser_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM live_events")
            timeline_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM evidence")
            evd_cnt = cursor.fetchone()[0]

        conn.close()

        return {
            "processes_count": proc_cnt,
            "network_count": net_cnt,
            "browser_artifacts_count": browser_cnt,
            "timeline_events_count": timeline_cnt,
            "evidence_count": evd_cnt
        }


class BrowserArtifactModel:
    @staticmethod
    def list_artifacts(case_id: Optional[str] = None, limit: int = 100, db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if case_id:
            cursor.execute("SELECT * FROM browser_artifacts WHERE case_id = ? ORDER BY id DESC LIMIT ?", (case_id, limit))
        else:
            cursor.execute("SELECT * FROM browser_artifacts ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["raw_payload"] = json.loads(d["raw_payload"])
            except Exception:
                pass
            results.append(d)
        return results


class RecoveryModel:
    @staticmethod
    def save_recovered_file(rec_data: Dict[str, Any], case_id: str, db_path: str = None) -> None:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO recovered_files (evidence_id, candidate_id, case_id, filename, source_path, destination_path, size_bytes, sha256, recovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rec_data.get("evidence_id"),
            rec_data.get("candidate_id"),
            case_id,
            rec_data.get("filename"),
            rec_data.get("source_path"),
            rec_data.get("destination_path"),
            rec_data.get("size_bytes"),
            rec_data.get("sha256"),
            rec_data.get("recovery_timestamp")
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def list_recovered(case_id: Optional[str] = None, db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if case_id:
            cursor.execute("SELECT * FROM recovered_files WHERE case_id = ? ORDER BY id DESC", (case_id,))
        else:
            cursor.execute("SELECT * FROM recovered_files ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]


class MemoryModel:
    @staticmethod
    def save_snapshot(assessment_data: Dict[str, Any], case_id: str, db_path: str = None) -> None:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        sn_id = f"mem_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            INSERT INTO memory_snapshots (snapshot_id, case_id, assessment_type, payload, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (sn_id, case_id, assessment_data.get("assessment_type", "MEMORY_TELEMETRY"), json.dumps(assessment_data), now))
        conn.commit()
        conn.close()




class DeviceTelemetryModel:
    @staticmethod
    def upsert(agent_id: str, category: str, payload: Any, collected_at: str = None, db_path: str = None) -> Dict[str, Any]:
        now = collected_at or datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        payload_json = json.dumps(payload)
        conn.execute("""
            INSERT INTO device_telemetry (agent_id, category, payload, collected_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(agent_id, category) DO UPDATE SET
                payload=excluded.payload, collected_at=excluded.collected_at
        """, (agent_id, category, payload_json, now))
        conn.execute("UPDATE devices SET last_seen = ?, status = 'ACTIVE' WHERE id = ?", (now, agent_id))
        
        # Save historical location. The location category may contain both
        # lightweight telemetry and a list of forensic artifacts.
        if category == "location":
            location_payload = payload.get("telemetry", payload) if isinstance(payload, dict) else {}
            lat = location_payload.get("latitude")
            lon = location_payload.get("longitude")
            conn.execute("""
                INSERT INTO location_telemetry 
                (case_id, agent_id, latitude, longitude, city, region, country, source, accuracy, confidence, payload, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("default", agent_id, lat, lon, location_payload.get("city"), location_payload.get("region"), location_payload.get("country"), location_payload.get("source"), location_payload.get("accuracy"), location_payload.get("confidence"), payload_json, now))

        conn.commit()
        conn.close()
        return {"agent_id": agent_id, "category": category, "data": payload, "timestamp": now}

    @staticmethod
    def get_location_history(agent_id: str, db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        rows = conn.execute("SELECT payload, timestamp FROM location_telemetry WHERE agent_id = ? ORDER BY timestamp DESC", (agent_id,)).fetchall()
        conn.close()
        out = []
        for r in rows:
            try:
                data = json.loads(r[0])
                data["timestamp"] = r[1]
                out.append(data)
            except:
                pass
        return out

    @staticmethod
    def get(agent_id: str, category: str, db_path: str = None) -> Optional[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        row = conn.execute("SELECT payload, collected_at FROM device_telemetry WHERE agent_id = ? AND category = ?", (agent_id, category)).fetchone()
        conn.close()
        if not row:
            return None
        try:
            payload = json.loads(row[0])
        except Exception:
            payload = row[0]
        return {"agent_id": agent_id, "category": category, "data": payload, "timestamp": row[1], "read_only": True}

    @staticmethod
    def list_for_agent(agent_id: str, db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        rows = conn.execute("SELECT category, payload, collected_at FROM device_telemetry WHERE agent_id = ? ORDER BY category", (agent_id,)).fetchall()
        conn.close()
        out=[]
        for row in rows:
            try: payload=json.loads(row[1])
            except Exception: payload=row[1]
            out.append({"category":row[0],"data":payload,"timestamp":row[2]})
        return out



class ThreatIntelModel:
    @staticmethod
    def save_research(case_id: str, indicator: str, indicator_type: str, query: str,
                      sources: List[Dict[str, Any]], status: str = "SUCCESS", db_path: str = None) -> Dict[str, Any]:
        research_id = f"intel_{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()
        sources_json = json.dumps(sources)
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO threat_intel_research
            (id, case_id, indicator, indicator_type, query, sources_json, status, review_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'UNREVIEWED', ?)
        """, (research_id, case_id, indicator, indicator_type, query, sources_json, status, now))
        conn.commit()
        conn.close()
        return {
            "id": research_id,
            "case_id": case_id,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "query": query,
            "sources": sources,
            "status": status,
            "review_status": "UNREVIEWED",
            "created_at": now
        }

    @staticmethod
    def update_fetched_content(research_id: str, fetched_url: str, content: str, db_path: str = None) -> bool:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("SELECT fetched_urls_json FROM threat_intel_research WHERE id = ?", (research_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return False
        existing_urls = []
        if row[0]:
            try:
                existing_urls = json.loads(row[0])
            except Exception:
                existing_urls = []
        if fetched_url not in existing_urls:
            existing_urls.append(fetched_url)
        cur.execute("""
            UPDATE threat_intel_research
            SET fetched_urls_json = ?, fetched_content = ?
            WHERE id = ?
        """, (json.dumps(existing_urls), content, research_id))
        conn.commit()
        conn.close()
        return True

    @staticmethod
    def update_review(research_id: str, review_status: str, notes: str, db_path: str = None) -> bool:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("""
            UPDATE threat_intel_research
            SET review_status = ?, investigator_notes = ?
            WHERE id = ?
        """, (review_status, notes, research_id))
        rows_affected = cur.rowcount
        conn.commit()
        conn.close()
        return rows_affected > 0

    @staticmethod
    def get_by_id(research_id: str, db_path: str = None) -> Optional[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM threat_intel_research WHERE id = ?", (research_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        try:
            d["sources"] = json.loads(d.get("sources_json") or "[]")
        except Exception:
            d["sources"] = []
        try:
            d["fetched_urls"] = json.loads(d.get("fetched_urls_json") or "[]")
        except Exception:
            d["fetched_urls"] = []
        return d

    @staticmethod
    def list_for_case(case_id: str, db_path: str = None) -> List[Dict[str, Any]]:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM threat_intel_research WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
        rows = cur.fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["sources"] = json.loads(d.get("sources_json") or "[]")
            except Exception:
                d["sources"] = []
            try:
                d["fetched_urls"] = json.loads(d.get("fetched_urls_json") or "[]")
            except Exception:
                d["fetched_urls"] = []
            results.append(d)
        return results

    @staticmethod
    def save_to_findings(case_id: str, research_id: str, title: str, severity: str,
                         investigator_notes: str, recommendations: str = "",
                         mitre_technique: str = "T1071", db_path: str = None) -> Dict[str, Any]:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM threat_intel_research WHERE id = ?", (research_id,))
        r_row = cur.fetchone()
        if not r_row:
            conn.close()
            raise ValueError("Threat intelligence research record not found")
        research = dict(r_row)

        sources = []
        try:
            sources = json.loads(research.get("sources_json") or "[]")
        except Exception:
            pass

        finding_id = f"fnd_intel_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        # Build provenance-preserving evidence references
        evidence_refs = [f"threat_intel_research:{research_id}"]
        for s in sources[:5]:
            if s.get("url"):
                evidence_refs.append(s["url"])

        cur.execute("""
            INSERT INTO findings
            (id, device_id, case_id, title, category, severity, description, evidence_refs, recommendations, mitre_technique, timestamp, status)
            VALUES (?, 'EXTERNAL-INTEL', ?, ?, 'THREAT_INTELLIGENCE', ?, ?, ?, ?, ?, ?, 'CONFIRMED_FINDING')
        """, (finding_id, case_id, title, severity, investigator_notes, json.dumps(evidence_refs), recommendations, mitre_technique, now))

        # Update research review status
        cur.execute("""
            UPDATE threat_intel_research
            SET review_status = 'SAVED_TO_FINDINGS', investigator_notes = ?
            WHERE id = ?
        """, (investigator_notes, research_id))

        conn.commit()
        conn.close()

        return {
            "id": finding_id,
            "case_id": case_id,
            "research_id": research_id,
            "title": title,
            "category": "THREAT_INTELLIGENCE",
            "severity": severity,
            "description": investigator_notes,
            "evidence_references": evidence_refs,
            "recommendations": recommendations,
            "mitre_technique": mitre_technique,
            "timestamp": now,
            "status": "CONFIRMED_FINDING"
        }
