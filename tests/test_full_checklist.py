"""
JOCKY V5 Phase 1 — Full Checklist Test Suite

Covers every PDF checklist work item with at least one test per item.
All tests are host-independent (mocked / fixture-based).
"""
import json, os, sys, pytest, hashlib
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests.fixtures.benign_security_fixtures import (
    INJECTION_ASSESSMENT_MULTI, INJECTION_ASSESSMENT_CLEAN,
    API_INTEGRITY_ASSESSMENT_HIGH, API_INTEGRITY_ASSESSMENT_CLEAN,
    KERNEL_INTEGRITY_SUSPICIOUS, KERNEL_INTEGRITY_CLEAN,
    POSTURE_ALL_ACTIVE, POSTURE_CONTROLS_DISABLED, POSTURE_CONTROLS_DEGRADED,
    BYOVD_REPORT_WITH_VULNS, BYOVD_REPORT_CLEAN,
    FIXTURE_FAILED_LOGINS, FIXTURE_SUCCESSFUL_LOGINS,
    NORMALIZED_LINUX_LOGS, NORMALIZED_WINDOWS_EVENTS,
    FIXTURE_VULN_DRIVER_CRITICAL,
)


# ═══════════════════════════════════════════════════════════════════════════════
# P0 — Test determinism
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeterminism:
    """All tests are host-independent via fixtures."""

    def test_fixtures_have_fixed_timestamps(self):
        for report in (INJECTION_ASSESSMENT_MULTI, API_INTEGRITY_ASSESSMENT_HIGH,
                       BYOVD_REPORT_WITH_VULNS):
            assert "timestamp" in report
            # Must be a valid ISO string
            ts = report["timestamp"]
            assert "T" in ts or "Z" in ts or "+" in ts

    def test_fixture_risk_levels_valid(self):
        valid = {"CRITICAL","HIGH","MEDIUM","LOW","CLEAN","INFORMATIONAL"}
        for proc in INJECTION_ASSESSMENT_MULTI["suspicious_processes"]:
            assert proc["risk_level"] in valid
        assert BYOVD_REPORT_WITH_VULNS["summary"]["overall_risk"] in valid

    def test_fixture_evidence_ids_stable(self):
        # Evidence references in BYOVD remain stable (not random)
        assert BYOVD_REPORT_WITH_VULNS["vulnerable_drivers"][0]["driver_name"] == "rtcore64.sys"


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — Security posture hardening (v2)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityPostureV2:
    def test_not_installed_distinct_from_disabled(self):
        """NOT_INSTALLED must differ from DISABLED."""
        from collector.security_assessment import _linux_service_status_v2
        # Service that doesn't exist → NOT_INSTALLED
        with patch("collector.security_assessment._cmd", return_value=""), \
             patch("collector.security_assessment._linux_service_is_installed",
                   return_value=False):
            status = _linux_service_status_v2("nonexistent-svc")
        assert status["health"] == "NOT_INSTALLED"

    def test_active_service_flagged_active(self):
        from collector.security_assessment import _linux_service_status_v2
        with patch("collector.security_assessment._cmd", return_value="active"), \
             patch("collector.security_assessment._linux_service_is_installed",
                   return_value=True):
            status = _linux_service_status_v2("auditd")
        assert status["health"] == "ACTIVE"

    def test_installed_but_stopped_is_disabled(self):
        from collector.security_assessment import _linux_service_status_v2
        def cmd_side(args, **kw):
            if "is-active" in args: return "inactive"
            if "is-enabled" in args: return "disabled"
            return ""
        with patch("collector.security_assessment._cmd", side_effect=cmd_side), \
             patch("collector.security_assessment._linux_service_is_installed",
                   return_value=True):
            status = _linux_service_status_v2("auditd")
        assert status["health"] == "DISABLED"

    def test_posture_v2_has_collection_limitations(self):
        from collector.security_assessment import assess_security_posture_v2
        with patch("platform.system", return_value="Linux"), \
             patch("collector.security_assessment._cmd", return_value=""), \
             patch("collector.security_assessment._linux_service_is_installed",
                   return_value=False):
            result = assess_security_posture_v2()
        assert "collection_limitations" in result
        assert len(result["collection_limitations"]) >= 1

    def test_posture_v2_read_only(self):
        from collector.security_assessment import assess_security_posture_v2
        with patch("platform.system", return_value="Linux"), \
             patch("collector.security_assessment._cmd", return_value=""), \
             patch("collector.security_assessment._linux_service_is_installed",
                   return_value=False):
            result = assess_security_posture_v2()
        assert result["read_only"] is True

    def test_posture_disabled_fixture_is_high_risk(self):
        assert POSTURE_CONTROLS_DISABLED["overall_risk"] == "HIGH"
        disabled = [r for r in POSTURE_CONTROLS_DISABLED["risk_indicators"]
                    if r["status"] == "DISABLED"]
        assert len(disabled) >= 2

    def test_posture_degraded_fixture_is_medium_risk(self):
        assert POSTURE_CONTROLS_DEGRADED["overall_risk"] == "MEDIUM"
        degraded = [r for r in POSTURE_CONTROLS_DEGRADED["risk_indicators"]
                    if r["status"] == "DEGRADED"]
        assert len(degraded) >= 1

    def test_posture_active_fixture_is_low_risk(self):
        assert POSTURE_ALL_ACTIVE["overall_risk"] == "LOW"
        assert POSTURE_ALL_ACTIVE["risk_indicators"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — API integrity baselines
# ═══════════════════════════════════════════════════════════════════════════════

class TestAPIIntegrityBaselines:
    def test_no_baseline_returns_no_baseline_status(self):
        from collector.security_assessment import compare_against_baseline
        import collector.security_assessment as sa
        sa._API_BASELINE_STORE = {}
        result = compare_against_baseline("/lib/libc.so.6", "a" * 64)
        assert result["baseline_status"] == "NO_BASELINE"

    def test_matching_baseline_returns_match(self):
        from collector.security_assessment import compare_against_baseline
        import collector.security_assessment as sa
        sha = "a" * 64
        sa._API_BASELINE_STORE = {"/lib/libc.so.6": sha}
        result = compare_against_baseline("/lib/libc.so.6", sha)
        assert result["baseline_status"] == "MATCH"

    def test_mismatched_baseline_returns_mismatch(self):
        from collector.security_assessment import compare_against_baseline
        import collector.security_assessment as sa
        sa._API_BASELINE_STORE = {"/lib/libc.so.6": "a" * 64}
        result = compare_against_baseline("/lib/libc.so.6", "b" * 64)
        assert result["baseline_status"] == "MISMATCH"

    def test_path_not_in_baseline_returns_not_in_baseline(self):
        from collector.security_assessment import compare_against_baseline
        import collector.security_assessment as sa
        sa._API_BASELINE_STORE = {"/lib/libc.so.6": "a" * 64}
        result = compare_against_baseline("/lib/other.so", "b" * 64)
        assert result["baseline_status"] == "NOT_IN_BASELINE"

    def test_api_assessment_clean_fixture_has_no_high_risk_libs(self):
        report = API_INTEGRITY_ASSESSMENT_CLEAN
        high_risk = [l for l in report["library_integrity"]
                     if l.get("risk_level") == "HIGH"]
        assert len(high_risk) == 0

    def test_api_assessment_high_fixture_has_suspicious_sections(self):
        report = API_INTEGRITY_ASSESSMENT_HIGH
        high_libs = [l for l in report["library_integrity"]
                     if l.get("risk_level") == "HIGH"]
        assert len(high_libs) >= 1
        assert high_libs[0]["suspicious_exec_sections"]


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — BYOVD expanded catalogue
# ═══════════════════════════════════════════════════════════════════════════════

class TestBYOVDCatalogue:
    def test_catalogue_has_at_least_19_entries(self):
        from collector.driver_forensics import KNOWN_VULNERABLE_DRIVERS
        assert len(KNOWN_VULNERABLE_DRIVERS) >= 19

    def test_all_entries_have_required_fields(self):
        from collector.driver_forensics import KNOWN_VULNERABLE_DRIVERS
        required = ("cve","description","risk","vendor","remediation","mitre_technique")
        for name, entry in KNOWN_VULNERABLE_DRIVERS.items():
            for field in required:
                assert field in entry, f"{name} missing {field}"

    def test_mhyprot2_in_catalogue(self):
        from collector.driver_forensics import KNOWN_VULNERABLE_DRIVERS
        assert "mhyprot2.sys" in KNOWN_VULNERABLE_DRIVERS
        assert KNOWN_VULNERABLE_DRIVERS["mhyprot2.sys"]["risk"] == "CRITICAL"

    def test_get_driver_provenance_known(self):
        from collector.driver_forensics import get_driver_provenance
        p = get_driver_provenance("rtcore64.sys")
        assert p["in_catalogue"] is True
        assert "signer" in p
        assert p["mitre_technique"] == "T1068"

    def test_get_driver_provenance_unknown(self):
        from collector.driver_forensics import get_driver_provenance
        p = get_driver_provenance("totally_normal_driver.sys")
        assert p["in_catalogue"] is False

    def test_byovd_remediation_plan_sorted_by_priority(self):
        report = BYOVD_REPORT_WITH_VULNS
        actions = report["remediation_plan"]["actions"]
        order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        priorities = [order.get(a["priority"], 9) for a in actions]
        assert priorities == sorted(priorities)

    def test_byovd_hvci_recommended_for_critical(self):
        report = BYOVD_REPORT_WITH_VULNS
        critical_actions = [a for a in report["remediation_plan"]["actions"]
                            if a["priority"] == "IMMEDIATE"]
        for action in critical_actions:
            assert action["hvci_recommended"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — Logs normalization
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogsNormalization:
    _REQUIRED = ("timestamp","channel","event_id","level","severity_num",
                 "provider","message","source","raw")

    def test_linux_log_has_all_required_fields(self):
        from collector.log_normalizer import normalize_logs
        for record in NORMALIZED_LINUX_LOGS:
            out = normalize_logs([record], platform="linux")
            assert len(out) == 1
            for k in self._REQUIRED:
                assert k in out[0], f"Missing {k} in Linux log"

    def test_windows_log_has_all_required_fields(self):
        from collector.log_normalizer import normalize_logs
        for record in NORMALIZED_WINDOWS_EVENTS:
            out = normalize_logs([record], platform="windows")
            assert len(out) == 1
            for k in self._REQUIRED:
                assert k in out[0], f"Missing {k} in Windows log"

    def test_severity_num_is_integer(self):
        from collector.log_normalizer import normalize_logs
        out = normalize_logs(NORMALIZED_LINUX_LOGS, platform="linux")
        for e in out:
            assert isinstance(e["severity_num"], int)

    def test_windows_event_id_preserved(self):
        from collector.log_normalizer import normalize_logs
        win_logs = [{"Id": 4624, "LogName": "Security", "Level": 4,
                     "TimeCreated": "2026-09-11T08:00:00+00:00",
                     "ProviderName": "Microsoft-Windows-Security-Auditing",
                     "Message": "An account was successfully logged on."}]
        out = normalize_logs(win_logs, platform="windows")
        assert out[0]["event_id"] == "4624"
        assert out[0]["source"] == "Windows Event Log"

    def test_syslog_line_normalizes(self):
        from collector.log_normalizer import normalize_syslog_line
        line = "Sep 11 08:00:00 myhost sshd[1234]: Accepted publickey for analyst"
        result = normalize_syslog_line(line)
        assert result is not None
        assert result["provider"] == "sshd"
        assert "analyst" in result["message"]

    def test_dmesg_line_normalizes(self):
        from collector.log_normalizer import normalize_dmesg_line
        line = "[    1.234567] usb 1-1: new USB device found"
        result = normalize_dmesg_line(line)
        assert result is not None
        assert result["channel"] == "kernel"
        assert "USB" in result["message"]

    def test_timestamp_normalized_to_iso(self):
        from collector.log_normalizer import _ensure_utc
        result = _ensure_utc("2026-09-11T08:00:00Z")
        assert "2026-09-11" in result
        result2 = _ensure_utc("2026-09-11T08:00:00+00:00")
        assert "2026-09-11" in result2


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — Investigator filters
# ═══════════════════════════════════════════════════════════════════════════════

class TestInvestigatorFilters:
    _EVENTS = [
        {"timestamp": "2026-09-11T08:00:00+00:00", "severity": "CRITICAL",
         "event_type": "SUSPICIOUS_PROCESS_INJECTION", "source": "INJECTION",
         "description": "RWX mapping in bash", "process_name": "bash",
         "user": "root", "device": "host-001"},
        {"timestamp": "2026-09-11T09:00:00+00:00", "severity": "HIGH",
         "event_type": "VULNERABLE_DRIVER_DETECTED", "source": "DRIVER_FORENSICS",
         "description": "rtcore64.sys found", "process_name": "",
         "user": "System", "device": "host-001"},
        {"timestamp": "2026-09-11T10:00:00+00:00", "severity": "INFORMATIONAL",
         "event_type": "USER_LOGIN", "source": "AUTH",
         "description": "analyst logged in", "process_name": "",
         "user": "analyst", "device": "host-002"},
    ]

    def test_filter_by_severity(self):
        from server.filters import filter_timeline
        result = filter_timeline(self._EVENTS, severity="CRITICAL")
        assert result["total"] == 1
        assert result["events"][0]["severity"] == "CRITICAL"

    def test_filter_by_min_severity(self):
        from server.filters import filter_timeline
        result = filter_timeline(self._EVENTS, min_severity="HIGH")
        assert result["total"] == 2  # CRITICAL + HIGH, not INFORMATIONAL

    def test_filter_by_event_type(self):
        from server.filters import filter_timeline
        result = filter_timeline(self._EVENTS, event_type="USER_LOGIN")
        assert result["total"] == 1
        assert result["events"][0]["user"] == "analyst"

    def test_filter_by_device(self):
        from server.filters import filter_timeline
        result = filter_timeline(self._EVENTS, device_id="host-002")
        assert result["total"] == 1

    def test_filter_by_user(self):
        from server.filters import filter_timeline
        result = filter_timeline(self._EVENTS, user="analyst")
        assert result["total"] == 1

    def test_filter_by_search(self):
        from server.filters import filter_timeline
        result = filter_timeline(self._EVENTS, search="rtcore")
        assert result["total"] == 1

    def test_filter_time_range(self):
        from server.filters import filter_timeline
        result = filter_timeline(self._EVENTS,
                                 since="2026-09-11T08:30:00+00:00",
                                 until="2026-09-11T09:30:00+00:00")
        assert result["total"] == 1
        assert "DRIVER" in result["events"][0]["source"]

    def test_pagination(self):
        from server.filters import filter_timeline
        result = filter_timeline(self._EVENTS, page=1, page_size=2)
        assert len(result["events"]) == 2
        assert result["total"] == 3
        assert result["total_pages"] == 2

    def test_filter_findings_by_severity(self):
        from server.filters import filter_findings
        findings = [
            {"severity": "CRITICAL", "confidence": "HIGH", "mitre_technique": "T1068",
             "timestamp": "2026-09-11T08:00:00Z", "title": "Driver vuln", "description": ""},
            {"severity": "LOW", "confidence": "LOW", "mitre_technique": "T1027",
             "timestamp": "2026-09-11T08:01:00Z", "title": "Minor issue", "description": ""},
        ]
        result = filter_findings(findings, severity="CRITICAL")
        assert result["total"] == 1

    def test_filter_findings_by_mitre(self):
        from server.filters import filter_findings
        findings = [
            {"severity": "HIGH", "confidence": "HIGH", "mitre_technique": "T1068",
             "timestamp": "", "title": "", "description": ""},
            {"severity": "LOW", "confidence": "LOW", "mitre_technique": "T1027",
             "timestamp": "", "title": "", "description": ""},
        ]
        result = filter_findings(findings, mitre_technique="T1068")
        assert result["total"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — Database backup/restore + API key lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

class TestDatabaseBackupRestore:
    def test_backup_creates_file(self, tmp_path):
        from server.database import init_db, backup_db
        db = str(tmp_path / "test.db")
        bdir = str(tmp_path / "backups")
        init_db(db)
        meta = backup_db(db_path=db, backup_dir=bdir)
        assert os.path.isfile(meta["backup"])
        assert len(meta["sha256"]) == 64

    def test_backup_meta_json_created(self, tmp_path):
        from server.database import init_db, backup_db
        db = str(tmp_path / "test.db")
        bdir = str(tmp_path / "backups")
        init_db(db)
        meta = backup_db(db_path=db, backup_dir=bdir)
        assert os.path.isfile(meta["backup"] + ".meta.json")

    def test_restore_verifies_hash(self, tmp_path):
        from server.database import init_db, backup_db, restore_db
        db = str(tmp_path / "test.db")
        bdir = str(tmp_path / "backups")
        init_db(db)
        meta = backup_db(db_path=db, backup_dir=bdir)
        # Correct hash → success
        result = restore_db(meta["backup"], db_path=db, expected_sha256=meta["sha256"])
        assert result["success"] is True
        # Wrong hash → failure
        result2 = restore_db(meta["backup"], db_path=db, expected_sha256="0" * 64)
        assert result2["success"] is False

    def test_api_key_lifecycle(self, tmp_path):
        from server.database import (init_db, create_api_key, validate_api_key,
                                     revoke_api_key, list_api_keys)
        db = str(tmp_path / "keys.db")
        init_db(db)
        # Create
        raw = "test-key-12345"
        create_api_key(raw, "test-label", expires_in_days=30, db_path=db)
        # Validate
        ok, reason = validate_api_key(raw, db_path=db)
        assert ok is True
        # List
        keys = list_api_keys(db_path=db)
        assert len(keys) == 1
        assert keys[0]["status"] == "active"
        # Revoke
        revoke_api_key(raw, db_path=db)
        ok2, reason2 = validate_api_key(raw, db_path=db)
        assert ok2 is False
        assert "revoked" in reason2.lower()

    def test_unknown_key_rejected(self, tmp_path):
        from server.database import init_db, validate_api_key
        db = str(tmp_path / "keys2.db")
        init_db(db)
        ok, reason = validate_api_key("no-such-key", db_path=db)
        assert ok is False

    def test_pagination_helper(self, tmp_path):
        from server.database import init_db, get_db_connection, paginate
        db = str(tmp_path / "page.db")
        init_db(db)
        conn = get_db_connection(db)
        # Insert 5 devices
        import uuid as _u
        from datetime import datetime as _dt, timezone as _tz
        for i in range(5):
            conn.execute(
                "INSERT INTO devices (id,hostname,os,last_seen) VALUES (?,?,?,?)",
                (str(_u.uuid4()), f"host-{i}", "Linux",
                 _dt.now(_tz.utc).isoformat())
            )
        conn.commit()
        result = paginate("SELECT * FROM devices", (), conn, page=1, page_size=3)
        assert len(result["rows"]) == 3
        assert result["total"] == 5
        assert result["total_pages"] == 2
        conn.close()

    def test_stale_device_cleanup(self, tmp_path):
        from server.database import init_db, get_db_connection, cleanup_stale_devices
        import uuid as _u
        db = str(tmp_path / "stale.db")
        init_db(db)
        conn = get_db_connection(db)
        conn.execute(
            "INSERT INTO devices (id,hostname,os,last_seen) VALUES (?,?,?,?)",
            (str(_u.uuid4()), "old-host", "Linux", "2020-01-01T00:00:00+00:00")
        )
        conn.commit()
        conn.close()
        cleaned = cleanup_stale_devices(inactive_days=30, db_path=db)
        assert cleaned == 1


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — Audit chain export + summary
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditChain:
    def test_audit_summary_has_limitation_note(self, tmp_path):
        from server.database import init_db
        from server.audit import audit_summary
        db = str(tmp_path / "audit.db")
        init_db(db)
        summary = audit_summary(db_path=db)
        assert "limitation_note" in summary
        assert "clock" in summary["limitation_note"].lower() or \
               "suppress" in summary["limitation_note"].lower()

    def test_audit_chain_verify_empty_is_valid(self, tmp_path):
        from server.database import init_db
        from server.audit import verify_audit_chain
        db = str(tmp_path / "audit2.db")
        init_db(db)
        ok, msg, violations = verify_audit_chain(db_path=db)
        assert ok is True
        assert violations == []

    def test_audit_record_and_verify(self, tmp_path):
        from server.database import init_db
        from server.audit import record_audit_event, verify_audit_chain
        db = str(tmp_path / "audit3.db")
        init_db(db)
        record_audit_event("analyst", "UPLOAD_EVIDENCE", "evd_001", db_path=db)
        record_audit_event("analyst", "GENERATE_REPORT", "rpt_001", db_path=db)
        ok, msg, violations = verify_audit_chain(db_path=db)
        assert ok is True
        assert len(violations) == 0

    def test_audit_export_json(self, tmp_path):
        from server.database import init_db
        from server.audit import record_audit_event, export_audit_chain
        db = str(tmp_path / "audit4.db")
        init_db(db)
        record_audit_event("analyst", "TEST_ACTION", "obj_001", db_path=db)
        exported = export_audit_chain(fmt="json", db_path=db)
        data = json.loads(exported)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["action"] == "TEST_ACTION"

    def test_audit_export_csv(self, tmp_path):
        from server.database import init_db
        from server.audit import record_audit_event, export_audit_chain
        db = str(tmp_path / "audit5.db")
        init_db(db)
        record_audit_event("analyst", "CSV_TEST", "obj_002", db_path=db)
        csv_out = export_audit_chain(fmt="csv", db_path=db)
        assert "event_id" in csv_out
        assert "CSV_TEST" in csv_out


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — Manifest provenance v2
# ═══════════════════════════════════════════════════════════════════════════════

class TestManifestProvenanceV2:
    def test_manifest_has_provenance_block(self, tmp_path):
        from collector.manifest import ManifestGenerator
        files_dir = str(tmp_path / "files")
        os.makedirs(files_dir)
        (tmp_path / "files" / "test.txt").write_text("hello")
        manifest_path = str(tmp_path / "manifest.json")
        gen = ManifestGenerator()
        m = gen.generate_manifest(
            case_id="c1", session_id="s1", job_id="j1", agent_id="a1",
            files_dir=files_dir, output_manifest_path=manifest_path,
            build_id="build-001", source_revision="abc123"
        )
        assert "provenance" in m
        assert m["provenance"]["build_id"] == "build-001"
        assert m["provenance"]["source_revision"] == "abc123"
        assert m["manifest_sha256"]
        assert m["version"] == "2.0"

    def test_manifest_verify_intact(self, tmp_path):
        from collector.manifest import ManifestGenerator
        files_dir = str(tmp_path / "files")
        os.makedirs(files_dir)
        (tmp_path / "files" / "test.txt").write_text("hello world")
        manifest_path = str(tmp_path / "manifest.json")
        gen = ManifestGenerator()
        gen.generate_manifest("c1","s1","j1","a1", files_dir=files_dir,
                              output_manifest_path=manifest_path)
        result = gen.verify_manifest(manifest_path)
        assert result["intact"] is True
        assert result["manifest_hash_valid"] is True
        assert result["file_mismatches"] == []
        assert result["missing_files"] == []

    def test_manifest_detects_tampered_file(self, tmp_path):
        from collector.manifest import ManifestGenerator
        files_dir = str(tmp_path / "files")
        os.makedirs(files_dir)
        f = tmp_path / "files" / "test.txt"
        f.write_text("original content")
        manifest_path = str(tmp_path / "manifest.json")
        gen = ManifestGenerator()
        gen.generate_manifest("c1","s1","j1","a1", files_dir=files_dir,
                              output_manifest_path=manifest_path)
        # Tamper the file
        f.write_text("tampered content")
        result = gen.verify_manifest(manifest_path)
        assert result["intact"] is False
        assert len(result["file_mismatches"]) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — Polymorphic build identity uniqueness
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolymorphicBuildIdentity:
    def test_build_ids_are_unique(self):
        from poly.poly_engine import generate_build_identity
        ids = {generate_build_identity()["build_id"] for _ in range(10)}
        assert len(ids) == 10  # All must be unique

    def test_build_sha256_are_unique(self):
        from poly.poly_engine import generate_build_identity
        shas = {generate_build_identity()["build_sha256"] for _ in range(10)}
        assert len(shas) == 10

    def test_build_identity_has_required_fields(self):
        from poly.poly_engine import generate_build_identity
        identity = generate_build_identity()
        for field in ("build_id","build_sha256","timestamp","platform"):
            assert field in identity

    def test_build_sha256_is_64_hex_chars(self):
        from poly.poly_engine import generate_build_identity
        identity = generate_build_identity()
        sha = identity["build_sha256"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)


# ═══════════════════════════════════════════════════════════════════════════════
# P1 — Reports traceability
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportsTraceability:
    _FINDINGS = [{
        "finding_id": "FIND-BYOVD-001", "title": "Vulnerable Driver",
        "severity": "CRITICAL", "confidence": "HIGH",
        "description": "rtcore64.sys detected.",
        "mitre_technique": "T1068", "recommendation": "Block via WDAC.",
        "evidence_references": ["evd_001"], "timestamp": "2026-09-11T08:00:00Z",
    }]
    _EVIDENCE = [{
        "id": "evd_001", "job_id": "job_001", "device_id": "host-001",
        "source_collector": "driver_forensics", "sha256": "a"*64,
        "size_bytes": 1024, "uploaded_at": "2026-09-11T08:00:00Z",
        "is_encrypted": False, "collector_timestamp": "2026-09-11T07:59:00Z",
        "manifest": {"manifest_sha256": "b"*64, "provenance": {
            "source_revision": "abc123", "build_id": "build-001"
        }},
    }]

    def test_json_report_has_all_sections(self):
        from server.reports import generate_json_report
        report = generate_json_report(
            case_id="c1", session_id="s1",
            timeline_events=[], findings=self._FINDINGS,
            evidence_list=self._EVIDENCE)
        for key in ("report_format","case_id","findings","evidence",
                    "timeline_summary","disclaimer","read_only_collection"):
            assert key in report

    def test_json_report_findings_have_evidence_refs(self):
        from server.reports import generate_json_report
        report = generate_json_report("c1","s1",[],self._FINDINGS,self._EVIDENCE)
        f = report["findings"][0]
        assert "evidence_references" in f
        assert "evd_001" in f["evidence_references"]

    def test_json_report_read_only_flag(self):
        from server.reports import generate_json_report
        report = generate_json_report("c1","s1",[],[],[])
        assert report["read_only_collection"] is True

    def test_html_report_contains_finding_id(self):
        from server.reports import generate_html_report
        html = generate_html_report(
            case_id="c1", session_id="s1",
            timeline_events=[], findings=self._FINDINGS,
            evidence_list=self._EVIDENCE)
        assert "FIND-BYOVD-001" in html

    def test_html_report_contains_evidence_sha256(self):
        from server.reports import generate_html_report
        html = generate_html_report("c1","s1",[],self._FINDINGS,self._EVIDENCE)
        assert "a"*64 in html

    def test_html_report_contains_disclaimer(self):
        from server.reports import generate_html_report
        html = generate_html_report("c1","s1",[],[],[])
        assert "read-only" in html.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# P2 — Kernel injection detectors (benign fixtures only)
# ═══════════════════════════════════════════════════════════════════════════════

class TestKernelIntegrityFixtures:
    def test_clean_kernel_has_no_suspicious_modules(self):
        assert KERNEL_INTEGRITY_CLEAN["suspicious_modules"] == []
        assert KERNEL_INTEGRITY_CLEAN["suspicious_count"] == 0

    def test_suspicious_kernel_flagged(self):
        assert "rootkit_xyz" in KERNEL_INTEGRITY_SUSPICIOUS["suspicious_modules"]
        assert KERNEL_INTEGRITY_SUSPICIOUS["suspicious_count"] == 1
        assert KERNEL_INTEGRITY_SUSPICIOUS["unsigned_count"] == 1

    def test_security_modules_tracked(self):
        assert "apparmor" in KERNEL_INTEGRITY_CLEAN["security_modules_active"]
        assert "apparmor" in KERNEL_INTEGRITY_SUSPICIOUS["security_modules_active"]

    def test_indicators_present_for_suspicious(self):
        indicators = KERNEL_INTEGRITY_SUSPICIOUS["indicators"]
        assert len(indicators) >= 1
        assert indicators[0]["severity"] == "HIGH"


# ═══════════════════════════════════════════════════════════════════════════════
# P2 — Runtime files must be marked experimental
# ═══════════════════════════════════════════════════════════════════════════════

class TestRuntimeFilesAreNonOperational:
    _RUNTIME_DIR = os.path.join(os.path.dirname(__file__), "..", "runtime")
    _EXPERIMENTAL_FILES = [
        "jocky_inject_linux.c",
        "jocky_unhook_linux.c",
        "jocky_byovd_linux.c",
    ]

    def _file_path(self, fname):
        return os.path.join(self._RUNTIME_DIR, fname)

    def test_experimental_files_have_nonoperational_header(self):
        for fname in self._EXPERIMENTAL_FILES:
            path = self._file_path(fname)
            if not os.path.exists(path):
                pytest.skip(f"{fname} not present in runtime/")
            with open(path, errors="replace") as f:
                content = f.read(2000)
            assert "NON-OPERATIONAL" in content or "EXPERIMENTAL" in content, \
                f"{fname} missing NON-OPERATIONAL/EXPERIMENTAL header"

    def test_build_script_does_not_reference_experimental_files(self):
        build_script = os.path.join(
            os.path.dirname(__file__), "..", "tools", "build_jocky.py"
        )
        if not os.path.exists(build_script):
            pytest.skip("build_jocky.py not found")
        content = open(build_script, errors="replace").read()
        for fname in self._EXPERIMENTAL_FILES:
            assert fname not in content, \
                f"Production build script references experimental: {fname}"
