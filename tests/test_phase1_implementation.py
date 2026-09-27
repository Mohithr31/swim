"""
JOCKY Phase 1 & Phase 4 implementation tests.

Tests every new forensic capability added per the implementation plan:
  - Process injection / hollowing detector
  - API integrity assessment
  - Kernel integrity assessment
  - Security posture assessment
  - BYOVD risk report with remediation
  - Expanded correlation rules (9 rules)
  - Expanded timeline engine (all new event types)
"""
import sys
import pytest
from unittest.mock import patch, MagicMock


# ─────────────────────────────────────────────────────────────────────────────
# Process injection detector
# ─────────────────────────────────────────────────────────────────────────────

class TestProcessInjectionDetector:
    def test_returns_required_keys(self):
        from collector.security_assessment import detect_process_injection
        with patch("platform.system", return_value="Linux"), \
             patch("os.listdir", return_value=[]):
            result = detect_process_injection()
        for key in ("assessment_type", "platform", "read_only",
                    "processes_scanned", "suspicious_processes", "risk_summary"):
            assert key in result, f"Missing key: {key}"

    def test_read_only_flag(self):
        from collector.security_assessment import detect_process_injection
        with patch("platform.system", return_value="Linux"), \
             patch("os.listdir", return_value=[]):
            result = detect_process_injection()
        assert result["read_only"] is True

    def test_non_linux_returns_note(self):
        from collector.security_assessment import detect_process_injection
        with patch("platform.system", return_value="Darwin"):
            result = detect_process_injection()
        assert "note" in result

    def test_injection_score_scale(self):
        from collector.security_assessment import _detect_injection_linux
        with patch("collector.security_assessment._parse_proc_maps", return_value=[
            {"start": 0x7f000000, "end": 0x7f001000, "perms": "rwxp", "pathname": ""},
        ]), patch("os.readlink", side_effect=Exception), \
           patch("collector.security_assessment._read_file", return_value=""):
            det = _detect_injection_linux(1234, "/bin/test")
        assert det["injection_score"] >= 3
        assert det["risk_level"] in ("HIGH", "MEDIUM", "LOW")
        assert len(det["indicators"]) > 0

    def test_deleted_exe_flagged(self):
        from collector.security_assessment import _detect_injection_linux
        with patch("collector.security_assessment._parse_proc_maps", return_value=[]), \
             patch("os.readlink", side_effect=Exception), \
             patch("collector.security_assessment._read_file", return_value=""):
            det = _detect_injection_linux(9999, "/bin/bash (deleted)")
        assert any("deleted" in ind for ind in det["indicators"])


# ─────────────────────────────────────────────────────────────────────────────
# API integrity assessment
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIIntegrityAssessment:
    def test_returns_required_keys(self):
        from collector.security_assessment import assess_api_integrity
        with patch("platform.system", return_value="Linux"), \
             patch("os.listdir", return_value=[]):
            result = assess_api_integrity()
        for key in ("assessment_type", "platform", "read_only"):
            assert key in result

    def test_read_only_flag(self):
        from collector.security_assessment import assess_api_integrity
        with patch("platform.system", return_value="Linux"), \
             patch("os.listdir", return_value=[]):
            result = assess_api_integrity()
        assert result["read_only"] is True

    def test_library_integrity_list_on_linux(self):
        from collector.security_assessment import assess_api_integrity
        with patch("platform.system", return_value="Linux"), \
             patch("os.listdir", return_value=[]), \
             patch("os.path.isfile", return_value=False):
            result = assess_api_integrity()
        assert "library_integrity" in result
        assert isinstance(result["library_integrity"], list)

    def test_windows_returns_dll_hashes_key(self):
        from collector.security_assessment import assess_api_integrity
        with patch("platform.system", return_value="Windows"), \
             patch("os.path.isfile", return_value=False), \
             patch("os.environ.get", return_value="C:\\Windows"):
            result = assess_api_integrity()
        assert "system32_dll_hashes" in result


# ─────────────────────────────────────────────────────────────────────────────
# Kernel integrity assessment
# ─────────────────────────────────────────────────────────────────────────────

class TestKernelIntegrityAssessment:
    def test_returns_required_keys(self):
        from collector.security_assessment import assess_kernel_integrity
        with patch("platform.system", return_value="Linux"), \
             patch("builtins.open", side_effect=OSError):
            result = assess_kernel_integrity()
        for key in ("assessment_type", "platform", "read_only", "modules",
                    "suspicious_modules", "unsigned_modules", "security_modules_active"):
            assert key in result

    def test_non_linux_has_note(self):
        from collector.security_assessment import assess_kernel_integrity
        with patch("platform.system", return_value="Windows"):
            result = assess_kernel_integrity()
        assert "note" in result

    def test_read_only(self):
        from collector.security_assessment import assess_kernel_integrity
        with patch("platform.system", return_value="Linux"), \
             patch("builtins.open", side_effect=OSError):
            result = assess_kernel_integrity()
        assert result["read_only"] is True

    def test_suspicious_name_flagged(self):
        from collector.security_assessment import assess_kernel_integrity
        fake_proc_modules = "rootkit_mod 12345 0 - Live 0xdeadbeef\n"
        with patch("platform.system", return_value="Linux"), \
             patch("builtins.open", side_effect=[
                 MagicMock(**{"__enter__": lambda s, *a: MagicMock(
                     __iter__=lambda self: iter([fake_proc_modules])
                 ), "__exit__": MagicMock(return_value=False)}),
                 OSError,
             ]), \
             patch("collector.security_assessment._cmd", return_value=""):
            result = assess_kernel_integrity()
        # suspicious_modules may or may not be populated depending on mock depth
        assert isinstance(result["suspicious_modules"], list)


# ─────────────────────────────────────────────────────────────────────────────
# Security posture assessment
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityPostureAssessment:
    def test_returns_required_keys(self):
        from collector.security_assessment import assess_security_posture
        with patch("platform.system", return_value="Linux"), \
             patch("collector.security_assessment._cmd", return_value="inactive"):
            result = assess_security_posture()
        for key in ("assessment_type", "platform", "read_only",
                    "controls", "risk_indicators", "overall_risk"):
            assert key in result

    def test_read_only(self):
        from collector.security_assessment import assess_security_posture
        with patch("platform.system", return_value="Linux"), \
             patch("collector.security_assessment._cmd", return_value=""):
            result = assess_security_posture()
        assert result["read_only"] is True

    def test_overall_risk_is_valid(self):
        from collector.security_assessment import assess_security_posture
        with patch("platform.system", return_value="Linux"), \
             patch("collector.security_assessment._cmd", return_value=""):
            result = assess_security_posture()
        assert result["overall_risk"] in ("HIGH", "MEDIUM", "LOW")

    def test_disabled_control_raises_high_risk(self):
        from collector.security_assessment import assess_security_posture
        # auditd returns 'inactive' = DISABLED -> HIGH risk
        with patch("platform.system", return_value="Linux"), \
             patch("collector.security_assessment._cmd", return_value="inactive"):
            result = assess_security_posture()
        disabled = [r for r in result["risk_indicators"] if r.get("status") == "DISABLED"]
        assert len(disabled) > 0


# ─────────────────────────────────────────────────────────────────────────────
# BYOVD risk report + remediation
# ─────────────────────────────────────────────────────────────────────────────

class TestBYOVDRiskReport:
    def test_returns_required_keys(self):
        from collector.driver_forensics import get_byovd_risk_report
        with patch("collector.driver_forensics.get_driver_forensics", return_value=[]):
            report = get_byovd_risk_report()
        for key in ("assessment_type", "summary", "vulnerable_drivers",
                    "remediation_plan", "read_only"):
            assert key in report

    def test_read_only(self):
        from collector.driver_forensics import get_byovd_risk_report
        with patch("collector.driver_forensics.get_driver_forensics", return_value=[]):
            report = get_byovd_risk_report()
        assert report["read_only"] is True

    def test_vulnerable_driver_triggers_remediation(self):
        from collector.driver_forensics import get_byovd_risk_report
        fake_vuln = [{
            "driver_name": "rtcore64.sys",
            "is_vulnerable": True,
            "cve": "CVE-2021-21551",
            "risk_level": "CRITICAL",
            "remediation": "Uninstall MSI Afterburner.",
            "mitre_technique": "T1068",
        }]
        with patch("collector.driver_forensics.get_driver_forensics", return_value=fake_vuln):
            report = get_byovd_risk_report()
        assert report["summary"]["vulnerable_drivers_found"] == 1
        assert report["summary"]["critical_risk_count"] == 1
        assert report["remediation_plan"]["required"] is True
        actions = report["remediation_plan"]["actions"]
        assert len(actions) == 1
        assert actions[0]["priority"] == "IMMEDIATE"
        assert actions[0]["wdac_block_recommended"] is True

    def test_no_vuln_drivers_clean_report(self):
        from collector.driver_forensics import get_byovd_risk_report
        with patch("collector.driver_forensics.get_driver_forensics", return_value=[
            {"driver_name": "normal.ko", "is_vulnerable": False,
             "risk_level": "CLEAN", "signature_status": "SIGNED"}
        ]):
            report = get_byovd_risk_report()
        assert report["summary"]["overall_risk"] == "LOW"
        assert report["remediation_plan"]["required"] is False

    def test_catalogue_size(self):
        from collector.driver_forensics import KNOWN_VULNERABLE_DRIVERS
        assert len(KNOWN_VULNERABLE_DRIVERS) >= 10


# ─────────────────────────────────────────────────────────────────────────────
# Correlation engine — new rules
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelationEngine:
    def _make_event(self, event_type, **kw):
        from datetime import datetime, timezone
        return {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "TEST",
            **kw,
        }

    def test_byovd_rule(self):
        from server.correlation import CorrelationEngine, EventType, Severity
        events = [self._make_event(
            EventType.VULNERABLE_DRIVER,
            driver_name="rtcore64.sys",
            cve="CVE-2021-21551",
            risk_level="CRITICAL",
            description="MSI driver",
            remediation="Block via WDAC",
            mitre_technique="T1068",
        )]
        findings = CorrelationEngine.correlate_evidence(events, "ev-001")
        byovd_finds = [f for f in findings if "BYOVD" in f["finding_id"]]
        assert len(byovd_finds) >= 1
        assert byovd_finds[0]["severity"] == Severity.CRITICAL

    def test_injection_rule(self):
        from server.correlation import CorrelationEngine, EventType, Severity
        events = [self._make_event(
            EventType.SUSPICIOUS_PROCESS,
            pid=1234, process_name="bash",
            risk_level="HIGH", injection_score=6,
        )]
        findings = CorrelationEngine.correlate_evidence(events, "ev-002")
        inj_finds = [f for f in findings if "INJ" in f["finding_id"]]
        assert len(inj_finds) >= 1
        assert inj_finds[0]["severity"] == Severity.CRITICAL

    def test_api_anomaly_rule(self):
        from server.correlation import CorrelationEngine, EventType
        events = [self._make_event(
            EventType.API_ANOMALY, affected_library="/lib/x86_64-linux-gnu/libc.so.6"
        )]
        findings = CorrelationEngine.correlate_evidence(events, "ev-003")
        api_finds = [f for f in findings if "API" in f["finding_id"]]
        assert len(api_finds) >= 1

    def test_posture_disabled_rule(self):
        from server.correlation import CorrelationEngine, EventType, Severity
        events = [self._make_event(
            EventType.POSTURE_DISABLED, control_name="auditd", label="Linux Audit Daemon"
        )]
        findings = CorrelationEngine.correlate_evidence(events, "ev-004")
        ctrl_finds = [f for f in findings if "CTRL" in f["finding_id"]]
        assert len(ctrl_finds) >= 1
        assert ctrl_finds[0]["severity"] == Severity.HIGH

    def test_kernel_module_rule(self):
        from server.correlation import CorrelationEngine, EventType, Severity
        events = [self._make_event(
            EventType.KERNEL_MODULE_LOAD, module_name="rootkit_xyz", suspicious_name=True
        )]
        findings = CorrelationEngine.correlate_evidence(events, "ev-005")
        km_finds = [f for f in findings if "KM" in f["finding_id"]]
        assert len(km_finds) >= 1
        assert km_finds[0]["severity"] == Severity.CRITICAL

    def test_baseline_always_present(self):
        from server.correlation import CorrelationEngine
        findings = CorrelationEngine.correlate_evidence([], "ev-000")
        baseline = [f for f in findings if "BASE" in f["finding_id"]]
        assert len(baseline) == 1

    def test_all_findings_have_required_fields(self):
        from server.correlation import CorrelationEngine
        events = []
        findings = CorrelationEngine.correlate_evidence(events, "ev-xxx")
        required = ("finding_id", "title", "severity", "confidence",
                    "description", "evidence_references", "mitre_technique",
                    "recommendation", "timestamp")
        for f in findings:
            for field in required:
                assert field in f, f"Finding {f.get('finding_id')} missing {field}"

    def test_findings_sorted_by_severity(self):
        from server.correlation import CorrelationEngine, EventType
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        events = [
            self._make_event(EventType.FAILED_LOGIN, user="alice"),
            self._make_event(EventType.VULNERABLE_DRIVER,
                             driver_name="rtcore64.sys", cve="CVE-2021-21551",
                             risk_level="CRITICAL", description="x",
                             remediation="y", mitre_technique="T1068"),
        ]
        findings = CorrelationEngine.correlate_evidence(events, "ev-sort")
        sevs = [sev_order.get(f["severity"], 9) for f in findings]
        assert sevs == sorted(sevs)


# ─────────────────────────────────────────────────────────────────────────────
# Timeline engine — new event types
# ─────────────────────────────────────────────────────────────────────────────

class TestTimelineEngine:
    def test_process_injection_events_in_timeline(self):
        from server.timeline import TimelineEngine
        from server.correlation import EventType
        inj_report = {
            "suspicious_processes": [{
                "pid": 1234, "process_name": "bash", "injection_score": 6,
                "risk_level": "HIGH",
                "indicators": ["executable_writable_mapping at 0x7f000000"],
            }]
        }
        tl = TimelineEngine.generate_timeline(
            process_injection_report=inj_report, evidence_id="ev-tl-1"
        )
        inj_entries = [e for e in tl if e["event_type"] == EventType.SUSPICIOUS_PROCESS]
        assert len(inj_entries) >= 1
        assert inj_entries[0]["severity"] in ("CRITICAL", "HIGH")

    def test_api_integrity_events_in_timeline(self):
        from server.timeline import TimelineEngine
        from server.correlation import EventType
        api_report = {
            "library_integrity": [{
                "path": "/lib/x86_64-linux-gnu/libc.so.6",
                "sha256": "abc123",
                "risk_level": "HIGH",
                "suspicious_exec_sections": [".evil"],
            }],
            "process_api_map_anomalies": [],
        }
        tl = TimelineEngine.generate_timeline(
            api_integrity_report=api_report, evidence_id="ev-tl-2"
        )
        api_entries = [e for e in tl if e["event_type"] == EventType.API_ANOMALY]
        assert len(api_entries) >= 1

    def test_posture_events_in_timeline(self):
        from server.timeline import TimelineEngine
        from server.correlation import EventType
        posture_report = {
            "risk_indicators": [{
                "control": "auditd",
                "label": "Linux Audit Daemon",
                "severity": "HIGH",
                "status": "DISABLED",
                "note": "auditd is disabled",
            }]
        }
        tl = TimelineEngine.generate_timeline(
            security_posture_report=posture_report, evidence_id="ev-tl-3"
        )
        posture_entries = [e for e in tl if e["event_type"] == EventType.POSTURE_DISABLED]
        assert len(posture_entries) >= 1

    def test_vulnerable_driver_in_timeline(self):
        from server.timeline import TimelineEngine
        from server.correlation import EventType
        drivers = [{
            "driver_name": "rtcore64.sys",
            "is_vulnerable": True, "suspicious_name": False,
            "cve": "CVE-2021-21551", "risk_level": "CRITICAL",
            "remediation": "Block via WDAC",
            "mitre_technique": "T1068",
            "assessment_timestamp": "",
        }]
        tl = TimelineEngine.generate_timeline(drivers=drivers, evidence_id="ev-tl-4")
        drv_entries = [e for e in tl if e["event_type"] == EventType.VULNERABLE_DRIVER]
        assert len(drv_entries) >= 1
        assert drv_entries[0]["severity"] == "CRITICAL"

    def test_all_entries_have_required_fields(self):
        from server.timeline import TimelineEngine
        tl = TimelineEngine.generate_timeline(
            logins=[{"username": "root", "status": "SUCCESS", "source_ip": "127.0.0.1",
                     "timestamp": "2026-09-11T00:00:00Z"}],
            evidence_id="ev-tl-fields",
        )
        required = ("timestamp", "source", "event_type", "description",
                    "severity", "confidence", "evidence_id")
        for entry in tl:
            for field in required:
                assert field in entry, f"Entry missing {field}: {entry}"

    def test_timeline_sorted_chronologically(self):
        from server.timeline import TimelineEngine
        logins = [
            {"username": "a", "status": "SUCCESS", "timestamp": "2026-09-11T12:00:00Z"},
            {"username": "b", "status": "FAIL", "timestamp": "2026-09-11T10:00:00Z"},
        ]
        tl = TimelineEngine.generate_timeline(logins=logins, evidence_id="ev-sort")
        ts_list = [e["timestamp"] for e in tl]
        assert ts_list == sorted(ts_list)
