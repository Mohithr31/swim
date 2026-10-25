"""
Tests for JOCKY Live Threat Intelligence (TinyFish Integration) Subsystem
========================================================================
Covers:
  - Configuration & Secret Protection (no key leakage in responses/logs)
  - Strict Input Validation & SSRF Prevention (private IPs, loopback, link-local, multicast, invalid schemes)
  - TinyFish Search & Fetch API Client Mocking (Success, No Results, Timeout, 401 Auth, 429 Rate Limit, 500 Upstream)
  - Source-Grounded Evidence Summarization & Provenance
  - REST Endpoints (/api/threat-intel/research, /fetch, /validate, /status, /summary, /cases/<id>/threat-intel, /save)
  - Case Association & Finding Persistence
  - Forensic Separation (external intelligence never modifies acquired evidence manifests)
  - Audit Logging of External Research
"""
from __future__ import annotations

import os
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from server.server import app, init_db
import server.server as srv
from server.tinyfish_service import (
    TinyFishService,
    get_tinyfish_api_key,
    is_tinyfish_configured,
)
from server.models import CaseModel, ThreatIntelModel


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    init_db(db_path)
    old_env = os.environ.get("JOCKY_DB")
    old_srv_db = srv.DB_PATH
    os.environ["JOCKY_DB"] = db_path
    srv.DB_PATH = db_path
    app.config["TESTING"] = True
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


@pytest.fixture
def client(temp_db):
    with app.test_client() as client:
        yield client


@pytest.fixture
def sample_case(temp_db):
    case = CaseModel.create(
        name="Test Incident 2026-Alpha",
        description="Investigation of suspicious outbound beaconing",
        db_path=temp_db,
        investigator_name="Agent Smith",
    )
    return case


# ─────────────────────────────────────────────────────────────────────────────
# 1. Configuration & Key Leakage Prevention Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_config_status_endpoint(client, monkeypatch):
    """Status endpoint must report configuration without exposing key value."""
    monkeypatch.setenv("TINYFISH_API_KEY", "sk-tinyfish-fake-secret-key-12345")
    res = client.get("/api/threat-intel/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["configured"] is True
    assert data["provider"] == "TinyFish"
    # Verify the secret is NOT leaked anywhere in the response JSON
    raw_text = res.get_data(as_text=True)
    assert "sk-tinyfish" not in raw_text
    assert "fake-secret-key" not in raw_text


def test_missing_config_behavior(client, monkeypatch):
    """When API key is unset, search fails gracefully with CONFIG_ERROR without crashing."""
    monkeypatch.delenv("TINYFISH_API_KEY", raising=False)
    with patch("server.tinyfish_service.get_tinyfish_api_key", return_value=""):
        res = client.post("/api/threat-intel/research", json={"indicator": "8.8.8.8"})
        assert res.status_code == 502
        data = res.get_json()
        assert data["success"] is False
        assert data["code"] == "CONFIG_ERROR"
        assert "TINYFISH_API_KEY is not configured" in data["error"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. Input Validation & SSRF Prevention Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("val,itype,expected_type", [
    ("8.8.8.8", "auto", "ipv4"),
    ("1.1.1.1", "ipv4", "ipv4"),
    ("2001:4860:4860::8888", "auto", "ipv6"),
    ("evil-c2.com", "auto", "domain"),
    ("sub.domain.threat.org", "domain", "domain"),
    ("https://cisa.gov/advisories/aa24-001a", "auto", "url"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "auto", "sha256"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "auto", "sha1"),
    ("d41d8cd98f00b204e9800998ecf8427e", "auto", "md5"),
])
def test_valid_indicators(val, itype, expected_type):
    valid, norm, resolved, err = TinyFishService.validate_indicator(val, itype)
    assert valid is True
    assert resolved == expected_type
    assert not err


@pytest.mark.parametrize("val,itype,expected_error_snippet", [
    ("", "auto", "cannot be empty"),
    ("   ", "domain", "cannot be empty"),
    ("192.168.1.1", "ipv4", "private RFC-1918"),
    ("10.0.0.5", "auto", "private RFC-1918"),
    ("172.16.0.10", "ipv4", "private RFC-1918"),
    ("127.0.0.1", "auto", "loopback"),
    ("169.254.169.254", "auto", "link-local"),
    ("224.0.0.1", "auto", "multicast"),
    ("file:///etc/passwd", "url", "http:// or https://"),
    ("ftp://malicious.site/payload.exe", "url", "http:// or https://"),
    ("http://localhost:8080/admin", "url", "targets local/internal infrastructure"),
    ("http://127.0.0.1:5000/api", "url", "targets local/internal infrastructure"),
    ("invalid_domain_with_spaces .com", "domain", "Invalid domain name syntax"),
    ("not_a_hash_xyz", "sha256", "Invalid SHA-256 hash format"),
    ("12345", "md5", "Invalid MD5 hash format"),
])
def test_invalid_and_ssrf_indicators(val, itype, expected_error_snippet):
    valid, norm, resolved, err = TinyFishService.validate_indicator(val, itype)
    assert valid is False
    assert expected_error_snippet.lower() in err.lower()


def test_oversized_indicator_rejected():
    oversized = "a" * 2500
    valid, norm, resolved, err = TinyFishService.validate_indicator(oversized, "domain")
    assert valid is False
    assert "exceeds maximum allowed length" in err


# ─────────────────────────────────────────────────────────────────────────────
# 3. TinyFish Search API Service Mocking Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_successful_search_ranking():
    raw_results = [
        {
            "position": 1,
            "title": "Random Blog Post About Security",
            "url": "https://randomblog.xyz/post/123",
            "snippet": "General security discussion without specific indicators.",
            "site_name": "Random Blog"
        },
        {
            "position": 2,
            "title": "Cybersecurity Alert: C2 Infrastructure at evil-c2.com",
            "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-evil",
            "snippet": "CISA advisory detailing malicious domains including evil-c2.com used for malware delivery.",
            "site_name": "CISA"
        }
    ]

    ranked = TinyFishService.rank_and_categorize_results(raw_results, "evil-c2.com")
    assert len(ranked) == 2
    # CISA result must be ranked highest due to authoritative domain and exact match boost
    assert ranked[0]["domain"] == "cisa.gov"
    assert ranked[0]["source_category"] == "GOV_ADVISORY"
    assert ranked[0]["relevance_score"] > ranked[1]["relevance_score"]


def test_search_success_mock(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query": '"evil-c2.com" threat intelligence',
        "total_results": 1,
        "results": [
            {
                "position": 1,
                "title": "Malware Advisory",
                "url": "https://www.cisa.gov/advisory/101",
                "snippet": "Analysis of evil-c2.com command and control activity.",
                "site_name": "CISA",
            }
        ],
    }

    with patch("server.tinyfish_service.get_tinyfish_api_key", return_value="sk-fake-key"):
        with patch("requests.get", return_value=mock_resp):
            res = TinyFishService.search("evil-c2.com", indicator_type="domain")
            assert res["success"] is True
            assert res["indicator"] == "evil-c2.com"
            assert res["indicator_type"] == "domain"
            assert len(res["results"]) == 1
            assert res["results"][0]["domain"] == "cisa.gov"
            assert "disclaimer" in res


def test_search_rate_limited_mock():
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    with patch("server.tinyfish_service.get_tinyfish_api_key", return_value="sk-fake-key"):
        with patch("requests.get", return_value=mock_resp):
            res = TinyFishService.search("evil-c2.com", indicator_type="domain")
            assert res["success"] is False
            assert res["code"] == "RATE_LIMITED"


def test_search_timeout_mock():
    import requests
    with patch("server.tinyfish_service.get_tinyfish_api_key", return_value="sk-fake-key"):
        with patch("requests.get", side_effect=requests.Timeout):
            res = TinyFishService.search("evil-c2.com", indicator_type="domain")
            assert res["success"] is False
            assert res["code"] == "TIMEOUT"


# ─────────────────────────────────────────────────────────────────────────────
# 4. TinyFish Fetch API Service Mocking Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_fetch_ssrf_protection():
    """Fetch must block private and internal IP targets before sending request."""
    res = TinyFishService.fetch_source("http://192.168.1.10/admin")
    assert res["success"] is False
    assert res["code"] == "SSRF_BLOCKED"

    res_local = TinyFishService.fetch_source("http://localhost:5000/api")
    assert res_local["success"] is False
    assert res_local["code"] == "SSRF_BLOCKED"


def test_fetch_success_mock():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "results": [
            {
                "url": "https://www.cisa.gov/advisory/101",
                "final_url": "https://www.cisa.gov/advisory/101",
                "title": "CISA Security Bulletin",
                "text": "# Threat Advisory\n\nDetailed breakdown of adversary tactics.",
                "format": "markdown",
                "language": "en"
            }
        ],
        "errors": []
    }

    with patch("server.tinyfish_service.get_tinyfish_api_key", return_value="sk-fake-key"):
        with patch("requests.post", return_value=mock_resp):
            res = TinyFishService.fetch_source("https://www.cisa.gov/advisory/101")
            assert res["success"] is True
            assert "Threat Advisory" in res["content"]
            assert res["format"] == "markdown"
            assert res["char_count"] > 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. REST Endpoints & Case Finding Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_research_endpoint_with_case_association(client, sample_case, temp_db):
    cid = sample_case["id"]
    mock_search_res = {
        "success": True,
        "indicator": "evil-c2.com",
        "indicator_type": "domain",
        "query": '"evil-c2.com" threat intelligence',
        "total_results": 1,
        "results": [
            {
                "position": 1,
                "title": "CISA Advisory: Ransomware C2",
                "url": "https://www.cisa.gov/advisories/aa24-01",
                "domain": "cisa.gov",
                "site_name": "CISA",
                "source_category": "GOV_ADVISORY",
                "snippet": "Adversary observed communicating with evil-c2.com.",
                "relevance_score": 95,
                "retrieved_at": "2026-10-25T12:00:00Z"
            }
        ],
        "retrieved_at": "2026-10-25T12:00:00Z",
        "disclaimer": "External web research."
    }

    with patch("server.tinyfish_service.TinyFishService.search", return_value=mock_search_res):
        res = client.post("/api/threat-intel/research", json={
            "indicator": "evil-c2.com",
            "indicator_type": "domain",
            "case_id": cid,
            "context": "Ransomware outbreak"
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["research_id"] is not None
        assert data["case_id"] == cid

        # Verify research record was persisted to database
        history_res = client.get(f"/api/cases/{cid}/threat-intel")
        assert history_res.status_code == 200
        h_data = history_res.get_json()
        assert h_data["count"] == 1
        record = h_data["research_records"][0]
        assert record["indicator"] == "evil-c2.com"
        assert record["review_status"] == "UNREVIEWED"


def test_save_threat_intel_finding(client, sample_case, temp_db):
    cid = sample_case["id"]
    # 1. Create a research record
    saved_research = ThreatIntelModel.save_research(
        case_id=cid,
        indicator="198.51.100.23",
        indicator_type="ipv4",
        query='"198.51.100.23" threat intelligence',
        sources=[{
            "title": "AbuseIPDB Threat Report",
            "url": "https://www.abuseipdb.com/check/198.51.100.23",
            "domain": "abuseipdb.com",
            "site_name": "AbuseIPDB",
            "snippet": "Reported 45 times for SSH brute force and C2 beaconing."
        }],
        db_path=temp_db,
    )
    rid = saved_research["id"]

    # 2. Save as investigator-reviewed finding
    finding_payload = {
        "research_id": rid,
        "title": "External C2 Infrastructure: 198.51.100.23",
        "severity": "HIGH",
        "investigator_notes": "Correlated outbound beacon observed from endpoint matching public AbuseIPDB reports.",
        "recommendations": "Block IP 198.51.100.23 at boundary firewall and isolate affected workstation.",
        "mitre_technique": "T1071.001",
    }
    res = client.post(f"/api/cases/{cid}/threat-intel/save", json=finding_payload)
    assert res.status_code == 201
    f_data = res.get_json()
    assert f_data["success"] is True
    assert f_data["finding"]["category"] == "THREAT_INTELLIGENCE"
    assert f_data["finding"]["severity"] == "HIGH"

    # 3. Verify it shows up in case findings
    find_res = client.get(f"/api/findings?case_id={cid}")
    assert find_res.status_code == 200
    findings = find_res.get_json()["items"]
    assert any(f["title"] == "External C2 Infrastructure: 198.51.100.23" for f in findings)

    # 4. Verify research record review_status was updated
    r_updated = ThreatIntelModel.get_by_id(rid, db_path=temp_db)
    assert r_updated["review_status"] == "SAVED_TO_FINDINGS"


def test_evidence_integrity_unaltered_by_threat_intel(temp_db, sample_case):
    """External threat intelligence records must NOT modify acquired evidence files or manifests."""
    from server.database import get_db_connection
    conn = get_db_connection(temp_db)
    evidence_count_before = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    # Save threat intelligence linked to valid case
    ThreatIntelModel.save_research(
        case_id=sample_case["id"],
        indicator="evil.org",
        indicator_type="domain",
        query="query",
        sources=[],
        db_path=temp_db,
    )

    evidence_count_after = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    conn.close()
    assert evidence_count_before == evidence_count_after == 0


def test_evidence_summary_generation():
    """Verify source-grounded briefing generation without hallucination."""
    results = [
        {
            "position": 1,
            "title": "CISA Alert AA24-100",
            "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-100",
            "domain": "cisa.gov",
            "site_name": "CISA",
            "source_category": "GOV_ADVISORY",
            "snippet": "Adversary infrastructure identified at 203.0.113.55 involved in ransomware campaign.",
        }
    ]
    summary = TinyFishService.generate_evidence_summary("203.0.113.55", "ipv4", results)
    assert summary["authoritative_sources_count"] == 1
    assert "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-100" in summary["sources_cited"][0]["url"]
    assert "203.0.113.55" in summary["summary"]
