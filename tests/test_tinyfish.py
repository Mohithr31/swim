"""
TINY MONITOR — TinyFish Service Unit Tests
Tests indicator classification, query construction, response normalization,
and mocked API error handling (401, 402, 429, timeouts).
"""

from unittest.mock import MagicMock
import pytest
import requests
from requests.exceptions import Timeout

from app.config import Config
from app.services.tinyfish_service import (
    TinyFishAuthError,
    TinyFishError,
    TinyFishQuotaError,
    TinyFishRateLimitError,
    TinyFishService,
)


def test_classify_indicators():
    assert TinyFishService.classify_indicator("192.168.1.100") == "ip"
    assert TinyFishService.classify_indicator("10.0.0.1") == "ip"
    assert TinyFishService.classify_indicator("phishing-login-portal.com") == "domain"
    assert TinyFishService.classify_indicator("sub.bad-domain.org") == "domain"
    assert TinyFishService.classify_indicator("https://evil.ru/payload.exe") == "url"
    assert TinyFishService.classify_indicator("44d88612fea8a8f36de82e1278abb02f") == "hash"
    assert TinyFishService.classify_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"
    assert TinyFishService.classify_indicator("CVE-2024-38077") == "cve"
    assert TinyFishService.classify_indicator("random investigation note") == "general"


def test_build_threat_query():
    q, p = TinyFishService.build_threat_query("185.220.101.5", "ip")
    assert "185.220.101.5" in q
    assert "threat" in q.lower() or "malicious" in q.lower()
    assert "185.220.101.5" in p

    q_cve, p_cve = TinyFishService.build_threat_query("CVE-2024-38077", "cve")
    assert "CVE-2024-38077" in q_cve
    assert "advisory" in q_cve.lower()


def test_normalize_response_structure():
    raw_api_payload = {
        "query": "evil-domain.com",
        "results": [
            {
                "position": 1,
                "site_name": "cisa.gov",
                "title": "CISA Alert: Active Exploitation of Evil Domain",
                "snippet": "Analysis of threat actors utilizing evil-domain.com for command and control.",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-001a",
                "date": "2026-02-14",
                "publisher": "Cybersecurity and Infrastructure Security Agency"
            }
        ],
        "total_results": 1,
        "page": 0
    }

    normalized = TinyFishService.normalize_response(raw_api_payload)
    assert normalized["query"] == "evil-domain.com"
    assert normalized["total_results"] == 1
    assert len(normalized["results"]) == 1

    item = normalized["results"][0]
    assert item["position"] == 1
    assert item["site_name"] == "cisa.gov"
    assert "CISA Alert" in item["title"]
    assert "cisa.gov" in item["url"]
    assert item["date"] == "2026-02-14"
    assert item["retrieved_at"] is not None


def test_search_raises_auth_error_when_no_key(monkeypatch):
    monkeypatch.setattr(Config, "TINYFISH_API_KEY", "")
    with pytest.raises(TinyFishAuthError, match="not configured"):
        TinyFishService.search(query="test query")


def test_search_raises_auth_error_when_compromised_key(monkeypatch):
    monkeypatch.setattr(Config, "TINYFISH_API_KEY", "sk-tinyfish-old-uURSS7P48Q")
    with pytest.raises(TinyFishAuthError, match="compromised and blocked"):
        TinyFishService.search(query="test query")


def test_search_success_with_mocked_http_200(monkeypatch):
    # Mock requests.get
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query": "test query",
        "results": [
            {
                "position": 1,
                "site_name": "threatpost.com",
                "title": "Security Report",
                "snippet": "Details on threat actor tactics",
                "url": "https://threatpost.com/report-123",
                "date": "2026-01-10"
            }
        ],
        "total_results": 1,
        "page": 0
    }

    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: mock_resp)

    res = TinyFishService.search(query="test query", api_key="sk-tinyfish-valid-test-key-12345")
    assert res["total_results"] == 1
    assert res["results"][0]["title"] == "Security Report"
    assert res["results"][0]["url"] == "https://threatpost.com/report-123"


def test_search_handles_401_auth_failure(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"error": {"code": "INVALID_API_KEY", "message": "The provided API key is invalid"}}
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: mock_resp)

    with pytest.raises(TinyFishAuthError, match="Authentication failed"):
        TinyFishService.search(query="test query", api_key="sk-tinyfish-bad-key")


def test_search_handles_402_quota_exhausted(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.json.return_value = {"error": {"code": "INSUFFICIENT_CREDITS", "message": "Wallet balance is zero"}}
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: mock_resp)

    with pytest.raises(TinyFishQuotaError, match="daily free allowance"):
        TinyFishService.search(query="test query", api_key="sk-tinyfish-valid-key")


def test_search_handles_429_rate_limit(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: mock_resp)

    with pytest.raises(TinyFishRateLimitError, match="rate limit exceeded"):
        TinyFishService.search(query="test query", api_key="sk-tinyfish-valid-key")


def test_search_handles_timeout(monkeypatch):
    def timeout_get(*args, **kwargs):
        raise Timeout("Connection timed out after 15s")

    monkeypatch.setattr(requests, "get", timeout_get)

    with pytest.raises(TinyFishError, match="timed out"):
        TinyFishService.search(query="test query", api_key="sk-tinyfish-valid-key")
