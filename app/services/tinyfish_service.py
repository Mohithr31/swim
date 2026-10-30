"""
TINY MONITOR — TinyFish Service
Production-grade integration with official TinyFish Search API (https://api.search.tinyfish.ai).
Handles authentication, error normalization, rate limits, indicator classification, and connectivity testing.
"""

import re
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from requests.exceptions import ConnectionError, HTTPError, RequestException, Timeout

from app.config import Config
from app.database import utc_now_iso

logger = logging.getLogger("tiny_monitor.tinyfish")


class TinyFishError(Exception):
    """Base exception for TinyFish integration issues."""
    def __init__(self, message: str, status_code: Optional[int] = None, error_code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


class TinyFishAuthError(TinyFishError):
    """Raised when authentication fails (401/403)."""
    pass


class TinyFishQuotaError(TinyFishError):
    """Raised when quota/allowance is exhausted (402)."""
    pass


class TinyFishRateLimitError(TinyFishError):
    """Raised when rate limit is exceeded (429)."""
    pass


class TinyFishService:
    """Service to interact with TinyFish Search API and manage integration health."""

    # Cached connectivity test status:
    # {"status": "NOT_CONFIGURED"|"CONFIGURED_AND_TESTED"|"AUTH_FAILED"|"REQUEST_FAILED", "message": "...", "timestamp": "..."}
    _last_test_result: Optional[Dict[str, Any]] = None

    @classmethod
    def get_api_key(cls) -> str:
        """Retrieve the configured TinyFish API key or empty string."""
        return Config.TINYFISH_API_KEY.strip()

    @classmethod
    def is_configured(cls) -> bool:
        """Return True only if a non-placeholder API key is set."""
        return Config.is_tinyfish_configured()

    @classmethod
    def classify_indicator(cls, indicator: str) -> str:
        """
        Classify input indicator type for cybersecurity research.
        Supported types: 'ip', 'domain', 'url', 'hash', 'cve', 'general'
        """
        raw = indicator.strip()
        if not raw:
            return "general"

        # CVE pattern (e.g. CVE-2024-38077)
        if re.match(r"^CVE-\d{4}-\d{4,}$", raw, re.IGNORECASE):
            return "cve"

        # IP address (IPv4)
        ip_v4_pattern = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
        if re.match(ip_v4_pattern, raw):
            return "ip"

        # Hashes: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
        if re.match(r"^[a-fA-F0-9]{32}$", raw) or re.match(r"^[a-fA-F0-9]{40}$", raw) or re.match(r"^[a-fA-F0-9]{64}$", raw):
            return "hash"

        # URL pattern
        if raw.startswith("http://") or raw.startswith("https://"):
            return "url"

        # Domain pattern (e.g. evil-domain.com, sub.threat.net)
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if re.match(domain_pattern, raw):
            return "domain"

        return "general"

    @classmethod
    def build_threat_query(cls, indicator: str, indicator_type: str) -> Tuple[str, str]:
        """
        Formulate a cybersecurity intelligence query and purpose string for TinyFish Search API.
        Returns: (query_string, purpose_string)
        """
        indicator = indicator.strip()
        if indicator_type == "ip":
            query = f'"{indicator}" (malicious OR threat OR incident OR abuse OR vulnerability OR c2)'
            purpose = f"Investigating threat intelligence, malicious activities, and security incident reports for IP address {indicator}"
        elif indicator_type == "domain":
            query = f'"{indicator}" (malware OR phishing OR breach OR abuse OR c2 OR security advisory)'
            purpose = f"Investigating security threat intelligence, phishing, and advisory reports for domain {indicator}"
        elif indicator_type == "url":
            parsed = urlparse(indicator)
            netloc = parsed.netloc or indicator
            query = f'"{netloc}" (phishing OR malware OR security report)'
            purpose = f"Investigating reputation and security threat advisories for URL {indicator}"
        elif indicator_type == "hash":
            query = f'"{indicator}" (malware OR hash OR virus OR trojan OR ransom)'
            purpose = f"Investigating malware analysis and threat intelligence reports for cryptographic hash {indicator}"
        elif indicator_type == "cve":
            query = f'"{indicator}" (advisory OR exploit OR patch OR mitigation OR cisa)'
            purpose = f"Investigating vulnerability details, public exploits, and vendor advisories for {indicator}"
        else:
            query = f"{indicator} cybersecurity threat analysis"
            purpose = f"Researching cybersecurity incident data for query: {indicator}"

        return query, purpose

    @classmethod
    def search(
        cls,
        query: str,
        purpose: Optional[str] = None,
        domain_type: str = "web",
        location: str = "US",
        language: str = "en",
        api_key: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Execute a genuine GET request to TinyFish Search API endpoint.
        Normalizes the response and raises appropriate TinyFishError subclasses on failure.
        Never substitutes fake or placeholder results.
        """
        key = api_key or cls.get_api_key()
        if not key or key == "your_tinyfish_api_key_here":
            raise TinyFishAuthError(
                "TinyFish API key is not configured. Please set TINYFISH_API_KEY in your local .env file.",
                status_code=401,
                error_code="NOT_CONFIGURED"
            )

        if "COMPROMISED_KEY_DETECTED" in Config.get_redacted_api_key() or key in getattr(Config, "REVOKED_KEYS", set()):
            raise TinyFishAuthError(
                "TinyFish API key is compromised and blocked. Please rotate credentials in .env.",
                status_code=401,
                error_code="COMPROMISED_KEY_BLOCKED"
            )

        if not query or not query.strip():
            raise TinyFishError("Search query cannot be empty.", status_code=400, error_code="INVALID_QUERY")

        endpoint = Config.TINYFISH_SEARCH_ENDPOINT
        headers = {
            "X-API-Key": key,
            "Accept": "application/json",
            "User-Agent": "TinyMonitor-DFIR/1.0"
        }

        params: Dict[str, Any] = {
            "query": query.strip(),
            "location": location,
            "language": language,
            "domain_type": domain_type if domain_type in ("web", "news", "research_paper") else "web"
        }
        if purpose:
            params["purpose"] = purpose[:2000]

        req_timeout = timeout or Config.TINYFISH_TIMEOUT

        try:
            logger.info("Executing TinyFish search: endpoint=%s, query=%s", endpoint, query[:50])
            resp = requests.get(endpoint, headers=headers, params=params, timeout=req_timeout)
        except Timeout as exc:
            cls._last_test_result = {
                "status": "REQUEST_FAILED",
                "message": f"TinyFish API request timed out after {req_timeout}s.",
                "timestamp": utc_now_iso()
            }
            raise TinyFishError(
                f"TinyFish Search API timed out after {req_timeout} seconds.",
                status_code=504,
                error_code="TIMEOUT"
            ) from exc
        except ConnectionError as exc:
            cls._last_test_result = {
                "status": "REQUEST_FAILED",
                "message": "Network connection error connecting to TinyFish API.",
                "timestamp": utc_now_iso()
            }
            raise TinyFishError(
                "Unable to connect to TinyFish API. Check your internet connection or endpoint URL.",
                status_code=503,
                error_code="CONNECTION_ERROR"
            ) from exc
        except RequestException as exc:
            cls._last_test_result = {
                "status": "REQUEST_FAILED",
                "message": f"Network request error: {str(exc)}",
                "timestamp": utc_now_iso()
            }
            raise TinyFishError(
                f"Network error during TinyFish API request: {str(exc)}",
                status_code=502,
                error_code="NETWORK_ERROR"
            ) from exc

        # Handle specific HTTP error status codes
        if resp.status_code == 401:
            cls._last_test_result = {
                "status": "AUTH_FAILED",
                "message": "Authentication failed: 401 Unauthorized (Invalid or expired API Key).",
                "timestamp": utc_now_iso()
            }
            err_msg = "Authentication failed: TinyFish API key is invalid or revoked."
            try:
                err_data = resp.json().get("error", {})
                if isinstance(err_data, dict) and "message" in err_data:
                    err_msg = f"Authentication failed: {err_data['message']}"
            except Exception:
                pass
            raise TinyFishAuthError(err_msg, status_code=401, error_code="INVALID_API_KEY")

        if resp.status_code == 402:
            cls._last_test_result = {
                "status": "REQUEST_FAILED",
                "message": "Quota / Wallet balance exhausted (402 Payment Required).",
                "timestamp": utc_now_iso()
            }
            raise TinyFishQuotaError(
                "TinyFish daily free allowance used or wallet balance is zero (402 Payment Required).",
                status_code=402,
                error_code="INSUFFICIENT_CREDITS"
            )

        if resp.status_code == 429:
            cls._last_test_result = {
                "status": "REQUEST_FAILED",
                "message": "Rate limit exceeded (429 Too Many Requests).",
                "timestamp": utc_now_iso()
            }
            raise TinyFishRateLimitError(
                "TinyFish rate limit exceeded (429). Please wait before submitting more queries.",
                status_code=429,
                error_code="RATE_LIMIT_EXCEEDED"
            )

        if resp.status_code >= 400:
            cls._last_test_result = {
                "status": "REQUEST_FAILED",
                "message": f"TinyFish API returned HTTP {resp.status_code}",
                "timestamp": utc_now_iso()
            }
            err_msg = f"TinyFish API error: HTTP {resp.status_code}"
            try:
                err_json = resp.json()
                if "error" in err_json:
                    err_msg = f"TinyFish API error: {err_json['error']}"
            except Exception:
                err_msg = f"TinyFish API error: {resp.text[:200]}"
            raise TinyFishError(err_msg, status_code=resp.status_code, error_code=f"HTTP_{resp.status_code}")

        # Parse and validate response JSON
        try:
            data = resp.json()
        except ValueError as exc:
            cls._last_test_result = {
                "status": "REQUEST_FAILED",
                "message": "TinyFish returned invalid JSON.",
                "timestamp": utc_now_iso()
            }
            raise TinyFishError(
                "Failed to parse TinyFish API response as JSON.",
                status_code=502,
                error_code="MALFORMED_RESPONSE"
            ) from exc

        normalized = cls.normalize_response(data)
        cls._last_test_result = {
            "status": "CONFIGURED_AND_TESTED",
            "message": f"Successfully connected and verified against TinyFish Search API. ({len(normalized['results'])} results returned)",
            "timestamp": utc_now_iso()
        }
        return normalized

    @classmethod
    def normalize_response(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize raw API response according to TinyFish Search schema.
        Ensures consistent, safe dictionary structure for UI and reporting.
        """
        query_text = raw.get("query", "")
        raw_results = raw.get("results", [])
        total_results = raw.get("total_results", len(raw_results))
        page = raw.get("page", 0)

        cleaned_results: List[Dict[str, Any]] = []
        for i, item in enumerate(raw_results, start=1):
            if not isinstance(item, dict):
                continue
            cleaned_results.append({
                "position": item.get("position", i),
                "title": (item.get("title") or "Untitled Document").strip(),
                "url": (item.get("url") or "").strip(),
                "snippet": (item.get("snippet") or "").strip(),
                "site_name": (item.get("site_name") or "").strip(),
                "date": item.get("date"),
                "publisher": item.get("publisher"),
                "retrieved_at": utc_now_iso()
            })

        return {
            "query": query_text,
            "results": cleaned_results,
            "total_results": total_results,
            "page": page,
            "normalized_at": utc_now_iso()
        }

    @classmethod
    def test_connection(cls) -> Dict[str, Any]:
        """
        Perform a live connectivity verification test.
        Returns clear integration status dictionary:
        - status: 'CONFIGURED_AND_TESTED' | 'NOT_CONFIGURED' | 'AUTH_FAILED' | 'REQUEST_FAILED'
        - message: human-readable explanation
        - key_status: redacted key representation
        - timestamp: ISO 8601 string
        """
        redacted_key = Config.get_redacted_api_key()

        if not cls.is_configured():
            res = {
                "status": "NOT_CONFIGURED",
                "message": "TinyFish API key is not configured in .env. Please set TINYFISH_API_KEY with a valid key.",
                "key_status": redacted_key,
                "timestamp": utc_now_iso()
            }
            cls._last_test_result = res
            return res

        try:
            # Perform a lightweight search test query
            test_query = "Presidency University Bengaluru cybersecurity"
            test_purpose = "Tiny Monitor connectivity health check"
            resp = cls.search(query=test_query, purpose=test_purpose, timeout=10.0)
            res = {
                "status": "CONFIGURED_AND_TESTED",
                "message": f"Successfully authenticated and queried TinyFish Search API. ({len(resp['results'])} results retrieved).",
                "key_status": redacted_key,
                "endpoint": Config.TINYFISH_SEARCH_ENDPOINT,
                "timestamp": utc_now_iso()
            }
            cls._last_test_result = res
            return res
        except TinyFishAuthError as exc:
            res = {
                "status": "AUTH_FAILED",
                "message": f"Authentication failed: {exc.message}",
                "key_status": redacted_key,
                "timestamp": utc_now_iso()
            }
            cls._last_test_result = res
            return res
        except TinyFishError as exc:
            res = {
                "status": "REQUEST_FAILED",
                "message": f"Request failed: {exc.message}",
                "key_status": redacted_key,
                "timestamp": utc_now_iso()
            }
            cls._last_test_result = res
            return res
        except Exception as exc:
            res = {
                "status": "REQUEST_FAILED",
                "message": f"Unexpected error during connection test: {str(exc)}",
                "key_status": redacted_key,
                "timestamp": utc_now_iso()
            }
            cls._last_test_result = res
            return res

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """Return the current integration status without triggering an unprompted network call."""
        key_repr = Config.get_redacted_api_key()
        if "COMPROMISED_KEY_DETECTED" in key_repr:
            return {
                "status": "NOT_CONFIGURED",
                "message": "Previously exposed API key was compromised and blocked. Please add a newly rotated TINYFISH_API_KEY in your local .env file.",
                "key_status": key_repr,
                "endpoint": Config.TINYFISH_SEARCH_ENDPOINT,
                "last_tested": None
            }

        if not cls.is_configured():
            return {
                "status": "NOT_CONFIGURED",
                "message": "TinyFish API key is not configured in .env. Set TINYFISH_API_KEY to enable live research.",
                "key_status": key_repr,
                "endpoint": Config.TINYFISH_SEARCH_ENDPOINT,
                "last_tested": cls._last_test_result.get("timestamp") if cls._last_test_result else None
            }

        if cls._last_test_result:
            return {
                "status": cls._last_test_result["status"],
                "message": cls._last_test_result["message"],
                "key_status": Config.get_redacted_api_key(),
                "endpoint": Config.TINYFISH_SEARCH_ENDPOINT,
                "last_tested": cls._last_test_result["timestamp"]
            }

        return {
            "status": "CONFIGURED_UNTESTED",
            "message": "TinyFish API key is present in environment, but connectivity has not been tested yet.",
            "key_status": Config.get_redacted_api_key(),
            "endpoint": Config.TINYFISH_SEARCH_ENDPOINT,
            "last_tested": None
        }
