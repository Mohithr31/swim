"""
JOCKY Forensic Platform — TinyFish Threat Intelligence Integration Service
===========================================================================
Provides source-grounded external threat intelligence research for forensic
indicators (domains, IPs, URLs, file hashes) using the official TinyFish REST APIs.

Adheres strictly to DFIR integrity principles:
  - External research is never treated as original forensic endpoint evidence.
  - All sources include original URLs, titles, snippets, and retrieval timestamps.
  - Strict input validation and SSRF defenses protect endpoints and networks.
  - API credentials remain server-side and are never returned or logged.
"""
from __future__ import annotations

import os
import re
import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple

import requests

TINYFISH_SEARCH_ENDPOINT = "https://api.search.tinyfish.ai"
TINYFISH_FETCH_ENDPOINT = "https://api.fetch.tinyfish.ai"

# Authoritative cybersecurity and threat intelligence domains
AUTHORITATIVE_SOURCES = {
    # Government & CERT advisories
    "cisa.gov": ("US Cybersecurity and Infrastructure Security Agency", "GOV_ADVISORY", 95),
    "cert.org": ("CERT Coordination Center", "CERT_ADVISORY", 95),
    "us-cert.gov": ("US-CERT", "GOV_ADVISORY", 95),
    "ncsc.gov.uk": ("UK National Cyber Security Centre", "GOV_ADVISORY", 95),
    "cyber.gov.au": ("Australian Cyber Security Centre", "GOV_ADVISORY", 95),
    "bsi.bund.de": ("BSI Germany", "GOV_ADVISORY", 90),
    # Threat intelligence & reputation databases
    "virustotal.com": ("VirusTotal", "THREAT_INTEL_DB", 90),
    "abuseipdb.com": ("AbuseIPDB", "REPUTATION_DB", 85),
    "alienvault.com": ("AlienVault OTX", "THREAT_INTEL_DB", 85),
    "otx.alienvault.com": ("AlienVault OTX", "THREAT_INTEL_DB", 85),
    "urlscan.io": ("urlscan.io", "SANDBOX_ANALYSIS", 85),
    "hybrid-analysis.com": ("Hybrid Analysis", "SANDBOX_ANALYSIS", 85),
    "threatfox.abuse.ch": ("ThreatFox (abuse.ch)", "IOC_DATABASE", 90),
    "bazaar.abuse.ch": ("MalwareBazaar (abuse.ch)", "IOC_DATABASE", 90),
    "malpedia.caad.fkie.fraunhofer.de": ("Malpedia", "THREAT_INTEL_DB", 90),
    "isc.sans.edu": ("SANS Internet Storm Center", "SECURITY_RESEARCH", 85),
    # Security vendors & research labs
    "mandiant.com": ("Mandiant Threat Intelligence", "VENDOR_BULLETIN", 85),
    "microsoft.com": ("Microsoft Security Intelligence", "VENDOR_BULLETIN", 85),
    "crowdstrike.com": ("CrowdStrike Falcon Intelligence", "VENDOR_BULLETIN", 85),
    "unit42.paloaltonetworks.com": ("Palo Alto Unit 42", "VENDOR_BULLETIN", 85),
    "trendmicro.com": ("Trend Micro Security", "VENDOR_BULLETIN", 80),
    "sentinelone.com": ("SentinelOne Research", "VENDOR_BULLETIN", 80),
    "talosintelligence.com": ("Cisco Talos", "VENDOR_BULLETIN", 85),
    "bleepingcomputer.com": ("BleepingComputer", "SECURITY_NEWS", 75),
    "krebsonsecurity.com": ("Krebs on Security", "SECURITY_RESEARCH", 75),
    "malwarebytes.com": ("Malwarebytes Labs", "SECURITY_RESEARCH", 75),
}

# Regex patterns for validation
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
HASH_MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
HASH_SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def is_placeholder_credential(val: Optional[str]) -> bool:
    if not val:
        return True
    s = str(val).strip().lower()
    return (
        s.startswith("replace_with_")
        or s.startswith("your_")
        or (s.startswith("<") and s.endswith(">"))
        or "your-secret" in s
        or "example" in s
        or s in (
            "change_me",
            "changeme",
            "default",
            "password",
            "secret",
            "change-this-to-a-secure-random-key-in-production",
            "dev-insecure-secret-key-change-in-production",
        )
    )


def get_tinyfish_api_key() -> str:
    """Retrieve TinyFish API key from environment or .env without logging or exposing it."""
    key = os.environ.get("TINYFISH_API_KEY", "").strip()
    if not key or key.startswith("${"):
        try:
            from dotenv import load_dotenv
            root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            load_dotenv(os.path.join(root, ".env"), override=True)
            key = os.environ.get("TINYFISH_API_KEY", "").strip()
        except Exception:
            pass
    if key.startswith("${"):
        key = ""
    if is_placeholder_credential(key):
        return ""
    return key


def is_tinyfish_configured() -> bool:
    """Check whether a non-empty, non-placeholder TinyFish API key is present."""
    return bool(get_tinyfish_api_key())


class TinyFishService:
    """Enterprise DFIR Research Service integrating TinyFish Search and Fetch APIs."""

    @staticmethod
    def detect_indicator_type(indicator: str) -> Optional[str]:
        """Infer indicator type from value. Returns domain, ipv4, ipv6, url, or hash."""
        s = indicator.strip()
        if not s:
            return None

        # Check for URL
        if s.lower().startswith(("http://", "https://")):
            return "url"

        # Check for File Hashes
        if HASH_SHA256_REGEX.match(s):
            return "sha256"
        if HASH_SHA1_REGEX.match(s):
            return "sha1"
        if HASH_MD5_REGEX.match(s):
            return "md5"

        # Check for IP address
        try:
            ip_obj = ipaddress.ip_address(s)
            return "ipv4" if ip_obj.version == 4 else "ipv6"
        except ValueError:
            pass

        # Check for Domain
        if DOMAIN_REGEX.match(s):
            return "domain"

        return None

    @classmethod
    def validate_indicator(
        cls, indicator: str, indicator_type: Optional[str] = None
    ) -> Tuple[bool, str, str, str]:
        """
        Validate and normalize an indicator.
        Returns: (is_valid, normalized_value, detected_type, error_message)
        """
        raw = indicator.strip()
        if not raw:
            return False, "", "", "Indicator value cannot be empty."

        if len(raw) > 2048:
            return False, "", "", "Indicator exceeds maximum allowed length (2048 characters)."

        itype = (indicator_type or "").strip().lower()
        if not itype or itype == "auto":
            inferred = cls.detect_indicator_type(raw)
            if not inferred:
                return False, "", "", f"Could not determine indicator type for '{raw[:50]}'. Please specify type."
            itype = inferred

        # Type-specific validation
        if itype in ("hash", "sha256", "sha1", "md5"):
            cleaned = raw.lower()
            if itype == "sha256" or (itype == "hash" and len(cleaned) == 64):
                if not HASH_SHA256_REGEX.match(cleaned):
                    return False, "", "", "Invalid SHA-256 hash format (must be 64 hexadecimal characters)."
                return True, cleaned, "sha256", ""
            elif itype == "sha1" or (itype == "hash" and len(cleaned) == 40):
                if not HASH_SHA1_REGEX.match(cleaned):
                    return False, "", "", "Invalid SHA-1 hash format (must be 40 hexadecimal characters)."
                return True, cleaned, "sha1", ""
            elif itype == "md5" or (itype == "hash" and len(cleaned) == 32):
                if not HASH_MD5_REGEX.match(cleaned):
                    return False, "", "", "Invalid MD5 hash format (must be 32 hexadecimal characters)."
                return True, cleaned, "md5", ""
            else:
                return False, "", "", f"Invalid hash length ({len(cleaned)} chars). Supported: MD5 (32), SHA-1 (40), SHA-256 (64)."

        elif itype in ("ip", "ipv4", "ipv6"):
            try:
                ip_obj = ipaddress.ip_address(raw)
            except ValueError:
                return False, "", "", f"Invalid IP address format: '{raw}'"

            # Anti-SSRF and safety checks: reject loopback, link-local, multicast, private
            if ip_obj.is_loopback:
                return False, "", "", f"IP '{raw}' is a local loopback address."
            if ip_obj.is_link_local:
                return False, "", "", f"IP '{raw}' is a link-local address."
            if ip_obj.is_multicast:
                return False, "", "", f"IP '{raw}' is a multicast address."
            if ip_obj.is_private:
                return False, "", "", f"IP '{raw}' is a private RFC-1918 network address. External threat intelligence only applies to public routable IPs."
            if not ip_obj.is_global:
                return False, "", "", f"IP '{raw}' is not a globally routable public address."

            resolved_type = "ipv4" if ip_obj.version == 4 else "ipv6"
            return True, str(ip_obj), resolved_type, ""

        elif itype == "domain":
            cleaned = raw.lower()
            # Strip protocol if accidentally pasted
            if cleaned.startswith("http://"):
                cleaned = cleaned[7:]
            elif cleaned.startswith("https://"):
                cleaned = cleaned[8:]
            cleaned = cleaned.split("/")[0].split(":")[0]  # remove path and port

            if not DOMAIN_REGEX.match(cleaned):
                return False, "", "", f"Invalid domain name syntax: '{cleaned}'"
            if cleaned.endswith(".local") or cleaned.endswith(".internal") or cleaned == "localhost":
                return False, "", "", f"Domain '{cleaned}' is an internal/local destination, not suitable for external threat research."

            return True, cleaned, "domain", ""

        elif itype == "url":
            # Must have http or https scheme
            parsed = urlparse(raw)
            if parsed.scheme.lower() not in ("http", "https"):
                return False, "", "", "URL must use http:// or https:// scheme."
            hostname = parsed.hostname
            if not hostname:
                return False, "", "", "URL missing valid hostname."

            # Check if hostname is an IP
            try:
                ip_obj = ipaddress.ip_address(hostname)
                if not ip_obj.is_global:
                    return False, "", "", f"URL targets local/internal infrastructure (SSRF protection: {hostname})."
            except ValueError:
                # Hostname is a domain
                if hostname.lower() in ("localhost", "127.0.0.1") or hostname.lower().endswith(".local"):
                    return False, "", "", "URL targets local/internal infrastructure (SSRF protection)."

            return True, raw, "url", ""

        return False, "", "", f"Unsupported indicator type: '{itype}'. Supported: domain, ipv4, ipv6, url, sha256, sha1, md5."

    @staticmethod
    def build_search_query(indicator: str, indicator_type: str, context: Optional[str] = None) -> str:
        """Construct a focused, safe search query for public threat intelligence."""
        ctx = f" {context.strip()}" if context and context.strip() else ""

        if indicator_type in ("sha256", "sha1", "md5", "hash"):
            return f'"{indicator}" (threat OR malware OR advisory OR analysis OR cve){ctx}'
        elif indicator_type in ("ipv4", "ipv6", "ip"):
            return f'"{indicator}" (malicious OR "c2" OR abuse OR threat OR scanner){ctx}'
        elif indicator_type == "domain":
            return f'"{indicator}" (malware OR "c2" OR phishing OR threat OR advisory){ctx}'
        elif indicator_type == "url":
            parsed = urlparse(indicator)
            host = parsed.hostname or indicator
            return f'"{indicator}" OR "{host}" (malicious OR phishing OR payload){ctx}'
        else:
            return f'"{indicator}" threat intelligence{ctx}'

    @classmethod
    def rank_and_categorize_results(
        cls, raw_results: List[Dict[str, Any]], indicator: str
    ) -> List[Dict[str, Any]]:
        """
        Rank and annotate search results based on domain authority,
        exact indicator match, and cybersecurity relevance.
        """
        ranked = []
        indicator_lower = indicator.lower()

        for item in raw_results:
            url = item.get("url", "")
            title = item.get("title", "")
            snippet = item.get("snippet", "")
            site_name = item.get("site_name", "")

            # Parse domain
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]

            # Determine source category and baseline trust
            source_category = "PUBLIC_WEB_SOURCE"
            source_org = site_name or host
            authority_weight = 40

            # Match against authoritative domains
            for auth_domain, (org_name, cat, weight) in AUTHORITATIVE_SOURCES.items():
                if host == auth_domain or host.endswith("." + auth_domain):
                    source_category = cat
                    source_org = org_name
                    authority_weight = weight
                    break

            # Calculate transparent relevance score (0-100)
            score = authority_weight
            title_lower = title.lower()
            snippet_lower = snippet.lower()

            # Exact indicator match boost
            if indicator_lower in title_lower:
                score += 15
            elif indicator_lower in snippet_lower:
                score += 10

            # Security keywords boost
            security_terms = ["malware", "advisory", "vulnerability", "cve-", "ransomware", "trojan", "apt", "c2", "c&c"]
            term_matches = sum(1 for term in security_terms if term in title_lower or term in snippet_lower)
            score += min(15, term_matches * 5)

            score = max(10, min(99, score))

            ranked.append({
                "position": item.get("position", len(ranked) + 1),
                "title": title or host,
                "url": url,
                "domain": host,
                "site_name": source_org,
                "source_category": source_category,
                "snippet": snippet,
                "relevance_score": score,
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            })

        # Sort by relevance score descending
        ranked.sort(key=lambda x: x["relevance_score"], reverse=True)
        return ranked

    @classmethod
    def search(
        cls,
        indicator: str,
        indicator_type: Optional[str] = None,
        context: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        """
        Execute a public threat intelligence search via TinyFish Search API.
        """
        # Validate indicator
        is_valid, norm_ind, resolved_type, err = cls.validate_indicator(indicator, indicator_type)
        if not is_valid:
            return {
                "success": False,
                "error": err,
                "code": "VALIDATION_ERROR",
                "indicator": indicator,
            }

        key = api_key or get_tinyfish_api_key()
        if not key:
            return {
                "success": False,
                "error": "TINYFISH_API_KEY is not configured on the server. Please configure it in .env to enable live threat intelligence.",
                "code": "CONFIG_ERROR",
                "indicator": norm_ind,
                "indicator_type": resolved_type,
            }

        query = cls.build_search_query(norm_ind, resolved_type, context)
        purpose = f"DFIR forensic indicator triage lookup for {resolved_type} '{norm_ind}' in security incident investigation."

        params = {
            "query": query,
            "purpose": purpose[:500],
            "location": "US",
            "language": "en",
        }
        headers = {
            "X-API-Key": key,
            "User-Agent": "JOCKY-DFIR-Platform/2026.1",
        }

        try:
            resp = requests.get(
                TINYFISH_SEARCH_ENDPOINT,
                params=params,
                headers=headers,
                timeout=timeout,
            )

            if resp.status_code == 401:
                return {
                    "success": False,
                    "error": "TinyFish API authentication failed. Please verify your TINYFISH_API_KEY.",
                    "code": "AUTH_ERROR",
                    "indicator": norm_ind,
                }
            elif resp.status_code == 429:
                return {
                    "success": False,
                    "error": "TinyFish API rate limit exceeded. Please wait a moment before retrying.",
                    "code": "RATE_LIMITED",
                    "indicator": norm_ind,
                }
            elif resp.status_code != 200:
                return {
                    "success": False,
                    "error": f"TinyFish Search API returned HTTP {resp.status_code}.",
                    "code": "UPSTREAM_ERROR",
                    "indicator": norm_ind,
                }

            data = resp.json()
            raw_results = data.get("results", [])
            ranked_results = cls.rank_and_categorize_results(raw_results, norm_ind)

            return {
                "success": True,
                "indicator": norm_ind,
                "indicator_type": resolved_type,
                "query": query,
                "total_results": len(ranked_results),
                "results": ranked_results,
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "disclaimer": "External web research retrieved via TinyFish. Not original endpoint forensic evidence. Verify sources independently.",
            }

        except requests.Timeout:
            return {
                "success": False,
                "error": "TinyFish Search API request timed out (15s). The upstream service may be busy.",
                "code": "TIMEOUT",
                "indicator": norm_ind,
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "error": f"Network error connecting to TinyFish Search API: {type(e).__name__}",
                "code": "NETWORK_ERROR",
                "indicator": norm_ind,
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error executing TinyFish search: {type(e).__name__}",
                "code": "INTERNAL_ERROR",
                "indicator": norm_ind,
            }

    @classmethod
    def fetch_source(
        cls,
        url: str,
        api_key: Optional[str] = None,
        max_length: int = 6000,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        """
        Fetch and extract clean markdown text from a specific permitted public source URL
        using the TinyFish Fetch API.
        Enforces SSRF prevention checks prior to upstream dispatch.
        """
        # Validate URL syntax and safety
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() not in ("http", "https"):
            return {
                "success": False,
                "error": "Only public http:// and https:// URLs can be fetched.",
                "code": "SSRF_BLOCKED",
                "url": url,
            }

        hostname = parsed.hostname
        if not hostname:
            return {"success": False, "error": "URL has no valid hostname.", "code": "INVALID_URL", "url": url}

        # SSRF checks
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if not ip_obj.is_global:
                return {
                    "success": False,
                    "error": f"SSRF Protection: destination '{hostname}' is not a public global IP.",
                    "code": "SSRF_BLOCKED",
                    "url": url,
                }
        except ValueError:
            # Resolvable domain name — check if it's localhost or internal
            if hostname.lower() in ("localhost", "127.0.0.1") or hostname.lower().endswith(".local") or hostname.lower().endswith(".internal"):
                return {
                    "success": False,
                    "error": f"SSRF Protection: destination '{hostname}' is internal.",
                    "code": "SSRF_BLOCKED",
                    "url": url,
                }

        key = api_key or get_tinyfish_api_key()
        if not key:
            return {
                "success": False,
                "error": "TINYFISH_API_KEY is not configured.",
                "code": "CONFIG_ERROR",
                "url": url,
            }

        headers = {
            "X-API-Key": key,
            "Content-Type": "application/json",
            "User-Agent": "JOCKY-DFIR-Platform/2026.1",
        }
        payload = {"urls": [url]}

        try:
            resp = requests.post(
                TINYFISH_FETCH_ENDPOINT,
                json=payload,
                headers=headers,
                timeout=timeout,
            )

            if resp.status_code == 401:
                return {"success": False, "error": "TinyFish API authentication failed.", "code": "AUTH_ERROR", "url": url}
            elif resp.status_code == 429:
                return {"success": False, "error": "TinyFish API rate limit exceeded.", "code": "RATE_LIMITED", "url": url}
            elif resp.status_code != 200:
                return {"success": False, "error": f"TinyFish Fetch API returned HTTP {resp.status_code}.", "code": "UPSTREAM_ERROR", "url": url}

            data = resp.json()
            results = data.get("results", [])
            errors = data.get("errors", [])

            if errors and not results:
                err_msg = errors[0].get("error", "Failed to fetch source content.")
                return {"success": False, "error": err_msg, "code": "FETCH_FAILED", "url": url}

            if not results:
                return {"success": False, "error": "No content returned for this URL.", "code": "EMPTY_RESULT", "url": url}

            page = results[0]
            raw_text = page.get("text", "") or page.get("description", "") or ""
            truncated = len(raw_text) > max_length
            bounded_text = raw_text[:max_length]

            return {
                "success": True,
                "url": url,
                "final_url": page.get("final_url", url),
                "title": page.get("title", ""),
                "description": page.get("description", ""),
                "language": page.get("language", "en"),
                "format": page.get("format", "markdown"),
                "content": bounded_text,
                "truncated": truncated,
                "char_count": len(bounded_text),
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }

        except requests.Timeout:
            return {"success": False, "error": "Request timed out while fetching page content.", "code": "TIMEOUT", "url": url}
        except requests.RequestException as e:
            return {"success": False, "error": f"Network error during fetch: {type(e).__name__}", "code": "NETWORK_ERROR", "url": url}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error during fetch: {type(e).__name__}", "code": "INTERNAL_ERROR", "url": url}

    @classmethod
    def generate_evidence_summary(
        cls, indicator: str, indicator_type: str, search_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a strictly source-grounded briefing from retrieved public sources.
        Avoids hallucination: only cites facts actually present in snippets and titles.
        """
        if not search_results:
            return {
                "summary": f"No public threat intelligence sources were found for indicator '{indicator}'. Insufficient external evidence to draw conclusions.",
                "reported_associations": [],
                "authoritative_sources_count": 0,
                "sources_cited": [],
                "confidence": "INSUFFICIENT_DATA",
            }

        authoritative = [r for r in search_results if r.get("source_category") in ("GOV_ADVISORY", "CERT_ADVISORY", "VENDOR_BULLETIN", "THREAT_INTEL_DB", "IOC_DATABASE")]
        sources_cited = [{"title": r["title"], "url": r["url"], "domain": r["domain"], "site_name": r["site_name"]} for r in search_results[:5]]

        bullet_points = []
        for r in search_results[:5]:
            snippet = r.get("snippet", "").strip()
            if snippet:
                # Truncate clean snippet
                clean_snip = " ".join(snippet.split()[:40])
                bullet_points.append(f"[{r.get('site_name') or r.get('domain')}]: {clean_snip} (Source: {r.get('url')})")

        headline = f"External research retrieved {len(search_results)} relevant public source(s) for {indicator_type.upper()} indicator '{indicator}'."
        if authoritative:
            headline += f" Including {len(authoritative)} advisory/vendor intelligence report(s)."

        return {
            "summary": headline,
            "findings_excerpts": bullet_points,
            "authoritative_sources_count": len(authoritative),
            "sources_cited": sources_cited,
            "disclaimer": "This intelligence summary is compiled from external web sources retrieved via TinyFish and does not independently prove activity on the investigated endpoint.",
        }
