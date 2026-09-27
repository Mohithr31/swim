"""
JOCKY DFIR Gateway — B5 Web & Social Activity Mapping Engine
Maps web and social platforms from legitimate browser history artifacts.
Assigns forensic evidence types:
  VISITED_DOMAIN
  LOGIN_PAGE_VISITED
  SESSION_ARTIFACT_PRESENT
  ACCOUNT_ARTIFACT_UNKNOWN
Never extracts cookies, tokens, or credentials.
"""
import os
import sys
import hashlib
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


KNOWN_PLATFORMS = [
    ("Google", ["google.com", "google.co", "accounts.google.com", "mail.google.com", "drive.google.com"]),
    ("Microsoft", ["microsoft.com", "live.com", "login.microsoftonline.com", "office.com", "outlook.com", "bing.com"]),
    ("GitHub", ["github.com", "gist.github.com"]),
    ("YouTube", ["youtube.com", "youtu.be"]),
    ("LinkedIn", ["linkedin.com"]),
    ("Reddit", ["reddit.com", "redd.it"]),
    ("X / Twitter", ["x.com", "twitter.com", "t.co"]),
    ("Facebook", ["facebook.com", "fb.com", "messenger.com"]),
    ("Instagram", ["instagram.com"]),
    ("WhatsApp Web", ["web.whatsapp.com", "whatsapp.com"]),
    ("Telegram Web", ["web.telegram.org", "telegram.org"]),
    ("Discord", ["discord.com", "discordapp.com"]),
    ("OpenAI / ChatGPT", ["openai.com", "chatgpt.com"]),
    ("Amazon", ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"]),
    ("Apple / iCloud", ["apple.com", "icloud.com"]),
    ("Netflix", ["netflix.com"]),
    ("Spotify", ["spotify.com"]),
    ("Slack", ["slack.com"]),
    ("Zoom", ["zoom.us"]),
    ("Wikipedia", ["wikipedia.org", "wikimedia.org"]),
    ("Stack Overflow", ["stackoverflow.com", "stackexchange.com"]),
]


def identify_platform(domain: str) -> Optional[str]:
    """Match domain to known web/social platform."""
    dom_lower = domain.lower()
    for plat_name, domain_patterns in KNOWN_PLATFORMS:
        for pat in domain_patterns:
            if pat in dom_lower:
                return plat_name
    return None


class WebActivityMapper:
    """B5 Web & Social Activity Mapper."""

    def __init__(self, device_id: str = "DEV-LOCAL", case_id: str = "CAS-DEFAULT"):
        self.device_id = device_id
        self.case_id = case_id

    def map_from_history(self, history_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate browser history into forensic Web & Social platform activity records."""
        if not history_records:
            return {
                "status": "NO_EVIDENCE_FOUND",
                "items": [],
                "count": 0,
                "platform_summary": {}
            }

        # Key: (platform or domain, browser, profile)
        aggregated: Dict[str, Dict[str, Any]] = {}

        for h in history_records:
            url = h.get("url", "")
            if not url or not url.startswith("http"):
                continue

            try:
                parsed = urllib.parse.urlparse(url)
                netloc = parsed.netloc.lower()
                # strip port if present
                domain = netloc.split(":")[0] if ":" in netloc else netloc
            except Exception:
                continue

            if not domain:
                continue

            plat_name = identify_platform(domain) or domain
            browser = h.get("browser", "Browser")
            profile = h.get("profile", "Default")
            timestamp = h.get("timestamp", datetime.now(timezone.utc).isoformat())

            # Determine evidence type
            is_login = False
            lower_url = url.lower()
            if any(kw in lower_url for kw in ["/login", "/signin", "/sign-in", "/auth", "accounts.google.com", "login.microsoft"]):
                is_login = True

            agg_key = f"{plat_name}_{domain}_{browser}_{profile}"
            if agg_key not in aggregated:
                aggregated[agg_key] = {
                    "platform": plat_name,
                    "domain": domain,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "visit_count": h.get("visit_count", 1) or 1,
                    "evidence_type": "LOGIN_PAGE_VISITED" if is_login else "VISITED_DOMAIN",
                    "browser": browser,
                    "profile": profile,
                    "has_login": is_login,
                    "source": h.get("source", "Browser History"),
                    "status": "COLLECTED"
                }
            else:
                entry = aggregated[agg_key]
                entry["visit_count"] += h.get("visit_count", 1) or 1
                if timestamp < entry["first_seen"]:
                    entry["first_seen"] = timestamp
                if timestamp > entry["last_seen"]:
                    entry["last_seen"] = timestamp
                if is_login:
                    entry["has_login"] = True
                    entry["evidence_type"] = "LOGIN_PAGE_VISITED"

        items = []
        platform_summary: Dict[str, int] = {}
        for k, v in aggregated.items():
            record_id = f"WEB-{hashlib.md5(k.encode()).hexdigest()[:12]}"
            v["id"] = record_id
            v["device_id"] = self.device_id
            v["case_id"] = self.case_id
            v["timestamp"] = v["last_seen"]
            v.pop("has_login", None)
            items.append(v)

            p = v["platform"]
            platform_summary[p] = platform_summary.get(p, 0) + v["visit_count"]

        # Sort by last_seen descending
        items.sort(key=lambda x: x["last_seen"], reverse=True)

        return {
            "status": "COLLECTED" if items else "NO_EVIDENCE_FOUND",
            "items": items,
            "count": len(items),
            "platform_summary": platform_summary
        }
