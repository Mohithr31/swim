"""
JOCKY Location & Geolocation Telemetry Engine
Provides location analysis based on legitimate endpoint telemetry sources.
Combines Public IP Geolocation, Network Adapter Telemetry, Wi-Fi SSIDs, and System Locale.
"""
import json
import socket
import subprocess
import sys
import time
import urllib.request
from typing import Any, Dict, Optional


def _get_wifi_ssids() -> list:
    ssids=[]
    if sys.platform == "win32":
        try:
            out=subprocess.check_output(["netsh","wlan","show","interfaces"],text=True,errors="replace",stderr=subprocess.DEVNULL,timeout=5)
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    parts=line.split(":",1)
                    if len(parts)==2 and parts[1].strip(): ssids.append(parts[1].strip())
        except Exception: pass
    else:
        try:
            out=subprocess.check_output(["nmcli","-t","-f","ACTIVE,SSID,BSSID","device","wifi"],text=True,errors="replace",stderr=subprocess.DEVNULL,timeout=5)
            for line in out.splitlines():
                parts=line.split(":")
                if len(parts)>=2 and parts[0].upper()=="YES":
                    ssids.append(parts[1])
                    if len(parts)>=3 and parts[2]: ssids.append(f"BSSID:{parts[2]}")
        except Exception:
            try:
                out=subprocess.check_output(["iwgetid","-r"],text=True,errors="replace",stderr=subprocess.DEVNULL,timeout=5).strip()
                if out: ssids.append(out)
            except Exception: pass
    return list(dict.fromkeys(ssids))

def _fetch_ipapi_co(ip: Optional[str]) -> Optional[Dict[str, Any]]:
    url = f"https://ipapi.co/{ip}/json/" if ip and ip not in ["127.0.0.1", "localhost", "::1"] else "https://ipapi.co/json/"
    req = urllib.request.Request(url, headers={"User-Agent": "JOCKY-Forensics/1.0"})
    with urllib.request.urlopen(req, timeout=3) as resp:
        if resp.status == 200:
            data = json.loads(resp.read().decode())
            lat = data.get("latitude")
            lon = data.get("longitude")
            if lat is not None and lon is not None:
                return {
                    "latitude": float(lat),
                    "longitude": float(lon),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "ip": data.get("ip", ip or "IP"),
                    "org": data.get("org", "ISP"),
                    "source": "ipapi.co"
                }
    return None


def _fetch_ipinfo(ip: Optional[str]) -> Optional[Dict[str, Any]]:
    url = f"https://ipinfo.io/{ip}/json" if ip and ip not in ["127.0.0.1", "localhost", "::1"] else "https://ipinfo.io/json"
    req = urllib.request.Request(url, headers={"User-Agent": "JOCKY-Forensics/1.0"})
    with urllib.request.urlopen(req, timeout=3) as resp:
        if resp.status == 200:
            data = json.loads(resp.read().decode())
            loc = data.get("loc")
            if loc and "," in loc:
                lat_str, lon_str = loc.split(",", 1)
                return {
                    "latitude": float(lat_str),
                    "longitude": float(lon_str),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "ip": data.get("ip", ip or "IP"),
                    "org": data.get("org", data.get("company", "ISP")),
                    "source": "ipinfo.io"
                }
    return None


def _fetch_ip_api(ip: Optional[str]) -> Optional[Dict[str, Any]]:
    url = f"http://ip-api.com/json/{ip}" if ip and ip not in ["127.0.0.1", "localhost", "::1"] else "http://ip-api.com/json/"
    req = urllib.request.Request(url, headers={"User-Agent": "JOCKY-Forensics/1.0"})
    with urllib.request.urlopen(req, timeout=3) as resp:
        if resp.status == 200:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return {
                    "latitude": float(data.get("lat")),
                    "longitude": float(data.get("lon")),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "ip": data.get("query", ip or "IP"),
                    "org": data.get("isp", "ISP"),
                    "source": "ip-api.com"
                }
    return None


def get_location_telemetry(ip_address: Optional[str] = None, force_offline: bool = False) -> Dict[str, Any]:
    """
    Evaluates location telemetry using a multi-tier confidence model:
    1. Device Wi-Fi / Subnet Network Indicators -> Medium-High confidence
    2. Public IP Geolocation -> Medium confidence (City/Region level)
    3. Timezone / System Locale -> Low confidence (Country/Region level)
    """
    tz_name = time.tzname[0] if hasattr(time, "tzname") else "UTC"
    wifi_networks = _get_wifi_ssids()

    location_data = {
        "exact_location_available": False,
        "latitude": None,
        "longitude": None,
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "ip": ip_address or "127.0.0.1",
        "timezone": tz_name,
        "wifi_networks": wifi_networks,
        "source": "System Timezone / Network Config",
        "accuracy": "Region Level",
        "confidence": "LOW",
        "honesty_note": "Location estimated from network & system telemetry."
    }

    if force_offline or ip_address == "OFFLINE":
        location_data.update({
            "city": "Local Endpoint Subnet",
            "region": f"Timezone: {tz_name}",
            "country": "Configured System Region",
            "source": "System Timezone / Locale",
            "confidence": "LOW",
            "honesty_note": "Offline mode active. Geolocation limited to local timezone telemetry. Exact GPS location UNAVAILABLE."
        })
        return location_data

    # Attempt Public IP Geolocation across multiple providers with fallbacks
    providers = [_fetch_ipapi_co, _fetch_ipinfo, _fetch_ip_api]
    geo_result = None
    for provider in providers:
        try:
            geo_result = provider(ip_address)
            if geo_result:
                break
        except Exception:
            continue

    if geo_result:
        location_data.update({
            "exact_location_available": False,
            "latitude": geo_result["latitude"],
            "longitude": geo_result["longitude"],
            "city": geo_result["city"],
            "region": geo_result["region"],
            "country": geo_result["country"],
            "ip": geo_result["ip"],
            "org": geo_result.get("org", "ISP"),
            "source": f"Public IP Geolocation ({geo_result['source']})",
            "accuracy": "Approximate (City level)",
            "confidence": "MEDIUM",
            "honesty_note": f"Location estimated from public IP address via {geo_result['source']}."
        })
        return location_data

    # Fallback to local subnet / timezone
    location_data.update({
        "city": "Approximate Region",
        "region": f"Timezone: {tz_name}",
        "country": "System Configured Region",
        "source": "System Timezone / Subnet",
        "accuracy": "Region Level",
        "confidence": "LOW"
    })

    return location_data
