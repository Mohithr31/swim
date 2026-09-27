"""
JOCKY Location Intelligence Forensics Engine
Answers: WHERE WAS THE DEVICE/ACCOUNT AT A PARTICULAR TIME?
Strictly separates Location Intelligence from Connected Device Forensics.
Enforces Zero Fake Data Policy: Returns "No location evidence found on this system." unless real evidence is found or DEMO MODE is explicitly enabled.
Includes full [LOCATION] backend pipeline logging, safe Windows artifact collectors, EXIF GPS parser, and LocationEvidence model.
"""
import os
import re
import sys
import json
import math
import socket
import hashlib
import subprocess
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from collector.location import get_location_telemetry

# WinReg import (Windows only)
try:
    import winreg
except ImportError:
    winreg = None


def log_loc(msg: str):
    """Print backend pipeline log matching Requirement 10."""
    print(f"[LOCATION] {msg}")


class LocationEvidence:
    """Standardized Location Evidence Data Model matching Requirement 4."""
    def __init__(
        self,
        id: str,
        evidence_type: str,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        accuracy: Optional[float] = None,
        timestamp: Optional[str] = None,
        timestamp_start: Optional[str] = None,
        timestamp_end: Optional[str] = None,
        source: Optional[str] = None,
        source_path: Optional[str] = None,
        artifact_type: Optional[str] = None,
        device: Optional[str] = None,
        network: Optional[str] = None,
        ip_address: Optional[str] = None,
        browser: Optional[str] = None,
        file_path: Optional[str] = None,
        file_hash: Optional[str] = None,
        confidence: str = "LOW",
        timestamp_reliability: str = "CORRELATED",
        description: Optional[str] = None,
        collection_status: str = "FOUND",
        city: Optional[str] = None,
        region: Optional[str] = None,
        country: Optional[str] = None,
        location_name: Optional[str] = None
    ):
        self.id = id
        self.evidence_type = evidence_type
        self.latitude = latitude
        self.longitude = longitude
        self.accuracy = accuracy
        self.timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.timestamp_start = timestamp_start
        self.timestamp_end = timestamp_end
        self.source = source or "Windows Evidence Source"
        self.source_path = source_path
        self.artifact_type = artifact_type or evidence_type
        self.device = device or socket.gethostname() or "Local Host"
        self.network = network
        self.ip_address = ip_address
        self.browser = browser
        self.file_path = file_path
        self.file_hash = file_hash
        self.confidence = confidence
        self.timestamp_reliability = timestamp_reliability
        self.description = description or ""
        self.collection_status = collection_status
        self.city = city
        self.region = region
        self.country = country
        self.location_name = location_name

    def to_dict(self) -> Dict[str, Any]:
        loc_name = self.location_name
        if not loc_name:
            parts = [p for p in [self.city, self.region, self.country] if p and p != "Unknown"]
            if parts:
                loc_name = ", ".join(parts)
        if not loc_name and self.latitude is not None and self.longitude is not None:
            loc_name = f"{self.latitude}, {self.longitude}"
        if not loc_name:
            loc_name = self.network or self.ip_address or self.source or "Unknown Location"

        return {
            "id": self.id,
            "evidence_type": self.evidence_type,
            "evidence_label": self.evidence_type,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "accuracy": self.accuracy,
            "accuracy_meters": self.accuracy,
            "timestamp": self.timestamp,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
            "source": self.source,
            "source_path": self.source_path,
            "artifact_type": self.artifact_type,
            "device": self.device,
            "network": self.network,
            "ip_address": self.ip_address,
            "browser": self.browser,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "confidence": self.confidence,
            "timestamp_reliability": self.timestamp_reliability,
            "description": self.description,
            "collection_status": self.collection_status,
            "city": self.city,
            "region": self.region,
            "country": self.country,
            "location_name": loc_name
        }


class LocationCollector:
    @staticmethod
    def collect_raw_location_artifacts() -> List[Dict[str, Any]]:
        """Safely discover and parse legitimate Windows location artifacts across system, network, browser, EXIF, and IP sources."""
        log_loc("Starting location evidence collection pipeline...")
        artifacts = []
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        host_name = socket.gethostname() or "Local Host"

        # Pre-fetch IP & Telemetry for endpoint location context fallback
        geo_lat = None
        geo_lon = None
        geo_city = None
        geo_region = None
        geo_country = None
        geo_location_str = None
        ip_telemetry = None

        try:
            ip_telemetry = get_location_telemetry(force_offline=False)
            if ip_telemetry.get("latitude") is not None and ip_telemetry.get("longitude") is not None:
                geo_lat = ip_telemetry.get("latitude")
                geo_lon = ip_telemetry.get("longitude")
                geo_city = ip_telemetry.get("city") if ip_telemetry.get("city") != "Unknown" else None
                geo_region = ip_telemetry.get("region") if ip_telemetry.get("region") != "Unknown" else None
                geo_country = ip_telemetry.get("country") if ip_telemetry.get("country") != "Unknown" else None
                geo_parts = [p for p in [geo_city, geo_region, geo_country] if p]
                if geo_parts:
                    geo_location_str = ", ".join(geo_parts)
        except Exception as te:
            log_loc(f"Telemetry resolution warning: {te}")

        # A. Windows Location Services Registry & Consent Store
        log_loc("Checking artifact: Windows Location Services Registry")
        try:
            if sys.platform == "win32" and winreg:
                reg_key_path = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key_path)
                    log_loc(f"Artifact found: HKEY_CURRENT_USER\\{reg_key_path}")
                    
                    # Read subkeys for apps granted location permissions
                    i = 0
                    while True:
                        try:
                            app_sub = winreg.EnumKey(key, i)
                            i += 1
                            if app_sub.lower() != "nonpackaged":
                                sub_key = winreg.OpenKey(key, app_sub)
                                try:
                                    last_used, _ = winreg.QueryValueEx(sub_key, "LastUsedTimeStop")
                                    # Convert Windows 64-bit FILETIME timestamp if present
                                    ev_time = now_str
                                    if last_used and isinstance(last_used, int) and last_used > 0:
                                        us = last_used / 10
                                        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
                                        ev_time = dt.strftime("%Y-%m-%d %H:%M:%S")

                                    app_loc_name = f"{app_sub} ({geo_location_str})" if geo_location_str else app_sub

                                    artifacts.append(LocationEvidence(
                                        id=f"LOC-WINREG-{len(artifacts)+1:03d}",
                                        evidence_type="Windows Location Artifact",
                                        source="Windows Location ConsentStore Registry",
                                        source_path=f"HKCU\\{reg_key_path}\\{app_sub}",
                                        device=host_name,
                                        latitude=geo_lat,
                                        longitude=geo_lon,
                                        city=geo_city,
                                        region=geo_region,
                                        country=geo_country,
                                        location_name=app_loc_name,
                                        timestamp=ev_time,
                                        confidence="MEDIUM",
                                        timestamp_reliability="CONFIRMED",
                                        description=f"Windows App '{app_sub}' requested and accessed location services in region '{geo_location_str or 'Local System'}'.",
                                        collection_status="FOUND"
                                    ).to_dict())
                                except Exception:
                                    pass
                                winreg.CloseKey(sub_key)
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    log_loc("Artifact not found: Windows Location ConsentStore Registry key does not exist.")
                except PermissionError:
                    log_loc("Access denied: Windows Location Registry permissions restricted.")
        except Exception as e:
            log_loc(f"Parse error checking Windows Location Services: {e}")

        # B. Wi-Fi / Network location evidence (cross-platform)
        log_loc("Checking artifact: Wi-Fi / Network connection telemetry")
        try:
            if sys.platform == "win32":
                out=subprocess.check_output(["netsh","wlan","show","interfaces"],text=True,errors="replace",stderr=subprocess.DEVNULL,timeout=5)
                ssid=bssid=None
                for line in out.splitlines():
                    if "BSSID" in line:
                        parts=line.split(":",1); bssid=parts[1].strip() if len(parts)==2 else bssid
                    elif "SSID" in line and "BSSID" not in line:
                        parts=line.split(":",1); ssid=parts[1].strip() if len(parts)==2 else ssid
                if ssid or bssid:
                    artifacts.append(LocationEvidence(id=f"LOC-WIFI-{len(artifacts)+1:03d}",evidence_type="WI-FI LOCATION EVIDENCE",source="Windows WLAN Interface Telemetry",source_path="netsh wlan show interfaces",network=ssid or bssid,device=host_name,latitude=geo_lat,longitude=geo_lon,city=geo_city,region=geo_region,country=geo_country,location_name=f"{ssid or bssid} ({geo_location_str})" if geo_location_str else (ssid or bssid),timestamp=now_str,confidence="MEDIUM",timestamp_reliability="CORRELATED",description="Observed Wi-Fi network telemetry. Coordinates, when present, come from a separate geolocation artifact and are not inferred from SSID.",collection_status="FOUND").to_dict())
            else:
                out=subprocess.check_output(["nmcli","-t","-f","ACTIVE,SSID,BSSID,DEVICE","device","wifi"],text=True,errors="replace",stderr=subprocess.DEVNULL,timeout=5)
                for line in out.splitlines():
                    parts=line.split(":")
                    if len(parts)>=4 and parts[0].upper()=="YES":
                        ssid,bssid,iface=parts[1],parts[2],parts[3]
                        artifacts.append(LocationEvidence(id=f"LOC-LINUX-WIFI-{len(artifacts)+1:03d}",evidence_type="LINUX WI-FI LOCATION EVIDENCE",source="NetworkManager nmcli",source_path="nmcli device wifi",network=ssid or bssid,device=host_name,latitude=geo_lat,longitude=geo_lon,city=geo_city,region=geo_region,country=geo_country,location_name=f"{ssid or bssid} ({geo_location_str})" if geo_location_str else (ssid or bssid),timestamp=now_str,confidence="MEDIUM" if geo_lat is not None else "LOW",timestamp_reliability="CORRELATED",description=f"Observed Wi-Fi network '{ssid}' on interface {iface}; BSSID {bssid}. No physical coordinates are inferred from the network name.",collection_status="FOUND").to_dict())
        except Exception as e:
            log_loc(f"Wi-Fi telemetry unavailable: {e}")

        # Linux NetworkManager connection history
        if sys.platform != "win32":
            try:
                out=subprocess.check_output(["journalctl","-u","NetworkManager","-o","short-iso","--no-pager","-n","300"],text=True,errors="replace",stderr=subprocess.DEVNULL,timeout=10)
                for line in out.splitlines():
                    low=line.lower()
                    if any(x in low for x in ("connected to", "disconnected from", "connection activated", "connection deactivated")):
                        ts=line.split()[0] if line.split() else now_str
                        artifacts.append(LocationEvidence(id=f"LOC-NM-{len(artifacts)+1:03d}",evidence_type="NETWORK LOCATION EVENT",source="NetworkManager journal",source_path="journalctl -u NetworkManager",network=None,device=host_name,latitude=None,longitude=None,location_name="Network connection event",timestamp=ts,confidence="LOW",timestamp_reliability="CONFIRMED",description=line[-500:],collection_status="FOUND").to_dict())
            except Exception: pass

        # Linux WLAN profile files are evidence of configured networks, not proof of physical location.
        if sys.platform != "win32":
            nm_dir=Path("/etc/NetworkManager/system-connections")
            if nm_dir.exists():
                try:
                    for fpath in nm_dir.glob("*.nmconnection"):
                        artifacts.append(LocationEvidence(id=f"LOC-NM-PROF-{len(artifacts)+1:03d}",evidence_type="WI-FI PROFILE ARTIFACT",source="NetworkManager connection profile",source_path=str(fpath),network=fpath.stem,device=host_name,latitude=None,longitude=None,location_name=fpath.stem,timestamp=datetime.fromtimestamp(fpath.stat().st_mtime,timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),confidence="LOW",timestamp_reliability="CORRELATED",description="Saved Wi-Fi configuration artifact. It establishes a configured network, not a physical coordinate.",collection_status="FOUND").to_dict())
                except Exception: pass

        # C. Browser Location Evidence
        log_loc("Checking artifact: Browser Location Permissions")
        try:
            if sys.platform == "win32":
                local_appdata = os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local")
                browser_paths = [("Google Chrome", os.path.join(local_appdata, r"Google\Chrome\User Data\Default\Preferences")), ("Microsoft Edge", os.path.join(local_appdata, r"Microsoft\Edge\User Data\Default\Preferences"))]
            else:
                home = Path.home()
                browser_paths = [("Google Chrome", home/".config/google-chrome/Default/Preferences"), ("Chromium", home/".config/chromium/Default/Preferences"), ("Firefox", home/".mozilla/firefox") ]
            for bname, bpath in browser_paths:
                if not os.path.exists(bpath):
                    continue
                log_loc(f"Artifact found: {bname} Preferences at {bpath}")
                # Firefox stores multiple profiles under ~/.mozilla/firefox;
                # the parent directory itself is not a JSON Preferences file.
                preference_files = [bpath]
                if bname == "Firefox" and bpath.is_dir():
                    preference_files = list(bpath.glob("*/prefs.js")) + list(bpath.glob("*/user.js"))
                for pref_path in preference_files:
                    try:
                        if bname == "Firefox":
                            raw_text = pref_path.read_text(encoding="utf-8", errors="ignore")
                            # prefs.js contains user_pref("key", value) lines;
                            # only record explicit geolocation permission artifacts.
                            for line in raw_text.splitlines():
                                if "geo" in line.lower() and ("permission" in line.lower() or "location" in line.lower()):
                                    mtime = datetime.fromtimestamp(pref_path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                                    artifacts.append(LocationEvidence(
                                        id=f"LOC-FIREFOX-{len(artifacts)+1:03d}",
                                        evidence_type="Browser Location Permission Artifact",
                                        source="Firefox profile preference",
                                        source_path=str(pref_path),
                                        browser=bname, device=host_name,
                                        latitude=None, longitude=None,
                                        location_name="Firefox location permission artifact",
                                        timestamp=mtime, confidence="LOW",
                                        timestamp_reliability="CORRELATED",
                                        description=line.strip()[:500],
                                        collection_status="FOUND"
                                    ).to_dict())
                            continue
                        with open(pref_path, "r", encoding="utf-8", errors="ignore") as f:
                            data = json.load(f)
                        # Extract location permissions from profile preferences
                        prefs = data.get("profile", {}).get("content_settings", {}).get("exceptions", {}).get("geolocation", {})
                        for domain, settings in prefs.items():
                            setting_val = settings.get("setting", 0)
                            if setting_val == 1: # Granted
                                mtime = datetime.fromtimestamp(os.path.getmtime(bpath), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                                b_loc_name = f"{domain} ({bname} Permission in {geo_location_str})" if geo_location_str else f"{domain} ({bname})"
                                artifacts.append(LocationEvidence(
                                    id=f"LOC-BROWSER-{len(artifacts)+1:03d}",
                                    evidence_type="Browser Location Evidence",
                                    source=f"{bname} Geolocation Preferences",
                                    source_path=bpath,
                                    browser=bname,
                                    device=host_name,
                                    latitude=geo_lat,
                                    longitude=geo_lon,
                                    city=geo_city,
                                    region=geo_region,
                                    country=geo_country,
                                    location_name=b_loc_name,
                                    timestamp=mtime,
                                    confidence="LOW",
                                    timestamp_reliability="CORRELATED",
                                    description=f"Browser location permission evidence: Domain '{domain}' granted location permission in {bname}. Location context: {geo_location_str or 'Web Session'}.",
                                    collection_status="FOUND"
                                ).to_dict())
                    except PermissionError:
                        log_loc(f"Access denied: {bpath}")
                    except Exception as pe:
                        log_loc(f"Parse error on {bpath}: {pe}")
        except Exception as e:
            log_loc(f"Error checking browser location evidence: {e}")

        # D. EXIF GPS Image Metadata
        log_loc("Checking artifact: EXIF GPS Image Metadata")
        try:
            user_pics = os.path.expanduser("~/Pictures")
            user_downloads = os.path.expanduser("~/Downloads")
            scan_dirs = [d for d in [user_pics, user_downloads] if os.path.exists(d)]

            for sdir in scan_dirs:
                log_loc(f"Scanning directory for EXIF images: {sdir}")
                for root, dirs, files in os.walk(sdir):
                    for file in files:
                        if file.lower().endswith((".jpg", ".jpeg")):
                            fpath = os.path.join(root, file)
                            try:
                                # Read EXIF bytes for GPS tags
                                with open(fpath, "rb") as f:
                                    header = f.read(65536)
                                
                                # Quick binary search for EXIF GPS tag marker
                                parsed_gps = GPSArtifactParser.extract_exif_gps_from_bytes(header)
                                mtime = datetime.fromtimestamp(os.path.getmtime(fpath), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                                fhash = hashlib.sha256(header[:4096]).hexdigest()

                                if parsed_gps:
                                    log_loc(f"Artifact found: EXIF GPS metadata in {file}")
                                    exif_loc_name = f"{geo_location_str} (EXIF GPS Photo)" if geo_location_str else f"{parsed_gps['latitude']}, {parsed_gps['longitude']}"
                                    artifacts.append(LocationEvidence(
                                        id=f"LOC-EXIF-{len(artifacts)+1:03d}",
                                        evidence_type="EXIF GPS",
                                        latitude=parsed_gps["latitude"],
                                        longitude=parsed_gps["longitude"],
                                        accuracy=5.0,
                                        timestamp=mtime,
                                        source=f"EXIF GPS Header ({file})",
                                        source_path=fpath,
                                        file_path=fpath,
                                        file_hash=fhash,
                                        device=host_name,
                                        city=geo_city,
                                        region=geo_region,
                                        country=geo_country,
                                        location_name=exif_loc_name,
                                        confidence="HIGH",
                                        timestamp_reliability="CONFIRMED",
                                        description=f"Direct coordinate evidence recovered from image file EXIF metadata tags ({file}). Lat: {parsed_gps['latitude']}, Lon: {parsed_gps['longitude']}.",
                                        collection_status="FOUND"
                                    ).to_dict())
                            except PermissionError:
                                log_loc(f"Access denied reading image: {fpath}")
                            except Exception as pe:
                                log_loc(f"Parse error on image {file}: {pe}")
                            
                            if len([a for a in artifacts if a.get("evidence_type") == "EXIF GPS"]) >= 10:
                                break
                    if len([a for a in artifacts if a.get("evidence_type") == "EXIF GPS"]) >= 10:
                        break
        except Exception as e:
            log_loc(f"Error scanning EXIF GPS metadata: {e}")

        # E. Public IP Geolocation Resolution
        log_loc("Checking artifact: Public IP Geolocation")
        try:
            if ip_telemetry and ip_telemetry.get("latitude") is not None and ip_telemetry.get("longitude") is not None:
                log_loc(f"Artifact found: Public IP Geolocation ({ip_telemetry.get('ip')}) via {ip_telemetry.get('source')}")
                ip_loc_name = f"{geo_location_str} (ISP: {ip_telemetry.get('org', 'ISP')})" if geo_location_str else f"IP {ip_telemetry.get('ip')}"
                artifacts.append(LocationEvidence(
                    id="LOC-IP-GEO-001",
                    evidence_type="Approximate IP Geolocation",
                    latitude=ip_telemetry.get("latitude"),
                    longitude=ip_telemetry.get("longitude"),
                    accuracy=50000.0, # 50km city level
                    timestamp=now_str,
                    source=ip_telemetry.get("source", "Public IP Geolocation"),
                    ip_address=ip_telemetry.get("ip"),
                    device=host_name,
                    city=geo_city,
                    region=geo_region,
                    country=geo_country,
                    location_name=ip_loc_name,
                    confidence="LOW",
                    timestamp_reliability="CORRELATED",
                    description=f"Approximate IP geolocation resolved via {ip_telemetry.get('source')} (City: {ip_telemetry.get('city')}, Region: {ip_telemetry.get('region')}, Country: {ip_telemetry.get('country')}, ISP: {ip_telemetry.get('org')}). IMPORTANT: IP geolocation provides approximate routing region, NOT exact physical location.",
                    collection_status="FOUND"
                ).to_dict())
        except Exception as e:
            log_loc(f"Error collecting IP Geolocation: {e}")

        log_loc(f"Valid location evidence count: {len(artifacts)}")
        if not artifacts:
            log_loc("No location evidence found on this system.")

        return artifacts


class GPSArtifactParser:
    @staticmethod
    def extract_exif_gps_from_bytes(data: bytes) -> Optional[Dict[str, float]]:
        """Extract GPS latitude and longitude from raw JPEG binary stream without external C-libraries."""
        try:
            if not data.startswith(b"\xFF\xD8"):
                return None
            
            exif_idx = data.find(b"Exif\x00\x00")
            if exif_idx == -1:
                return None
            
            tiff_start = exif_idx + 6
            endian = data[tiff_start:tiff_start+2]
            if endian not in (b"II", b"MM"):
                return None
            
            is_le = (endian == b"II")

            def get_u16(offset):
                b = data[offset:offset+2]
                return int.from_bytes(b, byteorder="little" if is_le else "big")

            def get_u32(offset):
                b = data[offset:offset+4]
                return int.from_bytes(b, byteorder="little" if is_le else "big")

            first_ifd = get_u32(tiff_start + 4)
            ifd_offset = tiff_start + first_ifd
            
            num_entries = get_u16(ifd_offset)
            gps_ifd_offset = None

            for i in range(num_entries):
                entry_ptr = ifd_offset + 2 + (i * 12)
                tag = get_u16(entry_ptr)
                if tag == 0x8825: # GPS Info Tag
                    gps_ifd_offset = tiff_start + get_u32(entry_ptr + 8)
                    break

            if not gps_ifd_offset:
                return None

            # Parse GPS IFD entries
            gps_entries = get_u16(gps_ifd_offset)
            lat_ref = "N"
            lon_ref = "E"
            lat_deg = None
            lon_deg = None

            for i in range(gps_entries):
                e_ptr = gps_ifd_offset + 2 + (i * 12)
                tag = get_u16(e_ptr)
                val_offset = tiff_start + get_u32(e_ptr + 8)

                def read_rational(off):
                    num = get_u32(off)
                    den = get_u32(off + 4)
                    return float(num) / float(den) if den != 0 else 0.0

                if tag == 1: # GPSLatitudeRef
                    lat_ref = chr(data[e_ptr + 8])
                elif tag == 2: # GPSLatitude
                    deg = read_rational(val_offset)
                    m = read_rational(val_offset + 8)
                    s = read_rational(val_offset + 16)
                    lat_deg = deg + (m / 60.0) + (s / 3600.0)
                elif tag == 3: # GPSLongitudeRef
                    lon_ref = chr(data[e_ptr + 8])
                elif tag == 4: # GPSLongitude
                    deg = read_rational(val_offset)
                    m = read_rational(val_offset + 8)
                    s = read_rational(val_offset + 16)
                    lon_deg = deg + (m / 60.0) + (s / 3600.0)

            if lat_deg is not None and lon_deg is not None:
                if lat_ref == "S":
                    lat_deg = -lat_deg
                if lon_ref == "W":
                    lon_deg = -lon_deg
                return {"latitude": round(lat_deg, 6), "longitude": round(lon_deg, 6)}

        except Exception:
            pass
        return None


class WifiLocationAnalyzer:
    @staticmethod
    def analyze_wifi_artifacts(raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter Wi-Fi access point SSIDs, BSSIDs, and network evidence."""
        return [item for item in raw_data if "Wi-Fi" in item.get("evidence_type", "") or item.get("network")]


class NetworkLocationAnalyzer:
    @staticmethod
    def analyze_ip_artifacts(raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter IP geolocation events. Explicitly labels IP geolocation as approximate."""
        return [item for item in raw_data if "IP" in item.get("evidence_type", "") or item.get("ip_address")]


class EXIFLocationAnalyzer:
    @staticmethod
    def parse_exif_metadata(raw_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter EXIF metadata location records."""
        return [item for item in raw_data if "EXIF" in item.get("evidence_type", "")]


class LocationTimelineAnalyzer:
    @staticmethod
    def build_location_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort location evidence chronologically to establish forensic location timeline."""
        return sorted(events, key=lambda x: str(x.get("timestamp", "")))


class LocationConfidenceEngine:
    @staticmethod
    def evaluate_confidence(evidence_type: str, accuracy_meters: float = None) -> str:
        """Assign confidence rating: HIGH, MEDIUM, LOW, or UNKNOWN."""
        etype = (evidence_type or "").upper()
        if "GPS" in etype or "EXIF" in etype:
            return "HIGH"
        elif "WI-FI" in etype or "WIFI" in etype or "BLUETOOTH" in etype:
            return "MEDIUM"
        elif "IP" in etype or "CELL" in etype or "LOCALE" in etype:
            return "LOW"
        return "UNKNOWN"


def get_demo_location_evidence() -> Dict[str, Any]:
    """Synthetic forensic dataset for Location Intelligence DEMO MODE testing."""
    devices = [
        "Samsung Galaxy S24",
        "iPhone 15 Pro",
        "Google Pixel 8",
        "ThinkPad X1 Carbon",
        "Dell XPS 15",
        "iPad Pro 12.9"
    ]

    location_events = [
        {
            "id": "LOC-00042",
            "device": "Samsung Galaxy S24",
            "timestamp": "2026-09-15 18:44:52",
            "location_name": "Bengaluru, Karnataka, India",
            "latitude": 12.9716,
            "longitude": 77.5946,
            "accuracy": 4.5,
            "accuracy_meters": 4.5,
            "evidence_type": "GPS Artifact",
            "evidence_label": "GPS-BASED LOCATION",
            "source": "Recovered location database",
            "source_path": "C:\\ProgramData\\Microsoft\\Windows\\LocationActivity\\LocationDatabase.db",
            "confidence": "HIGH",
            "timestamp_reliability": "CONFIRMED",
            "description": "High precision GNSS location record recovered from system location cache."
        },
        {
            "id": "LOC-00043",
            "device": "Samsung Galaxy S24",
            "timestamp": "2026-09-15 18:45:01",
            "location_name": "MG Road Central, Bengaluru, India",
            "latitude": 12.9750,
            "longitude": 77.6080,
            "network": "TechPark_Guest_5G",
            "evidence_type": "WI-FI LOCATION EVIDENCE",
            "evidence_label": "WI-FI LOCATION EVIDENCE",
            "source": "WLAN Connection Log",
            "source_path": "netsh wlan show interfaces",
            "confidence": "MEDIUM",
            "timestamp_reliability": "CORRELATED",
            "description": "Connected to Wi-Fi SSID TechPark_Guest_5G. Network evidence supporting possible location context."
        },
        {
            "id": "LOC-00044",
            "device": "Samsung Galaxy S24",
            "timestamp": "2026-09-15 18:45:07",
            "location_name": "Bengaluru Urban, KA, India (ISP Gateway)",
            "latitude": 12.9600,
            "longitude": 77.5700,
            "ip_address": "49.207.210.44",
            "evidence_type": "Approximate IP Geolocation",
            "evidence_label": "APPROXIMATE IP GEOLOCATION",
            "source": "Public IP Geolocation",
            "confidence": "LOW",
            "timestamp_reliability": "CORRELATED",
            "description": "Public IP gateway route geolocation. Approximate IP geolocation provides routing region, NOT exact physical location."
        },
        {
            "id": "LOC-00040",
            "device": "Samsung Galaxy S24",
            "timestamp": "2026-09-15 18:41:23",
            "location_name": "Cubbon Park Entrance, Bengaluru",
            "latitude": 12.9710,
            "longitude": 77.5940,
            "file_path": "C:\\Users\\User\\Pictures\\IMG_20260915_184123.jpg",
            "file_hash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            "evidence_type": "EXIF GPS",
            "evidence_label": "EXIF GPS",
            "source": "EXIF GPS Header",
            "confidence": "HIGH",
            "timestamp_reliability": "CONFIRMED",
            "description": "Direct coordinate evidence recovered from image file EXIF metadata tags."
        },
        {
            "id": "LOC-00035",
            "device": "Samsung Galaxy S24",
            "timestamp": "2026-09-15 18:30:15",
            "location_name": "Indiranagar 100ft Road, Bengaluru",
            "latitude": 12.9784,
            "longitude": 77.6408,
            "evidence_type": "GPS Artifact",
            "evidence_label": "GPS-BASED LOCATION",
            "source": "Navigation App Cache",
            "confidence": "HIGH",
            "timestamp_reliability": "CONFIRMED",
            "description": "Waypoints logged during turn-by-turn navigation session."
        },
        {
            "id": "LOC-00048",
            "device": "Samsung Galaxy S24",
            "timestamp": "2026-09-15 19:10:00",
            "location_name": "Koramangala 5th Block, Bengaluru",
            "latitude": 12.9348,
            "longitude": 77.6253,
            "evidence_type": "GPS Artifact",
            "evidence_label": "GPS-BASED LOCATION",
            "source": "Cellular Tower Triangulation + GNSS",
            "confidence": "HIGH",
            "timestamp_reliability": "CONFIRMED",
            "description": "Active GPS ping at commercial center."
        }
    ]

    return {
        "status": "DEMO DATA MODE (SIMULATED)",
        "known_locations": 24,
        "location_events_count": 186,
        "gps_artifacts_count": 42,
        "network_location_events_count": 73,
        "devices_with_location_count": len(devices),
        "date_range": "01/01/2026 → 15/09/2026",
        "devices": devices,
        "location_events": location_events,
        "demo_mode": True
    }


def get_location_overview_intelligence(demo_mode: bool = False, raw_artifacts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Calculate executive metrics from real location artifacts.

    For an enrolled endpoint, pass its collected artifacts so the central server
    does not accidentally report the server machine's location.
    """
    if demo_mode:
        return get_demo_location_evidence()

    raw_artifacts = raw_artifacts if isinstance(raw_artifacts, list) else LocationCollector.collect_raw_location_artifacts()
    has_real_evidence = len(raw_artifacts) > 0

    if not has_real_evidence:
        return {
            "status": "NO LOCATION EVIDENCE LOADED",
            "message": "No location evidence found on this system.",
            "known_locations": 0,
            "location_events_count": 0,
            "gps_artifacts_count": 0,
            "network_location_events_count": 0,
            "devices_with_location_count": 0,
            "date_range": "N/A",
            "devices": [],
            "location_events": [],
            "demo_mode": False
        }

    devices = list(set(a.get("device", "Local Host") for a in raw_artifacts if a.get("device")))
    gps_count = sum(1 for a in raw_artifacts if "GPS" in a.get("evidence_type", "").upper() or "EXIF" in a.get("evidence_type", "").upper())
    net_count = sum(1 for a in raw_artifacts if "IP" in a.get("evidence_type", "").upper() or "WI-FI" in a.get("evidence_type", "").upper())

    return {
        "status": "EVIDENCE LOADED",
        "known_locations": len(raw_artifacts),
        "location_events_count": len(raw_artifacts),
        "gps_artifacts_count": gps_count,
        "network_location_events_count": net_count,
        "devices_with_location_count": len(devices),
        "date_range": "Live Telemetry",
        "devices": devices,
        "location_events": raw_artifacts,
        "demo_mode": False
    }


def parse_location_datetime(date_str: str, time_str: str) -> datetime:
    d_str = (date_str or "").strip()
    t_str = (time_str or "").strip()
    if not t_str:
        t_str = "12:00:00"
    elif len(t_str.split(":")) == 2:
        t_str = f"{t_str}:00"
    
    combined = f"{d_str} {t_str}".strip()
    
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d/%m/%Y",
        "%m/%d/%Y"
    ]
    for fmt in formats:
        try:
            return datetime.strptime(combined, fmt)
        except ValueError:
            pass
        try:
            return datetime.strptime(d_str, fmt)
        except ValueError:
            pass

    try:
        return datetime.fromisoformat(combined.replace("Z", "+00:00"))
    except Exception:
        pass

    return datetime.now()


def search_location_by_time(
    date_str: str = "2026-09-15",
    time_str: str = "18:45:00",
    range_mins: int = 5,
    device_filter: str = "All Devices",
    demo_mode: bool = False,
    location_events: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Search location evidence around exact date and time (e.g. 2026-09-15 18:45:00 ± 5 min).
    Ranks results by: 1. Timestamp proximity, 2. Evidence reliability, 3. Evidence type, 4. Device association.
    If no evidence falls in narrow search window, automatically falls back to nearest recorded location evidence.
    """
    overview = get_location_overview_intelligence(demo_mode=demo_mode) if location_events is None else {}
    all_events = location_events if location_events is not None else (overview.get("location_events") or [])

    if device_filter and device_filter.lower() != "all devices":
        all_events = [e for e in all_events if device_filter.lower() in (e.get("device") or "").lower()]

    target_dt = parse_location_datetime(date_str, time_str)
    target_datetime_str = target_dt.strftime("%Y-%m-%d %H:%M:%S")

    window_delta = timedelta(minutes=int(range_mins) if str(range_mins).isdigit() else 5)
    start_window = target_dt - window_delta
    end_window = target_dt + window_delta

    matching_events = []
    all_scored_events = []

    for ev in all_events:
        ts_str = ev.get("timestamp") or ""
        ev_dt = None
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"]:
            try:
                ev_dt = datetime.strptime(ts_str, fmt)
                break
            except ValueError:
                pass
        if not ev_dt:
            try:
                ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                continue

        diff_seconds = abs((ev_dt - target_dt).total_seconds())
        ev_copy = dict(ev)
        ev_copy["diff_seconds"] = int(diff_seconds)
        if diff_seconds < 60:
            ev_copy["diff_human"] = f"{int(diff_seconds)} seconds"
        elif diff_seconds < 3600:
            ev_copy["diff_human"] = f"{round(diff_seconds/60, 1)} minutes"
        elif diff_seconds < 86400:
            ev_copy["diff_human"] = f"{round(diff_seconds/3600, 1)} hours"
        else:
            ev_copy["diff_human"] = f"{round(diff_seconds/86400, 1)} days"

        all_scored_events.append((ev_copy, ev_dt))

        if start_window <= ev_dt <= end_window:
            matching_events.append(ev_copy)

    # If narrow window produces no direct matches, fallback to closest available location evidence for the date if within reasonable delta (e.g. 30 days)
    if not matching_events and all_scored_events:
        max_fallback_seconds = max(86400 * 30, window_delta.total_seconds() * 24)
        valid_fallbacks = [item[0] for item in all_scored_events if item[0]["diff_seconds"] <= max_fallback_seconds]
        if valid_fallbacks:
            def fallback_rank(item):
                secs = item["diff_seconds"]
                conf = {"HIGH": 300, "MEDIUM": 200, "LOW": 100}.get(item.get("confidence", "").upper(), 50)
                return (secs, -conf)

            valid_fallbacks.sort(key=fallback_rank)
            matching_events = valid_fallbacks[:10]

    # Proximity & Reliability Ranking
    def rank_score(item):
        conf_score = {"HIGH": 300, "MEDIUM": 200, "LOW": 100}.get(item.get("confidence", "").upper(), 50)
        proximity_score = max(0, 1000 - item.get("diff_seconds", 0))
        return conf_score + proximity_score

    matching_events.sort(key=rank_score, reverse=True)
    best_location = matching_events[0] if matching_events else None

    # Detect conflicts
    conflict_detected = False
    conflict_details = []
    if len(matching_events) >= 2:
        top_gps = next((e for e in matching_events if e.get("confidence") == "HIGH" and e.get("latitude")), None)
        top_net = next((e for e in matching_events if e.get("confidence") in ["MEDIUM", "LOW"] and e.get("latitude")), None)
        if top_gps and top_net:
            dist = math.sqrt((top_gps.get("latitude", 0) - top_net.get("latitude", 0))**2 + (top_gps.get("longitude", 0) - top_net.get("longitude", 0))**2)
            if dist > 0.05:
                conflict_detected = True
                conflict_details = [
                    {"type": top_gps.get("evidence_type"), "location": top_gps.get("location_name"), "time": top_gps.get("timestamp")},
                    {"type": top_net.get("evidence_type"), "location": top_net.get("location_name"), "time": top_net.get("timestamp")}
                ]

    return {
        "requested_time": target_datetime_str,
        "search_window": f"±{range_mins} minutes ({start_window.strftime('%H:%M:%S')} → {end_window.strftime('%H:%M:%S')})",
        "device_filter": device_filter,
        "best_available_location": best_location,
        "supporting_events": matching_events,
        "total_results": len(matching_events),
        "conflict_detected": conflict_detected,
        "conflict_details": conflict_details
    }


def search_location_date_range(
    start_time: str,
    end_time: str,
    device_filter: str = "All Devices",
    source_filter: str = "All Sources",
    confidence_filter: str = "All",
    demo_mode: bool = False,
    location_events: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """Search location history chronologically between start_time and end_time."""
    overview = get_location_overview_intelligence(demo_mode=demo_mode, raw_artifacts=location_events if isinstance(location_events, list) else None)
    all_events = overview.get("location_events") or []

    filtered = []
    for ev in all_events:
        ts = ev.get("timestamp") or ""
        if start_time and ts < start_time:
            continue
        if end_time and ts > end_time:
            continue
        if device_filter and device_filter.lower() != "all devices" and device_filter.lower() not in (ev.get("device") or "").lower():
            continue
        if source_filter and source_filter.lower() != "all sources" and source_filter.lower() not in (ev.get("source") or "").lower():
            continue
        if confidence_filter and confidence_filter.lower() != "all" and confidence_filter.upper() != ev.get("confidence", "").upper():
            continue
        filtered.append(ev)

    filtered.sort(key=lambda x: str(x.get("timestamp", "")))
    return filtered


def generate_location_forensic_report(demo_mode: bool = False) -> Dict[str, Any]:
    """Compile comprehensive exportable location forensic report JSON."""
    overview = get_location_overview_intelligence(demo_mode=demo_mode)
    search_res = search_location_by_time("2026-09-15", "18:45:00", 5, "Samsung Galaxy S24", demo_mode=demo_mode)

    return {
        "report_title": "LOCATION INTELLIGENCE FORENSIC REPORT",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_info": {
            "case_id": "CASE-LOC-2026-8801",
            "investigator": "JOCKY Digital Forensics Unit",
            "timezone": "IST (UTC+05:30)"
        },
        "executive_summary": {
            "status": overview.get("status"),
            "known_locations": overview.get("known_locations"),
            "total_location_events": overview.get("location_events_count"),
            "gps_artifacts": overview.get("gps_artifacts_count"),
            "network_location_events": overview.get("network_location_events_count"),
            "devices_with_location_data": overview.get("devices_with_location_count"),
            "date_range": overview.get("date_range")
        },
        "sample_time_query": {
            "requested_timestamp": search_res.get("requested_time"),
            "search_window": search_res.get("search_window"),
            "best_available_location": search_res.get("best_available_location")
        },
        "all_location_events": overview.get("location_events"),
        "devices": overview.get("devices"),
        "confidence_disclaimer": "Location determinations strictly reflect recoverable evidence timestamps, source types, and calculated confidence ratings. IP geolocations are explicitly demarcated as approximate."
    }


class LocationSearchEngine:
    @staticmethod
    def search(date_str: str = "2026-09-15", time_str: str = "18:45:00", range_mins: int = 5, device_filter: str = "All Devices", demo_mode: bool = False):
        return search_location_by_time(date_str, time_str, range_mins, device_filter, demo_mode)


class LocationCorrelationEngine:
    @staticmethod
    def correlate(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return events


class LocationReportGenerator:
    @staticmethod
    def generate(demo_mode: bool = False):
        return generate_location_forensic_report(demo_mode=demo_mode)


# Modular Service Classes matching Requirement 23
LocationCollectorService = LocationCollector
GPSArtifactParserService = GPSArtifactParser
WifiLocationAnalyzerService = WifiLocationAnalyzer
NetworkLocationAnalyzerService = NetworkLocationAnalyzer
EXIFLocationAnalyzerService = EXIFLocationAnalyzer
LocationTimelineAnalyzerService = LocationTimelineAnalyzer
LocationSearchEngineService = LocationSearchEngine
LocationCorrelationEngineService = LocationCorrelationEngine
LocationConfidenceEngineService = LocationConfidenceEngine
LocationReportGeneratorService = LocationReportGenerator
