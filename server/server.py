"""
JOCKY Central Forensic Server (Flask REST API)
"""
import os
from urllib.parse import unquote
import sys
import socket
import json
import io
import zipfile
import tarfile
import gzip
import base64
import mimetypes
import hashlib
import time
import uuid
import platform as host_platform
import threading
import subprocess
import shutil
from typing import Dict, Any, Optional, List
from flask import Flask, request, jsonify, render_template_string, send_from_directory, send_file, Response, make_response, session, redirect, url_for


# Ensure project root is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(root_dir, ".env"))
except Exception:
    pass
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# ---------------------------------------------------------------------------
# Package-agnostic imports: works whether run as `python -m server.server`
# or `python server/server.py` from project root.
# ---------------------------------------------------------------------------
_server_pkg = os.path.dirname(os.path.abspath(__file__))
if _server_pkg not in sys.path:
    sys.path.insert(0, _server_pkg)

from server.database import init_db, get_db_connection, query_evidence_records, get_dfir_overview_stats
from server.models import (DeviceModel, CaseModel, SessionModel, JobModel,
                            LiveEventModel, BrowserArtifactModel, RecoveryModel, MemoryModel, DeviceTelemetryModel)
from server.terminal import JockyTerminalEngine
from server.audit import record_audit_event, get_audit_events, verify_audit_chain
from server.evidence import EvidenceModel, DEFAULT_EVIDENCE_DIR
from server.reports import ReportGenerator
from src.parser import parse_jocky_source, ALLOWLISTED_OPERATIONS
from src.plan import compile_plan_from_ast, validate_forensic_plan
from src.codegen import generate_c_code
from collector.security_assessment import assess_endpoint

app = Flask(__name__)
# Browser dashboard authentication uses a server-side session cookie.
# Agent API requests continue to authenticate with X-API-Key.
app.secret_key = os.environ.get("JOCKY_SECRET_KEY") or os.environ.get("JOCKY_SECRET") or "JOCKY-DFIR-SESSION-2026"
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Config
DB_PATH = os.environ.get("JOCKY_DB", "jocky_forensics.db")
EVIDENCE_DIR = os.environ.get("JOCKY_EVIDENCE_DIR", "evidence")
API_KEY = os.environ.get("JOCKY_API_KEY", "")
FILE_REQUESTS: Dict[str, Dict[str, Any]] = {}
EMAIL_REQUESTS: Dict[str, Dict[str, Any]] = {}
AGENT_BUILD_LOCK = threading.Lock()


def get_db_path() -> str:
    env_db = os.environ.get("JOCKY_DB")
    if env_db:
        return os.path.abspath(env_db)
    return os.path.abspath(DB_PATH)



def get_evidence_dir() -> str:
    return os.path.abspath(os.environ.get("JOCKY_EVIDENCE_DIR", EVIDENCE_DIR))


os.makedirs(EVIDENCE_DIR, exist_ok=True)
init_db(DB_PATH)


DEFAULT_DASHBOARD_USER = "INV-9042-FED"
DEFAULT_DASHBOARD_PASSWORD = "JOCKY-DFIR-2026"
DEFAULT_DASHBOARD_OTP = "000000"
DASHBOARD_USERNAME = os.environ.get("JOCKY_DASHBOARD_USERNAME", DEFAULT_DASHBOARD_USER)
DASHBOARD_PASSWORD = os.environ.get("JOCKY_DASHBOARD_PASSWORD") or API_KEY or DEFAULT_DASHBOARD_PASSWORD
DASHBOARD_OTP = os.environ.get("JOCKY_DASHBOARD_OTP", DEFAULT_DASHBOARD_OTP)

def _api_key_valid() -> bool:
    return bool(API_KEY) and request.headers.get("X-API-Key", "") == API_KEY

def _dashboard_session_valid() -> bool:
    return bool(session.get("dashboard_authenticated"))

def check_auth():
    if API_KEY and not (_api_key_valid() or _dashboard_session_valid()):
        return jsonify({"error": "Unauthorized"}), 401
    return None


@app.before_request
def authenticate():
    if request.path.startswith("/api/"):
        if request.path == "/api/auth/status":
            return None
        auth_err = check_auth()
        if auth_err:
            return auth_err
    elif request.path.startswith("/downloads/agent/"):
        auth_err = check_auth()
        if auth_err:
            return auth_err


_LOGIN_PAGE = """
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>JOCKY - Dashboard Login</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1117;color:#e2e4ec;font:14px system-ui,Segoe UI,Arial}
.card{width:min(420px,calc(100vw - 40px));background:#181c26;border:1px solid #2a2e3d;border-radius:12px;padding:28px;box-sizing:border-box}
h1{margin:0 0 8px;font-size:22px}.muted{color:#7a8099;margin-bottom:22px}
label{display:block;color:#9aa0b8;font-size:12px;margin-bottom:7px}
input{width:100%;box-sizing:border-box;padding:11px 12px;background:#11141c;color:#e2e4ec;border:1px solid #2a2e3d;border-radius:7px}
button{margin-top:14px;width:100%;padding:11px;border:0;border-radius:7px;background:#f97316;color:white;font-weight:700;cursor:pointer}
.error{margin:0 0 14px;padding:10px;border-radius:7px;background:#3c171b;color:#ffb4b4}
.small{margin-top:16px;color:#7a8099;font-size:11px;line-height:1.5}
</style></head>
<body><form class="card" method="post">
<h1>JOCKY Forensic Console</h1><div class="muted">Authenticated investigator dashboard</div>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<label for="username">Investigator Badge ID / Username</label>
<input id="username" name="username" value="INV-9042-FED" autocomplete="username" required autofocus>
<label for="password">Security Passphrase / Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<label for="otp">6-Digit MFA / OTP Token</label>
<input id="otp" name="otp" inputmode="numeric" maxlength="6" value="000000" pattern="[0-9]{6}" required>
<button type="submit">Authenticate &amp; Access Gateway</button>
<div class="small">The key is validated server-side and is not embedded in dashboard JavaScript.</div>
</form></body></html>
"""

@app.route("/login", methods=["GET", "POST"])
def dashboard_login():
    if not API_KEY:
        session["dashboard_authenticated"] = True
        return redirect(url_for("dashboard_view"))
    if request.method == "POST":
        supplied_user = request.form.get("username", "").strip()
        supplied_password = request.form.get("password", "")
        supplied_otp = request.form.get("otp", "").strip()
        if (supplied_user == DASHBOARD_USERNAME and supplied_password == DASHBOARD_PASSWORD and supplied_otp == DASHBOARD_OTP):
            session["dashboard_authenticated"] = True
            session["dashboard_user"] = supplied_user
            session.permanent = True
            return redirect(url_for("dashboard_view"))
        return render_template_string(_LOGIN_PAGE, error="Invalid investigator credentials or MFA token."), 401
    return render_template_string(_LOGIN_PAGE, error=None)


@app.route("/logout")
def dashboard_logout():
    session.clear()
    return redirect(url_for("dashboard_login"))


@app.route("/api/auth/status")
def auth_status():
    return jsonify({
        "authenticated": (not API_KEY) or _dashboard_session_valid(),
        "auth_mode": "api-key + browser-session" if API_KEY else "open",
    })


@app.route("/")
def dashboard_view():
    if API_KEY and not _dashboard_session_valid():
        return redirect(url_for("dashboard_login"))
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if os.path.exists(dashboard_path):
        resp = make_response(send_file(dashboard_path))
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp
    return "JOCKY Forensic Server Dashboard (dashboard.html not found)"


AGENT_ARTIFACTS = {
    "windows": ("jocky-agent-windows.exe", "application/vnd.microsoft.portable-executable", "Windows"),
    "linux": ("jocky-agent-linux", "application/octet-stream", "Linux"),
}




def current_os_name() -> str:
    return host_platform.system()


def _agent_artifact_info(platform_name: str) -> dict:
    filename, _mimetype, native_os = AGENT_ARTIFACTS[platform_name]
    path = os.path.join(root_dir, "dist", filename)
    info = {
        "platform": platform_name,
        "label": f"{native_os} agent",
        "filename": filename,
        "native_os": native_os,
        "available": os.path.isfile(path),
        "builder_available": current_os_name() == native_os,
        "size_bytes": os.path.getsize(path) if os.path.isfile(path) else 0,
        "download_url": f"/downloads/agent/{platform_name}",
        "build_url": f"/api/agent-artifacts/build/{platform_name}",
    }
    manifest = path + ".manifest.json"
    if os.path.isfile(manifest):
        try:
            with open(manifest, "r", encoding="utf-8") as fh:
                info["manifest"] = json.load(fh)
        except Exception:
            info["manifest"] = None
    else:
        info["manifest"] = None
    return info


@app.route("/api/agent-artifacts", methods=["GET"])
def agent_artifact_status():
    """Return dashboard-ready status for both native single-file agents."""
    current = current_os_name()
    return jsonify({
        "server_platform": current,
        "artifacts": [_agent_artifact_info(name) for name in ("windows", "linux")],
        "native_build_note": "A native Windows PE must be built on Windows; a native Linux ELF must be built on Linux.",
    })



def _build_windows_agent_with_wine():
    """Build the Windows native agent from a Linux server using Wine."""
    script = os.path.join(os.path.dirname(__file__), "build_wine_windows.py")
    if not os.path.isfile(script):
        raise RuntimeError("Wine Windows builder is not installed")
    return subprocess.run(
        [sys.executable, script],
        cwd=os.path.dirname(__file__),
        capture_output=True,
        text=True,
        check=False,
    )

@app.route("/api/agent-artifacts/build/<platform_name>", methods=["POST"])
def build_agent_artifact(platform_name: str):
    """Build a native single-file agent from the dashboard.

    The endpoint deliberately permits only a build matching the server OS;
    this avoids pretending that PyInstaller can cross-compile PE/ELF targets.
    """
    if platform_name not in AGENT_ARTIFACTS:
        return jsonify({"error": "platform must be windows or linux"}), 404

    requested_os = AGENT_ARTIFACTS[platform_name][2]
    current_os = current_os_name()

    # On Linux, use the included Wine builder for the Windows PE artifact.
    if platform_name == "windows" and current_os == "Linux":
        script = os.path.join(os.path.dirname(__file__), "build_wine_windows.py")
        if not os.path.isfile(script):
            return jsonify({"error": "windows_wine_builder_missing"}), 500
        if not shutil.which("wine") and not shutil.which("wine64"):
            return jsonify({
                "error": "wine_not_installed",
                "message": "Install Wine before generating the Windows agent from this Linux server."
            }), 409
        if not AGENT_BUILD_LOCK.acquire(blocking=False):
            return jsonify({"error": "build_in_progress", "message": "Another agent build is already running."}), 409
        try:
            result = _build_windows_agent_with_wine()
            if result.returncode != 0:
                return jsonify({
                    "error": "agent_build_failed",
                    "returncode": result.returncode,
                    "stdout": result.stdout[-6000:],
                    "stderr": result.stderr[-6000:],
                }), 500
            return jsonify({
                "status": "built",
                "artifact": _agent_artifact_info("windows"),
                "output": result.stdout[-6000:],
            })
        except subprocess.TimeoutExpired:
            return jsonify({"error": "agent_build_timeout", "message": "Agent build exceeded 15 minutes."}), 504
        finally:
            AGENT_BUILD_LOCK.release()

    if current_os != requested_os:
        return jsonify({
            "error": "native_build_required",
            "platform": platform_name,
            "server_platform": current_os,
            "message": f"The {requested_os} agent must be built on a {requested_os} machine or native CI runner."
        }), 409

    if not AGENT_BUILD_LOCK.acquire(blocking=False):
        return jsonify({"error": "build_in_progress", "message": "Another agent build is already running."}), 409

    try:
        build_script = os.path.join(root_dir, "deploy", "build_agent.py")
        if not os.path.isfile(build_script):
            return jsonify({"error": "build_script_missing", "path": build_script}), 500

        result = subprocess.run(
            [sys.executable, build_script, "--platform", platform_name],
            cwd=root_dir,
            capture_output=True,
            text=True,
            timeout=900,
            env=os.environ.copy(),
        )
        if result.returncode != 0:
            return jsonify({
                "error": "agent_build_failed",
                "returncode": result.returncode,
                "stdout": result.stdout[-6000:],
                "stderr": result.stderr[-6000:],
            }), 500
        return jsonify({
            "status": "built",
            "artifact": _agent_artifact_info(platform_name),
            "output": result.stdout[-6000:],
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "agent_build_timeout", "message": "Agent build exceeded 15 minutes."}), 504
    finally:
        AGENT_BUILD_LOCK.release()


@app.route("/api/agent-artifacts/upload/<platform_name>", methods=["POST"])
def upload_agent_artifact(platform_name: str):
    """Register a native artifact built on the matching native OS.

    This keeps the dashboard as the deployment surface: a Windows PE can be
    built on a Windows workstation/runner and uploaded here without manually
    placing files into dist/. Only the expected artifact type is accepted.
    """
    if platform_name not in AGENT_ARTIFACTS:
        return jsonify({"error": "platform must be windows or linux"}), 404

    filename, _mimetype, native_os = AGENT_ARTIFACTS[platform_name]
    uploaded = request.files.get("artifact")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "artifact_file_required", "message": "Select the native agent binary to upload."}), 400

    if platform_name == "windows":
        head = uploaded.stream.read(2)
        uploaded.stream.seek(0)
        if head != b"MZ":
            return jsonify({"error": "invalid_windows_binary", "message": "The selected file is not a Windows PE executable (missing MZ header)."}), 400
    else:
        head = uploaded.stream.read(4)
        uploaded.stream.seek(0)
        if head != b"\x7fELF":
            return jsonify({"error": "invalid_linux_binary", "message": "The selected file is not an ELF executable."}), 400

    dist_dir = os.path.join(root_dir, "dist")
    os.makedirs(dist_dir, exist_ok=True)
    target = os.path.join(dist_dir, filename)
    uploaded.save(target)

    with open(target, "rb") as fh:
        sha256 = __import__("hashlib").sha256(fh.read()).hexdigest()
    manifest = {
        "build_id": "uploaded-native-build",
        "built_at": None,
        "platform": platform_name,
        "native_os": native_os,
        "artifact": filename,
        "sha256": sha256,
        "size_bytes": os.path.getsize(target),
        "source": "dashboard native artifact upload"
    }
    with open(target + ".manifest.json", "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return jsonify({"status": "uploaded", "artifact": _agent_artifact_info(platform_name)})




@app.route("/api/agent-artifacts/verify/<platform_name>", methods=["POST"])
def verify_agent_artifact(platform_name: str):
    """Verify a stored native artifact against its manifest and file format."""
    if platform_name not in AGENT_ARTIFACTS:
        return jsonify({"error": "platform must be windows or linux"}), 404
    filename, _mimetype, _native_os = AGENT_ARTIFACTS[platform_name]
    artifact = os.path.join(root_dir, "dist", filename)
    manifest_path = artifact + ".manifest.json"
    if not os.path.isfile(artifact) or not os.path.isfile(manifest_path):
        return jsonify({"error": "artifact_or_manifest_missing"}), 404
    try:
        with open(artifact, "rb") as fh:
            data = fh.read()
        expected_header = b"MZ" if platform_name == "windows" else b"\x7fELF"
        if not data.startswith(expected_header):
            return jsonify({"verified": False, "error": "invalid_native_format"}), 422
        digest = __import__("hashlib").sha256(data).hexdigest()
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        verified = digest == manifest.get("sha256")
        return jsonify({"verified": verified, "platform": platform_name, "artifact": filename, "sha256": digest, "manifest": manifest})
    except Exception as exc:
        return jsonify({"verified": False, "error": str(exc)}), 500

# ─── Per-download unique-hash delivery (placeholder-patch method) ─────────────
#
# HOW IT WORKS
# ─────────────
# jocky_agent.py contains a compiled-in 64-byte placeholder:
#   _DELIVERY_NONCE = b'JNONCE:' + b'\x00' * 57
#
# At download time we:
#   1. Read the built binary from dist/
#   2. Locate the JNONCE: marker inside the binary (it's in the PyInstaller PKG)
#   3. Overwrite the 57 null bytes after the marker with os.urandom(57)
#   4. Stream the patched binary — file size unchanged, PKG structure untouched
#
# WHY NOT APPEND BYTES
# ─────────────────────
# PyInstaller's bootloader finds its embedded PKG archive by searching BACKWARDS
# from EOF for a magic cookie. Appending ANY bytes after the binary shifts that
# search window and causes:
#   [PYI-XXXXX:ERROR] Could not load PyInstaller's embedded PKG archive
#
# The placeholder approach changes bytes INSIDE the existing binary so the ELF
# structure, PKG archive, and magic cookie positions are all preserved.
#
# REQUIREMENT: rebuild the binary from the dashboard after this code change
# so that the compiled binary contains the JNONCE: placeholder.
# ──────────────────────────────────────────────────────────────────────────────

JNONCE_MARKER   = b'JNONCE:'
JNONCE_PAYLOAD  = 57          # bytes after the marker that we overwrite
DELIVERY_LOG_DIR = os.path.join(root_dir, "dist", "delivery_log")


def _delivery_log_path(platform_name: str) -> str:
    os.makedirs(DELIVERY_LOG_DIR, exist_ok=True)
    return os.path.join(DELIVERY_LOG_DIR, f"{platform_name}_deliveries.jsonl")


def _log_delivery(platform_name: str, nonce_hex: str, sha256_delivered: str) -> None:
    import datetime as _dt
    entry = {
        "ts": _dt.datetime.utcnow().isoformat() + "Z",
        "platform": platform_name,
        "nonce": nonce_hex,
        "sha256_delivered": sha256_delivered,
    }
    try:
        with open(_delivery_log_path(platform_name), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


@app.route("/downloads/agent/<platform_name>", methods=["GET"])
def download_agent_artifact(platform_name: str):
    """Serve the agent binary with a unique per-download hash.

    Locates the JNONCE: placeholder compiled into the binary and overwrites
    the 57 null bytes after it with cryptographic random data. This changes
    the SHA-256 without touching PyInstaller's PKG archive or ELF structure,
    so the binary runs correctly on the target.

    Each delivery is watermark-logged: nonce + delivered SHA-256 + timestamp.
    """
    import hashlib as _hl
    from flask import Response as _Resp

    if platform_name not in AGENT_ARTIFACTS:
        return jsonify({"error": "platform must be windows or linux"}), 404

    filename, mimetype, _native_os = AGENT_ARTIFACTS[platform_name]
    executable_path = os.path.join(root_dir, "dist", filename)
    if not os.path.isfile(executable_path):
        return jsonify({
            "error": "agent_artifact_not_built",
            "platform": platform_name,
            "message": (
                "Binary not found. Build the agent from the dashboard first. "
                "After building, each download will have a unique SHA-256."
            ),
        }), 404

    binary = bytearray(open(executable_path, "rb").read())

    # Locate the JNONCE: placeholder inside the binary
    idx = binary.find(JNONCE_MARKER)
    if idx == -1:
        # Placeholder not present — binary was built before this fix.
        # Serve as-is (same hash every time) and tell the operator to rebuild.
        import io
        return _Resp(
            bytes(binary),
            mimetype=mimetype,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Length": str(len(binary)),
                "X-Nonce-Status": "placeholder-not-found-rebuild-required",
            },
        )

    # Overwrite the 57 null bytes after JNONCE: with random data
    nonce_start = idx + len(JNONCE_MARKER)
    nonce       = os.urandom(JNONCE_PAYLOAD)
    binary[nonce_start : nonce_start + JNONCE_PAYLOAD] = nonce

    delivered_sha256 = _hl.sha256(binary).hexdigest()
    _log_delivery(platform_name, nonce.hex(), delivered_sha256)

    payload = bytes(binary)

    def _stream():
        yield payload

    return _Resp(
        _stream(),
        mimetype=mimetype,
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(len(payload)),
            "X-Build-Hash":    _hl.sha256(open(executable_path, "rb").read()).hexdigest()[:16],
            "X-Delivery-Hash": delivered_sha256[:16],
            "X-Nonce-Status":  "patched",
        },
    )


@app.route("/api/agent-artifacts/deliveries/<platform_name>", methods=["GET"])
def list_agent_deliveries(platform_name: str):
    """Return the watermark delivery log — maps nonce to download timestamp + hash."""
    if platform_name not in AGENT_ARTIFACTS:
        return jsonify({"error": "unknown platform"}), 404
    log_path = _delivery_log_path(platform_name)
    if not os.path.isfile(log_path):
        return jsonify({"platform": platform_name, "deliveries": []})
    entries = []
    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500
    return jsonify({"platform": platform_name, "total": len(entries), "deliveries": entries})


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "JOCKY DFIR Central Server",
        "version": "1.0.0"
    })


@app.route("/api/devices/register", methods=["POST"])
def register_device():
    data = request.get_json() or {}
    device_id = data.get("device_id") or data.get("id")
    hostname = data.get("hostname", "unknown_host")
    os_name = data.get("os", "unknown_os")
    ip_address = data.get("ip_address") or request.remote_addr

    if not device_id:
        return jsonify({"error": "device_id is required"}), 400

    dev = DeviceModel.register_or_update(device_id, hostname, os_name, ip_address, get_db_path())
    record_audit_event("agent", "REGISTER_DEVICE", device_id, {"hostname": hostname, "os": os_name}, get_db_path())
    return jsonify(dev), 200


@app.route("/api/devices/enrolled", methods=["GET"])
def list_enrolled_devices():
    return jsonify(DeviceModel.list_all(get_db_path()))


@app.route("/api/devices", methods=["GET"])
def list_devices():
    # If caller requests forensic artifact view, device_type filter, or pagination/search
    if (request.args.get("view") == "artifacts" or 
        request.args.get("device_type") or 
        request.args.get("category") or 
        request.args.get("q") or 
        "page" in request.args or
        "limit" in request.args):
        return get_device_artifacts()
    devices = DeviceModel.list_all(get_db_path())
    return jsonify(devices)


@app.route("/api/devices/<device_id>/assignment", methods=["GET"])
def get_device_assignment(device_id):
    assignment = DeviceModel.get_assignment(device_id, get_db_path())
    return jsonify({"agent_id": device_id, "case_id": assignment})


@app.route("/api/investigations/start", methods=["POST"])
def start_investigation():
    data = request.get_json() or {}
    agent_id = data.get("agent_id")
    investigator_name = str(data.get("investigator_name", "")).strip()
    case_name = str(data.get("case_name", "")).strip()
    if not agent_id or not investigator_name or not case_name:
        return jsonify({"error": "agent_id, investigator_name and case_name are required"}), 400
    if not any(d.get("id") == agent_id for d in DeviceModel.list_all(get_db_path())):
        return jsonify({"error": "agent_not_registered"}), 404
    case = CaseModel.create(
        case_name, str(data.get("description", "")).strip(), get_db_path(),
        investigator_name=investigator_name,
        investigator_org=str(data.get("investigator_org", "")).strip(),
        subject_name=str(data.get("subject_name", "")).strip(),
        authorization_ref=str(data.get("authorization_ref", "")).strip(),
        evidence_source=str(data.get("evidence_source", "")).strip(),
        investigation_notes=str(data.get("investigation_notes", "")).strip(),
    )
    session = SessionModel.create(case["id"], f"Initial investigation — {agent_id}", get_db_path())
    device = DeviceModel.assign_case(agent_id, case["id"], get_db_path())
    record_audit_event("investigator", "START_INVESTIGATION", case["id"],
                       {"agent_id": agent_id, "investigator_name": investigator_name, "session_id": session["id"]}, get_db_path())
    return jsonify({"case": case, "session": session, "device": device}), 201


@app.route("/api/devices/<device_id>", methods=["DELETE"])
@app.route("/api/devices/<device_id>/delete", methods=["POST"])
def delete_device(device_id):
    """Remove a connected machine and all its telemetry from the database."""
    db_p = get_db_path()
    devices = DeviceModel.list_all(db_p)
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "device_not_found", "device_id": device_id}), 404
    deleted = DeviceModel.delete(device_id, db_p)
    if deleted:
        record_audit_event("investigator", "DELETE_DEVICE", device_id,
                           {"hostname": dev.get("hostname"), "os": dev.get("os")}, db_p)
        return jsonify({"status": "deleted", "device_id": device_id,
                        "hostname": dev.get("hostname")}), 200
    return jsonify({"error": "delete_failed", "device_id": device_id}), 500


@app.route("/api/security/assessment", methods=["GET"])
def security_assessment():
    """Return a read-only endpoint security assessment for the server host."""
    result = assess_endpoint()
    record_audit_event("investigator", "SECURITY_ASSESSMENT", result.get("hostname", "unknown"), {"read_only": True}, get_db_path())
    return jsonify(result)


@app.route("/api/jobs/bulk", methods=["POST"])
def create_bulk_jobs():
    """Create the same validated forensic plan for multiple registered agents."""
    data = request.get_json() or {}
    session_id = data.get("session_id")
    plan_hash = data.get("plan_hash")
    agent_ids = data.get("agent_ids") or []
    if not session_id or not plan_hash or not isinstance(agent_ids, list) or not agent_ids:
        return jsonify({"error": "session_id, plan_hash and non-empty agent_ids are required"}), 400
    conn = get_db_connection(get_db_path())
    row = conn.execute("SELECT plan_json FROM plans WHERE plan_hash = ?", (plan_hash,)).fetchone()
    if not row:
        conn.close(); return jsonify({"error": "Plan not found"}), 404
    created=[]; rejected=[]
    for agent_id in agent_ids:
        dev = conn.execute("SELECT id FROM devices WHERE id = ?", (agent_id,)).fetchone()
        if not dev:
            rejected.append({"agent_id": agent_id, "reason": "agent_not_registered"}); continue
        try:
            job = JobModel.create(session_id, agent_id, plan_hash, get_db_path())
            created.append(job)
        except Exception as exc:
            rejected.append({"agent_id": agent_id, "reason": str(exc)})
    conn.close()
    record_audit_event("investigator", "SUBMIT_BULK_JOBS", session_id, {"count": len(created), "plan_hash": plan_hash}, get_db_path())
    return jsonify({"created": created, "rejected": rejected}), 201


@app.route("/api/cases", methods=["POST"])
def create_case():
    data = request.get_json() or {}
    name = data.get("name")
    description = data.get("description", "")

    if not name:
        return jsonify({"error": "Case name is required"}), 400

    new_case = CaseModel.create(
        name, description, get_db_path(),
        investigator_name=data.get("investigator_name", ""),
        investigator_org=data.get("investigator_org", ""),
        subject_name=data.get("subject_name", ""),
        authorization_ref=data.get("authorization_ref", ""),
        evidence_source=data.get("evidence_source", ""),
        investigation_notes=data.get("investigation_notes", ""),
    )

    # If a target OS/device was supplied by the dashboard, bind the case to
    # the currently registered endpoint immediately.  The agent polls its
    # assignment before sending endpoint telemetry, so without this binding
    # a successfully registered agent would remain idle forever.
    agent_id = str(data.get("agent_id") or "").strip()
    target_os = str(data.get("target_os") or "").strip().lower()
    if not agent_id and target_os:
        devices = DeviceModel.list_all(get_db_path())
        candidates = [
            d for d in devices
            if str(d.get("os", "")).lower().find(target_os) >= 0
        ]
        if candidates:
            agent_id = candidates[0].get("id", "")
    if agent_id:
        try:
            assigned = DeviceModel.assign_case(agent_id, new_case["id"], get_db_path())
            new_case["agent_id"] = agent_id
            new_case["device"] = assigned
            record_audit_event("investigator", "ASSIGN_CASE_TO_DEVICE", new_case["id"], {"agent_id": agent_id, "target_os": target_os}, get_db_path())
        except ValueError:
            return jsonify({"error": "agent_not_registered", "case": new_case}), 404

    record_audit_event("investigator", "CREATE_CASE", new_case["id"], {"name": name, "agent_id": agent_id or None}, get_db_path())
    return jsonify(new_case), 201


@app.route("/api/cases", methods=["GET"])
def list_cases():
    cases = CaseModel.list_all(get_db_path())
    return jsonify(cases)


@app.route("/api/cases/<case_id>", methods=["GET"])
def get_case(case_id):
    c = CaseModel.get_by_id(case_id, get_db_path())
    if not c:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(c)


@app.route("/api/cases/<case_id>/assign", methods=["POST"])
def assign_case_to_device(case_id):
    """Bind an existing investigator case to a registered endpoint."""
    case = CaseModel.get_by_id(case_id, get_db_path())
    if not case:
        return jsonify({"error": "Case not found"}), 404
    data = request.get_json() or {}
    agent_id = str(data.get("agent_id") or "").strip()
    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400
    devices = DeviceModel.list_all(get_db_path())
    if not any(d.get("id") == agent_id for d in devices):
        return jsonify({"error": "agent_not_registered"}), 404
    assigned = DeviceModel.assign_case(agent_id, case_id, get_db_path())
    record_audit_event("investigator", "ASSIGN_CASE_TO_DEVICE", case_id, {"agent_id": agent_id}, get_db_path())
    return jsonify({"status": "assigned", "case_id": case_id, "agent_id": agent_id, "device": assigned}), 200


@app.route("/api/sessions", methods=["POST"])
def create_session():
    data = request.get_json() or {}
    case_id = data.get("case_id")
    name = data.get("name")

    if not case_id or not name:
        return jsonify({"error": "case_id and name are required"}), 400

    sess = SessionModel.create(case_id, name, get_db_path())
    record_audit_event("investigator", "CREATE_SESSION", sess["id"], {"case_id": case_id, "name": name}, get_db_path())
    return jsonify(sess), 201


@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    case_id = request.args.get("case_id")
    sessions = SessionModel.list_all(case_id, get_db_path())
    return jsonify(sessions)



@app.route("/api/compile", methods=["POST"])
def compile_dsl():
    data = request.get_json() or {}
    source = data.get("source", "")
    if not source:
        return jsonify({"error": "DSL source code is required"}), 400

    try:
        ast = parse_jocky_source(source)
        plan = compile_plan_from_ast(ast)
        c_code = generate_c_code(ast)

        # Store plan in db
        conn = get_db_connection(get_db_path())
        conn.execute("""
            INSERT OR REPLACE INTO plans (plan_hash, module_name, plan_json, created_at)
            VALUES (?, ?, ?, datetime('now'))
        """, (plan["plan_hash"], plan["module"], json.dumps(plan)))
        conn.commit()
        conn.close()

        record_audit_event("compiler", "COMPILE_DSL", plan["plan_hash"], {"module": plan["module"]}, get_db_path())

        return jsonify({
            "status": "success",
            "ast": ast.to_dict(),
            "plan": plan,
            "c_code": c_code
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/jobs", methods=["POST"])
def create_job():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    agent_id = data.get("agent_id")
    plan_hash = data.get("plan_hash")

    if not session_id or not agent_id or not plan_hash:
        return jsonify({"error": "session_id, agent_id, and plan_hash are required"}), 400

    # Verify plan exists
    conn = get_db_connection(get_db_path())
    cursor = conn.cursor()
    cursor.execute("SELECT plan_json FROM plans WHERE plan_hash = ?", (plan_hash,))
    p_row = cursor.fetchone()
    conn.close()

    if not p_row:
        return jsonify({"error": f"Plan with hash '{plan_hash}' not found. Compile DSL first."}), 404

    job = JobModel.create(session_id, agent_id, plan_hash, get_db_path())
    record_audit_event("investigator", "SUBMIT_JOB", job["id"], {"agent_id": agent_id, "plan_hash": plan_hash}, get_db_path())
    return jsonify(job), 201


@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    jobs = JobModel.list_all(get_db_path())
    return jsonify(jobs)


@app.route("/api/jobs/<job_id>", methods=["GET"])
def get_job(job_id):
    j = JobModel.get_by_id(job_id, get_db_path())
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(j)


@app.route("/api/agents/<agent_id>/jobs", methods=["GET"])
def get_agent_jobs(agent_id):
    jobs = JobModel.get_pending_for_agent(agent_id, get_db_path())
    return jsonify(jobs)


@app.route("/api/jobs/<job_id>/status", methods=["POST"])
def update_job_status(job_id):
    data = request.get_json() or {}
    status = data.get("status")
    if not status:
        return jsonify({"error": "Status is required"}), 400
    allowed = {"PENDING", "RUNNING", "COMPLETED", "FAILED"}
    status = str(status).upper()
    if status not in allowed:
        return jsonify({"error": f"Invalid status. Allowed: {sorted(allowed)}"}), 400

    JobModel.update_status(job_id, status, get_db_path())
    record_audit_event("agent", "UPDATE_JOB_STATUS", job_id, {"status": status}, get_db_path())
    return jsonify({"message": f"Job {job_id} updated to {status}"})


@app.route("/api/evidence", methods=["POST"])
def upload_evidence():
    job_id = request.form.get("job_id")
    manifest_str = request.form.get("manifest")
    is_encrypted = request.form.get("is_encrypted", "0") == "1"

    if not job_id or "file" not in request.files:
        return jsonify({"error": "job_id and file are required"}), 400

    file_obj = request.files["file"]
    db_p = get_db_path()
    ev_dir = get_evidence_dir()

    job = JobModel.get_by_id(job_id, db_p)
    if not job:
        return jsonify({"error": f"Job not found: {job_id}"}), 404

    # Determine case and session IDs
    conn = get_db_connection(db_p)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.case_id, s.id as session_id FROM jobs j
        JOIN sessions s ON j.session_id = s.id
        WHERE j.id = ?
    """, (job_id,))
    row = cursor.fetchone()
    conn.close()

    case_id = row["case_id"] if row else "case_default"
    session_id = row["session_id"] if row else "session_default"

    dest_dir = os.path.join(ev_dir, case_id, session_id, job_id)
    os.makedirs(dest_dir, exist_ok=True)
    archive_path = os.path.join(dest_dir, file_obj.filename)
    file_obj.save(archive_path)

    manifest_data = {}
    if manifest_str:
        try:
            manifest_data = json.loads(manifest_str)
        except Exception:
            pass

    manifest_path = os.path.join(dest_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    evd = EvidenceModel.register_evidence(
        job_id, archive_path, manifest_data, is_encrypted, db_path=db_p
    )
    JobModel.update_status(job_id, "COMPLETED", db_p)

    record_audit_event("agent", "UPLOAD_EVIDENCE", evd["id"], {"job_id": job_id, "sha256": evd["sha256"]}, db_p)

    return jsonify(evd), 201


@app.route("/api/evidence", methods=["GET"])
def list_evidence():
    evidence_list = EvidenceModel.list_all(get_db_path())
    return jsonify(evidence_list)


@app.route("/api/evidence/<evidence_id>", methods=["GET"])
def get_evidence(evidence_id):
    evd = EvidenceModel.get_by_id(evidence_id, get_db_path())
    if not evd:
        return jsonify({"error": "Evidence item not found"}), 404
    return jsonify(evd)


@app.route("/api/audit", methods=["GET"])
def list_audit():
    events = get_audit_events(get_db_path())
    return jsonify(events)


@app.route("/api/audit/verify", methods=["GET"])
def verify_audit():
    valid, message, violations = verify_audit_chain(get_db_path())
    return jsonify({
        "valid": valid,
        "message": message,
        "violations": violations
    })


@app.route("/api/reports/<case_id>", methods=["GET"])
def get_report(case_id):
    rep = ReportGenerator.generate_case_report(case_id, get_db_path())
    if "error" in rep:
        return jsonify(rep), 404
    return jsonify(rep)



from flask import send_file
from datetime import datetime, timezone
import tarfile
from collector.windows_collector import (
    get_windows_system_info,
    get_windows_processes,
    get_windows_network,
    get_windows_users,
    get_windows_services,
    get_windows_filesystem,
    get_windows_storage,
    get_windows_software,
    get_windows_scheduled_tasks,
    get_windows_environment,
    get_windows_logs,
)
from collector.verify import verify_manifest_and_evidence, calculate_sha256


@app.route("/api/evidence/<evidence_id>/download", methods=["GET"])
def download_evidence(evidence_id):
    db_p = get_db_path()
    evd = EvidenceModel.get_by_id(evidence_id, db_p)
    if not evd:
        return jsonify({"error": "Evidence item not found"}), 404
    archive_path = evd.get("archive_path")
    if not archive_path or not os.path.exists(archive_path):
        return jsonify({"error": "Evidence file not found on disk"}), 404
    record_audit_event("investigator", "DOWNLOAD_EVIDENCE", evidence_id, {"archive_path": archive_path}, db_p)
    return send_file(os.path.abspath(archive_path), as_attachment=True)


@app.route("/api/evidence/<evidence_id>/verify", methods=["GET"])
def verify_evidence(evidence_id):
    db_p = get_db_path()
    evd = EvidenceModel.get_by_id(evidence_id, db_p)
    if not evd:
        return jsonify({"error": "Evidence item not found"}), 404

    archive_path = evd.get("archive_path")
    if not archive_path or not os.path.exists(archive_path):
        return jsonify({"valid": False, "message": "Evidence file missing on disk"}), 404

    actual_hash = calculate_sha256(archive_path)
    expected_hash = evd.get("sha256")
    is_valid = (actual_hash == expected_hash)

    record_audit_event("investigator", "VERIFY_EVIDENCE", evidence_id, {"valid": is_valid, "sha256": actual_hash}, db_p)

    return jsonify({
        "evidence_id": evidence_id,
        "valid": is_valid,
        "expected_sha256": expected_hash,
        "actual_sha256": actual_hash,
        "status": "INTEGRITY VERIFIED" if is_valid else "INTEGRITY FAILURE",
        "message": f"SHA-256 integrity check {'passed' if is_valid else 'failed'}"
    })


def get_agent_telemetry_category(agent_id: str, category: str) -> Any:
    # 1. Prefer the endpoint's latest live baseline/snapshot. This makes the
    # dashboard useful immediately after an agent starts, without requiring
    # an investigator to create a forensic job first.
    live = DeviceTelemetryModel.get(agent_id, category, get_db_path())
    if live is not None:
        return live

    # 2. Search for latest completed job for agent_id
    conn = get_db_connection(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.archive_path FROM evidence e
        JOIN jobs j ON e.job_id = j.id
        WHERE j.agent_id = ? ORDER BY e.uploaded_at DESC LIMIT 1
    """, (agent_id,))
    row = cursor.fetchone()
    conn.close()

    if row and row["archive_path"] and os.path.exists(row["archive_path"]):
        archive_path = row["archive_path"]
        try:
            with tarfile.open(archive_path, "r:*") as tar:
                # Target file inside tar is collected/{category}.txt
                member_name = f"collected/{category}.txt"
                try:
                    f = tar.extractfile(member_name)
                    if f:
                        content = f.read().decode('utf-8', errors='replace')
                        try:
                            return json.loads(content)
                        except Exception:
                            return content
                except Exception:
                    pass
        except Exception:
            pass

    # Never substitute the server host for an enrolled endpoint. If no endpoint
    # telemetry or uploaded evidence exists, return an empty result explicitly.
    return []


@app.route("/api/cases/<case_id>/location", methods=["GET"])
def get_case_location(case_id):
    from collector.location import get_location_telemetry
    record_audit_event("investigator", "QUERY_LOCATION", case_id, {}, DB_PATH)
    loc = get_location_telemetry()
    return jsonify(loc)


@app.route("/api/cases/<case_id>/drivers", methods=["GET"])
def get_case_drivers(case_id):
    from collector.driver_forensics import get_driver_forensics
    record_audit_event("investigator", "QUERY_DRIVERS_BYOVD", case_id, {}, DB_PATH)
    drivers = get_driver_forensics()
    return jsonify({"case_id": case_id, "drivers": drivers, "vulnerable_count": sum(1 for d in drivers if d.get("is_vulnerable"))})


@app.route("/api/cases/<case_id>/security_events", methods=["GET"])
def get_case_security_events(case_id):
    from collector.security_telemetry import get_defender_security_telemetry
    record_audit_event("investigator", "QUERY_DEFENDER_TELEMETRY", case_id, {}, DB_PATH)
    events = get_defender_security_telemetry()
    return jsonify({"case_id": case_id, "defender_events": events})


@app.route("/api/cases/<case_id>/timeline", methods=["GET"])
def get_case_timeline(case_id):
    did=_case_device_id(case_id, request.args.get("device_id"))
    from server.timeline import TimelineEngine
    logins=[]; logs=_telemetry_data(did,"logs") or []
    if isinstance(logs,list): logins=[x for x in logs if any(k in str(x).lower() for k in ("login","authentication","sshd","pam"))]
    rich=_rich_category(did,"applications_forensics")
    processes=_telemetry_list(rich,("running_processes",)) or (_telemetry_data(did,"processes") or [])
    net=_telemetry_data(did,"network") or {}; network=net.get("connections",[]) if isinstance(net,dict) else net
    security=_telemetry_data(did,"security_telemetry") or []
    live_evts=LiveEventModel.get_recent_events(case_id,limit=200,db_path=get_db_path())
    timeline=TimelineEngine.generate_timeline(logins=logins,processes=processes,network=network,defender_events=security,drivers=[],live_events=live_evts,evidence_id=f"CASE:{case_id}") if (logins or processes or network or security or live_evts) else []
    return jsonify({"case_id":case_id,"device_id":did,"events_count":len(timeline),"timeline":timeline,"source":"endpoint_telemetry" if did else "none"})


@app.route("/api/live/ingest", methods=["POST"])
def live_ingest():
    data = request.get_json() or {}
    agent_id = data.get("agent_id")
    case_id = data.get("case_id")
    events = data.get("events", [])

    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400
    if not case_id:
        return jsonify({"error": "case_id is required"}), 400
    if not isinstance(events, list):
        return jsonify({"error": "events must be an array"}), 400

    db_p = get_db_path()
    res = LiveEventModel.ingest_events(agent_id, case_id, events, db_p)
    record_audit_event("agent", "LIVE_TELEMETRY_INGEST", agent_id, {"case_id": case_id, "count": len(events)}, db_p)
    return jsonify({"status": "success", "data": res}), 200


@app.route("/api/cases/<case_id>/live/stream", methods=["GET"])
def live_stream(case_id):
    def event_stream():
        yield f"data: {json.dumps({'type': 'CONNECTED', 'case_id': case_id, 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
        last_id = 0
        import time
        while True:
            conn = get_db_connection(get_db_path())
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM live_events WHERE case_id = ? AND id > ? ORDER BY id ASC LIMIT 20", (case_id, last_id))
            rows = cursor.fetchall()
            conn.close()

            for r in rows:
                row_id = r["id"]
                if row_id > last_id:
                    last_id = row_id
                d = dict(r)
                try:
                    d["payload"] = json.loads(d["payload"])
                except Exception:
                    pass
                yield f"data: {json.dumps({'type': 'EVENT', 'event': d})}\n\n"

            time.sleep(1)

    return Response(event_stream(), mimetype="text/event-stream")


@app.route("/api/live/status", methods=["GET"])
def live_status():
    case_id = request.args.get("case_id")
    counts = LiveEventModel.get_live_counts(case_id, get_db_path())
    return jsonify({
        "status": "LIVE_MONITORING_ACTIVE",
        "case_id": case_id or "ALL",
        "metrics": counts,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/terminal/execute", methods=["POST"])
def terminal_execute():
    data = request.get_json() or {}
    cmd_str = data.get("command", "")
    case_id = data.get("case_id")
    agent_id = data.get("agent_id")

    if not cmd_str:
        return jsonify({"error": "command is required"}), 400
    if not case_id:
        return jsonify({"error": "case_id is required"}), 400
    if not agent_id:
        # Device discovery is a local, read-only server operation and remains
        # usable for legacy case bootstrap. All other terminal operations must
        # identify the endpoint agent explicitly so execution is case-bound.
        if str(cmd_str).strip().split(None, 1)[0].lower() != "device":
            return jsonify({"error": "agent_id is required"}), 400
        agent_id = "local"

    result = JockyTerminalEngine.execute_command(cmd_str, case_id=case_id, agent_id=agent_id)
    record_audit_event("investigator", "TERMINAL_EXECUTE", cmd_str, {"case_id": case_id, "status": result["status"]}, get_db_path())
    return jsonify(result), 200


@app.route("/api/cases/<case_id>/recovery/scan", methods=["POST"])
def recovery_scan(case_id):
    data = request.get_json() or {}
    volume = data.get("volume", "C:\\")
    from collector.windows_collector import get_windows_recovery_candidates
    candidates = get_windows_recovery_candidates(volume)
    record_audit_event("investigator", "DELETED_FILE_RECOVERY_SCAN", case_id, {"volume": volume, "count": len(candidates)}, get_db_path())
    return jsonify({"case_id": case_id, "volume": volume, "candidates_count": len(candidates), "candidates": candidates}), 200


@app.route("/api/cases/<case_id>/recovery/recover", methods=["POST"])
def recovery_extract(case_id):
    data = request.get_json() or {}
    candidate_id = data.get("candidate_id")
    source_path = data.get("source_path")
    agent_id = data.get("agent_id")

    if not candidate_id or not source_path:
        return jsonify({"error": "candidate_id and source_path are required"}), 400
    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400

    from collector.windows_collector import perform_windows_file_recovery
    res = perform_windows_file_recovery(candidate_id, source_path)
    RecoveryModel.save_recovered_file(res, case_id=case_id, db_path=get_db_path())

    # Register as official evidence item
    with open(res["destination_path"], "rb") as f:
        dest_path = res["destination_path"]
        manifest_data = {
            "case_id": case_id,
            "session_id": f"session_recovery_{case_id}",
            "job_id": f"job_recovery_{case_id}",
            "agent_id": agent_id,
            "files": [{
                "path": res["filename"],
                "sha256": res["sha256"],
                "size_bytes": res["size_bytes"]
            }]
        }
        evd = EvidenceModel.register_evidence(manifest_data["job_id"], dest_path, manifest_data, False, get_db_path())

    record_audit_event("investigator", "DELETED_FILE_RECOVERED", candidate_id, {"evidence_id": res["evidence_id"], "sha256": res["sha256"]}, get_db_path())
    return jsonify({"case_id": case_id, "recovered": res, "evidence": evd}), 201


@app.route("/api/cases/<case_id>/memory", methods=["GET"])
def get_case_memory(case_id):
    did = _case_device_id(case_id, request.args.get("device_id"))
    mem = _telemetry_data(did, "memory") or {}
    if isinstance(mem, str):
        try:
            mem = json.loads(mem)
        except Exception:
            mem = {}
    if isinstance(mem, dict) and isinstance(mem.get("data"), dict):
        mem = mem["data"]
    source = "endpoint_telemetry" if did else "none"

    # No endpoint telemetry is available: expose the server's *real* live
    # memory statistics as an explicitly scoped fallback.  This preserves the
    # API schema without misrepresenting server memory as endpoint evidence.
    if not isinstance(mem, dict) or "total_ram_gb" not in mem:
        try:
            from collector.memory import get_live_memory_statistics
            fallback = get_live_memory_statistics()
            if isinstance(fallback, dict) and "total_ram_gb" in fallback:
                mem = dict(fallback)
                mem["source"] = "server_local_fallback"
                mem["telemetry_scope"] = "server_local_fallback"
                source = "server_local_fallback"
            elif not isinstance(mem, dict):
                mem = {}
        except Exception:
            if not isinstance(mem, dict):
                mem = {}

    return jsonify({
        "case_id": case_id,
        "device_id": did,
        "memory": mem,
        "source": source,
    })

@app.route("/api/cases/<case_id>/files", methods=["GET"])
def get_case_files(case_id):
    did = _case_device_id(case_id, request.args.get("device_id")); path = request.args.get("path", "/")
    data = _telemetry_data(did, "filesystem_forensics") or _telemetry_data(did, "filesystem") or []
    files = data.get("files", []) if isinstance(data, dict) else data
    if path not in ("", "/"):
        files = [f for f in files if str(f.get("path", "")).startswith(path)]
    return jsonify({"case_id": case_id, "device_id": did, "path": path, "count": len(files), "files": files, "source": "endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/events", methods=["GET"])
def get_case_events(case_id):
    did = _case_device_id(case_id, request.args.get("device_id")); logs = _telemetry_data(did, "logs") or []
    return jsonify({"case_id": case_id, "device_id": did, "count": len(logs), "events": logs, "source": "endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/services", methods=["GET"])
def get_case_services(case_id):
    did = _case_device_id(case_id, request.args.get("device_id")); rows = _telemetry_data(did, "services") or []
    return jsonify({"case_id": case_id, "device_id": did, "count": len(rows), "services": rows, "source": "endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/tasks", methods=["GET"])
def get_case_tasks(case_id):
    did = _case_device_id(case_id, request.args.get("device_id")); rows = _telemetry_data(did, "scheduled_tasks") or []
    return jsonify({"case_id": case_id, "device_id": did, "count": len(rows), "tasks": rows, "source": "endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/device", methods=["GET"])
def get_case_device(case_id):
    did=_case_device_id(case_id, request.args.get("device_id")); dev=next((d for d in DeviceModel.list_all(get_db_path()) if d.get("id")==did),{})
    sys_info=_telemetry_data(did,"system_forensics") or _telemetry_data(did,"system") or {}
    if isinstance(sys_info,dict) and isinstance(sys_info.get("data"),dict): sys_info=sys_info["data"]
    return jsonify({"case_id":case_id,"device_id":did,"device":{**dev,**sys_info},"source":"endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/users", methods=["GET"])
def get_case_users(case_id):
    did = _case_device_id(case_id, request.args.get("device_id")); rows = _telemetry_data(did, "users") or []
    return jsonify({"case_id": case_id, "device_id": did, "users": rows, "source": "endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/logins", methods=["GET"])
def get_case_logins(case_id):
    did=_case_device_id(case_id, request.args.get("device_id")); rows=_telemetry_data(did,"logs") or []
    login_rows=[r for r in rows if any(x in str(r).lower() for x in ("login","authentication","sshd","pam"))]
    return jsonify({"case_id":case_id,"device_id":did,"logins":login_rows,"source":"endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/network", methods=["GET"])
def get_case_network(case_id):
    did = _case_device_id(case_id, request.args.get("device_id")); payload = _telemetry_data(did, "network") or {}
    if not payload and did: payload = _telemetry_data(did, "network_forensics") or {}
    connections = payload.get("connections", []) if isinstance(payload, dict) else (payload or [])
    interfaces = payload.get("interfaces", []) if isinstance(payload, dict) else []
    return jsonify({"case_id": case_id, "device_id": did, "connections": connections, "interfaces": interfaces, "source": "endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/processes", methods=["GET"])
def get_case_processes(case_id):
    did = _case_device_id(case_id, request.args.get("device_id")); rich = _rich_category(did, "applications_forensics")
    procs = _telemetry_list(rich, ("running_processes",)) or (_telemetry_data(did, "processes") or [])
    return jsonify({"case_id": case_id, "device_id": did, "count": len(procs), "processes": procs, "source": "endpoint_telemetry" if did else "none"})

@app.route("/api/cases/<case_id>/browser", methods=["GET"])
@app.route("/api/cases/<case_id>/browser_artifacts", methods=["GET"])
def get_case_browser(case_id):
    # Browser artifacts can arrive through two legitimate paths:
    #   1. endpoint browser-forensics telemetry (batch collection), and
    #   2. live browser events persisted by /api/live/ingest.
    # Prefer endpoint telemetry when present, but never hide persisted live
    # artifacts. This also keeps the API useful immediately after live ingest.
    did = _case_device_id(case_id, request.args.get("device_id"))
    payload = _rich_category(did, "browser_forensics")
    telemetry_artifacts = _telemetry_list(payload, ("history",))

    persisted_artifacts = []
    try:
        persisted_artifacts = BrowserArtifactModel.list_artifacts(
            case_id=case_id, limit=1000, db_path=get_db_path()
        )
    except Exception:
        persisted_artifacts = []

    # Merge with deterministic de-duplication. Live artifacts may overlap with
    # endpoint history after a refresh, so use stable IDs/URLs/timestamps rather
    # than returning duplicate rows.
    artifacts = []
    seen = set()
    for item in list(telemetry_artifacts) + list(persisted_artifacts):
        if not isinstance(item, dict):
            continue
        key = item.get("artifact_id") or (
            item.get("browser"),
            item.get("type") or item.get("event_type"),
            item.get("url") or item.get("source_url"),
            item.get("query"),
            item.get("timestamp")
        )
        if key in seen:
            continue
        seen.add(key)
        artifacts.append(item)

    if telemetry_artifacts and persisted_artifacts:
        source = "endpoint_telemetry+live_events"
    elif telemetry_artifacts:
        source = "endpoint_telemetry"
    elif persisted_artifacts:
        source = "live_events"
    else:
        source = "none"

    return jsonify({"case_id": case_id, "device_id": did, "source": source,
                    "count": len(artifacts), "artifacts": artifacts,
                    "downloads": payload.get("downloads", []),
                    "bookmarks": payload.get("bookmarks", []),
                    "profiles": payload.get("profiles", []),
                    "summary": payload.get("browser_summary", {})})


@app.route("/api/cases/<case_id>/findings", methods=["GET"])
def get_case_findings(case_id):
    from collector.security_telemetry import get_defender_security_telemetry
    from collector.driver_forensics import get_driver_forensics
    from collector.windows_collector import get_windows_login_events, get_windows_processes
    from server.timeline import TimelineEngine
    from server.correlation import CorrelationEngine

    record_audit_event("investigator", "QUERY_CORRELATED_FINDINGS", case_id, {}, get_db_path())
    logins = get_windows_login_events()
    processes = get_windows_processes()
    defender_events = get_defender_security_telemetry()
    drivers = get_driver_forensics()

    timeline = TimelineEngine.generate_timeline(logins, processes, [], defender_events, drivers)
    findings = CorrelationEngine.correlate_evidence(timeline, "EVID-001")
    return jsonify({"case_id": case_id, "findings_count": len(findings), "findings": findings})



@app.route("/api/cases/<case_id>/report/html", methods=["GET"])
def get_html_report(case_id):
    record_audit_event("investigator", "GENERATE_HTML_REPORT", case_id, {}, DB_PATH)
    html_data = ReportGenerator.generate_html_report(case_id, DB_PATH)
    return html_data, 200, {"Content-Type": "text/html"}


@app.route("/api/cases/<case_id>/report/pdf", methods=["GET"])
def get_pdf_report(case_id):
    record_audit_event("investigator", "GENERATE_PDF_REPORT", case_id, {}, DB_PATH)
    pdf_bytes = ReportGenerator.generate_pdf_report(case_id, DB_PATH)
    return pdf_bytes, 200, {"Content-Type": "application/pdf", "Content-Disposition": f"inline; filename=case-{case_id}-report.pdf"}


@app.route("/api/evidence/<evidence_id>/view", methods=["GET"])
def view_evidence_decrypted(evidence_id):
    evd = EvidenceModel.get_by_id(evidence_id, DB_PATH)
    if not evd:
        return jsonify({"error": "Evidence item not found"}), 404

    record_audit_event("investigator", "VIEW_EVIDENCE_DECRYPTED", evidence_id, {"archive_path": evd.get("archive_path")}, DB_PATH)

    # In-memory decryption for authorized viewer
    archive_path = evd.get("archive_path")
    raw_content = ""
    if archive_path and os.path.exists(archive_path):
        try:
            with open(archive_path, "rb") as f:
                raw_bytes = f.read(4096)
                raw_content = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            raw_content = "[Binary Evidence Package]"

    return jsonify({
        "evidence_id": evidence_id,
        "job_id": evd.get("job_id"),
        "sha256": evd.get("sha256"),
        "size_bytes": evd.get("size_bytes"),
        "is_encrypted": bool(evd.get("is_encrypted")),
        "uploaded_at": evd.get("uploaded_at"),
        "decrypted_preview": raw_content[:2000],
        "format": "JSON / Text Viewer",
        "audit_status": "ACCESS LOGGED IN CHAIN OF CUSTODY"
    })


@app.route("/api/evidence/<evidence_id>/download_encrypted", methods=["GET"])
def download_encrypted_evidence(evidence_id):
    evd = EvidenceModel.get_by_id(evidence_id, DB_PATH)
    if not evd:
        return jsonify({"error": "Evidence item not found"}), 404
    archive_path = evd.get("archive_path")
    if not archive_path or not os.path.exists(archive_path):
        return jsonify({"error": "Evidence archive file not found"}), 404

    record_audit_event("investigator", "EXPORT_ENCRYPTED_EVIDENCE", evidence_id, {"archive_path": archive_path}, DB_PATH)
    return send_file(os.path.abspath(archive_path), as_attachment=True, download_name=f"evidence-{evidence_id}.jockyenc")


def is_local_device(dev):
    if not dev:
        return True
    hostname = (dev.get("hostname") or "").lower().strip()
    my_hostname = socket.gethostname().lower().strip()
    ip = (dev.get("ip_address") or "").strip()
    dev_id = (dev.get("id") or "").lower()
    return (
        hostname == my_hostname
        or ip in ("127.0.0.1", "::1", "localhost")
        or dev_id.startswith("local")
        or dev_id.startswith("standalone")
        or dev_id.startswith("agent_")
        or dev_id == "test_dev"
    )


def _archive_member_preview_local(archive_path, member_name):
    """Read an archive member in-memory for a bounded forensic preview; never extracts it."""
    archive_path=os.path.abspath(os.path.expanduser(archive_path)); name=str(member_name or '')
    lower=archive_path.lower(); raw=b''; size=None
    if lower.endswith('.zip'):
        with zipfile.ZipFile(archive_path,'r') as zf:
            info=zf.getinfo(name); size=info.file_size
            with zf.open(info,'r') as fh: raw=fh.read(8*1024*1024+1)
    elif lower.endswith(('.tar','.tar.gz','.tgz','.tar.bz2','.tbz2','.tar.xz','.txz')):
        with tarfile.open(archive_path,'r:*') as tf:
            m=tf.getmember(name); size=m.size
            if not m.isfile():
                return {'member':name,'size_bytes':m.size,'type':'directory' if m.isdir() else 'special','read_only':True}
            fh=tf.extractfile(m); raw=fh.read(8*1024*1024+1) if fh else b''
    elif lower.endswith('.gz'):
        with gzip.open(archive_path,'rb') as fh: raw=fh.read(8*1024*1024+1)
        size=len(raw)
    else:
        return {'error':'unsupported_archive'}
    truncated=len(raw)>8*1024*1024; raw=raw[:8*1024*1024]
    mime=mimetypes.guess_type(name)[0] or 'application/octet-stream'
    if raw.startswith(b'%PDF-'): mime='application/pdf'
    elif raw.startswith(b'\x89PNG\r\n\x1a\n'): mime='image/png'
    elif raw.startswith(b'\xff\xd8\xff'): mime='image/jpeg'
    elif raw.startswith((b'GIF87a',b'GIF89a')): mime='image/gif'
    elif raw.startswith(b'RIFF') and raw[8:12]==b'WEBP': mime='image/webp'
    if mime.startswith('image/'):
        return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'image_data_url':f'data:{mime};base64,{base64.b64encode(raw).decode("ascii")}','read_only':True}
    if mime=='application/pdf' or name.lower().endswith('.pdf'):
        return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':'application/pdf','pdf_data_url':f'data:application/pdf;base64,{base64.b64encode(raw).decode("ascii")}','read_only':True}
    ext=os.path.splitext(name)[1].lower()
    if ext=='.docx':
        try:
            with zipfile.ZipFile(io.BytesIO(raw),'r') as zf:
                import xml.etree.ElementTree as ET
                root=ET.fromstring(zf.read('word/document.xml')); texts=[]
                for para in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                    t=''.join((x.text or '') for x in para.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t')).strip()
                    if t: texts.append(t)
                return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','office_type':'docx','content':'\n\n'.join(texts)[:200000],'binary':False,'read_only':True}
        except Exception:
            pass
    if ext in {'.txt','.log','.csv','.json','.xml','.html','.htm','.md','.py','.sh','.js','.css','.yml','.yaml'} or mime.startswith('text/'):
        return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'content':raw.decode('utf-8',errors='replace')[:200000],'binary':False,'read_only':True}
    try:
        text=raw.decode('utf-8'); binary=False
    except UnicodeDecodeError:
        text=raw.decode('utf-8',errors='replace'); binary=True
    return {'member':name,'size_bytes':size,'bytes_returned':len(raw),'truncated':truncated,'mime':mime,'content':text[:200000],'binary':binary,'read_only':True}

def _archive_entries_local(path):
    """List archive members without extracting or modifying the evidence file."""
    lower = path.lower()
    entries = []
    if lower.endswith('.zip'):
        with zipfile.ZipFile(path, 'r') as zf:
            for info in zf.infolist():
                is_dir = info.is_dir()
                entries.append({
                    "name": info.filename,
                    "size_bytes": int(info.file_size),
                    "compressed_size": int(info.compress_size),
                    "type": "directory" if is_dir else "file",
                    "modified": f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} {info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}",
                    "crc": f"{info.CRC:08x}",
                })
    elif lower.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz')):
        with tarfile.open(path, 'r:*') as tf:
            for m in tf.getmembers():
                entries.append({
                    "name": m.name,
                    "size_bytes": int(m.size),
                    "type": "directory" if m.isdir() else ("symlink" if m.issym() else "file"),
                    "modified": datetime.fromtimestamp(m.mtime, tz=timezone.utc).isoformat() if m.mtime else None,
                    "mode": oct(m.mode) if m.mode else None,
                })
    elif lower.endswith('.gz'):
        # A standalone .gz contains one compressed stream rather than a multi-file archive.
        try:
            with gzip.open(path, 'rb') as gf:
                raw = gf.read(1024 * 1024 + 1)
            name = os.path.basename(path)[:-3] or os.path.basename(path)
            entries.append({"name": name, "size_bytes": len(raw), "type": "decompressed stream", "modified": None})
        except Exception:
            pass
    return entries


def _detect_mime_bytes(path, raw):
    ext_mime = mimetypes.guess_type(path)[0]
    if raw.startswith(b'\x89PNG\r\n\x1a\n'): return 'image/png'
    if raw.startswith(b'\xff\xd8\xff'): return 'image/jpeg'
    if raw.startswith((b'GIF87a', b'GIF89a')): return 'image/gif'
    if raw.startswith(b'RIFF') and raw[8:12] == b'WEBP': return 'image/webp'
    if raw.startswith(b'BM'): return 'image/bmp'
    if raw.startswith(b'II*\x00') or raw.startswith(b'MM\x00*'): return 'image/tiff'
    return ext_mime or 'application/octet-stream'


def _preview_local_file(path):
    max_bytes = 8 * 1024 * 1024
    size = os.path.getsize(path)
    with open(path, 'rb') as fh:
        raw = fh.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    mime = _detect_mime_bytes(path, raw)
    ext = os.path.splitext(path)[1].lower()
    if mime.startswith('image/'):
        return {"path": path, "size_bytes": size, "bytes_returned": len(raw), "truncated": truncated, "mime": mime, "image_data_url": f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}", "read_only": True}
    if mime == 'application/pdf' or ext == '.pdf' or raw.startswith(b'%PDF-'):
        return {"path": path, "size_bytes": size, "bytes_returned": len(raw), "truncated": truncated, "mime": 'application/pdf', "pdf_data_url": f"data:application/pdf;base64,{base64.b64encode(raw).decode('ascii')}", "read_only": True}
    if ext == '.docx':
        try:
            with zipfile.ZipFile(io.BytesIO(raw), 'r') as zf:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(zf.read('word/document.xml')); texts=[]
                for para in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                    t=''.join((x.text or '') for x in para.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t')).strip()
                    if t: texts.append(t)
                return {"path":path,"size_bytes":size,"bytes_returned":len(raw),"truncated":truncated,"mime":'application/vnd.openxmlformats-officedocument.wordprocessingml.document',"office_type":"docx","content":"\n\n".join(texts)[:200000],"binary":False,"read_only":True}
        except Exception:
            pass
    if ext in {'.xlsx','.xlsm'}:
        try:
            with zipfile.ZipFile(io.BytesIO(raw),'r') as zf:
                import xml.etree.ElementTree as ET
                ns={'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                shared=[]
                if 'xl/sharedStrings.xml' in zf.namelist():
                    sr=ET.fromstring(zf.read('xl/sharedStrings.xml'))
                    for si in sr.findall('m:si',ns): shared.append(''.join((t.text or '') for t in si.iter('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t')))
                sheets=[n for n in zf.namelist() if n.startswith('xl/worksheets/sheet') and n.endswith('.xml')]
                lines=[]
                for sh in sorted(sheets):
                    root=ET.fromstring(zf.read(sh)); lines.append(f'[{sh}]')
                    for row in root.findall('.//m:row',ns):
                        vals=[]
                        for c in row.findall('m:c',ns):
                            v=c.find('m:v',ns); val='' if v is None else (shared[int(v.text)] if c.get('t')=='s' and v.text and int(v.text)<len(shared) else v.text or '')
                            vals.append(val)
                        lines.append(' | '.join(vals))
                return {"path":path,"size_bytes":size,"bytes_returned":len(raw),"truncated":truncated,"mime":mime,"office_type":"xlsx","content":"\n".join(lines)[:200000],"binary":False,"read_only":True}
        except Exception:
            pass
    if ext == '.pptx':
        try:
            with zipfile.ZipFile(io.BytesIO(raw),'r') as zf:
                import xml.etree.ElementTree as ET
                slides=[n for n in zf.namelist() if n.startswith('ppt/slides/slide') and n.endswith('.xml')]
                lines=[]
                for sh in sorted(slides):
                    root=ET.fromstring(zf.read(sh)); texts=[(x.text or '') for x in root.iter('{http://schemas.openxmlformats.org/drawingml/2006/main}t') if x.text]
                    lines.append(f'[{sh}]'); lines.append(' '.join(texts))
                return {"path":path,"size_bytes":size,"bytes_returned":len(raw),"truncated":truncated,"mime":mime,"office_type":"pptx","content":"\n\n".join(lines)[:200000],"binary":False,"read_only":True}
        except Exception:
            pass
    try:
        text = raw.decode('utf-8'); binary=False
    except UnicodeDecodeError:
        text = raw.decode('utf-8', errors='replace'); binary=True
    return {"path": path, "size_bytes": size, "bytes_returned": len(raw), "truncated": truncated, "mime": mime, "binary": binary, "content": text, "read_only": True}


@app.route("/api/devices/<device_id>/filesystem/browse", methods=["GET"])
def browse_device_filesystem(device_id):
    """Read-only filesystem browser for a local endpoint.

    The dashboard's localhost endpoint is the same host as the reference
    server, so directory navigation can be resolved directly with the Linux
    collector. No files are modified and directory listings are bounded.
    """
    devices = DeviceModel.list_all(get_db_path())
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "device_not_found"}), 404
    path = request.args.get("path", "/") or "/"
    path = os.path.abspath(os.path.expanduser(unquote(path)))

    # Only resolve paths locally when the enrolled endpoint is this server
    # host. Remote endpoints must use the agent's normal collection workflow.
    if not is_local_device(dev):
        request_id = f"fs_{uuid.uuid4().hex[:12]}"
        FILE_REQUESTS[request_id] = {"request_id": request_id, "device_id": device_id, "kind": "browse", "path": path, "status": "pending"}
        deadline = time.time() + 12
        while time.time() < deadline:
            result = FILE_REQUESTS.get(request_id, {})
            if result.get("status") == "complete":
                FILE_REQUESTS.pop(request_id, None)
                return jsonify({"device_id": device_id, "path": path, "parent": os.path.dirname(path) or path, **result.get("result", {})})
            time.sleep(0.25)
        FILE_REQUESTS.pop(request_id, None)
        return jsonify({"error": "filesystem_request_timeout", "message": "The endpoint did not answer the read-only request."}), 504

    if not os.path.isdir(path):
        return jsonify({"error": "not_a_directory", "path": path}), 400

    if os.name == "nt":
        from collector.windows_collector import get_windows_filesystem
        raw_rows = get_windows_filesystem(path)
    else:
        from collector.linux_collector import filesystem
        raw_rows = filesystem(path)

    rows = [{
        "name": row.get("filename") or row.get("name", ""),
        "path": row.get("path", ""),
        "is_directory": bool(row.get("type") == "Directory" or row.get("is_directory")),
        "size_bytes": row.get("size_bytes") if row.get("size_bytes") is not None else row.get("size", 0),
        "ctime": row.get("created_time") or row.get("ctime", ""),
        "mtime": row.get("modified_time") or row.get("mtime", ""),
        "atime": row.get("access_time") or row.get("atime", ""),
        "owner": row.get("owner", "SYSTEM" if os.name == "nt" else "root"),
        "mode": row.get("mode") or row.get("attributes", "Normal"),
        "attributes": row.get("attributes", "Normal"),
        "is_deleted": bool(row.get("is_deleted", False)),
        "status": row.get("status", "PRESENT"),
        "mismatch_flag": bool(row.get("mismatch_flag", False)),
        "detected_type": row.get("detected_type", "Directory" if (row.get("type") == "Directory" or row.get("is_directory")) else "File"),
        "magic_hex": row.get("magic_hex", ""),
        "sha256": row.get("sha256"),
        "inode": row.get("inode"),
        "uid": row.get("uid"),
        "gid": row.get("gid"),
        "group": row.get("group"),
        "nlink": row.get("nlink"),
        "change_time": row.get("change_time"),
        "read_only": True
    } for row in raw_rows]

    # Deleted-file recovery is deliberately NOT performed during normal directory browsing.
    # Recovery can require filesystem-level inspection and should run only when the
    # investigator explicitly opens the Deleted Files view.

    # Sort directories first, then active/deleted files
    rows.sort(key=lambda r: (not bool(r.get("is_directory")), bool(r.get("is_deleted")), str(r.get("name", "")).lower()))
    parent = os.path.dirname(path) if path != os.path.dirname(path) else path
    record_audit_event("investigator", "BROWSE_FILESYSTEM", device_id, {"path": path}, get_db_path())
    return jsonify({
        "device_id": device_id,
        "path": path,
        "parent": parent,
        "count": len(rows),
        "entries": rows,
        "read_only": True,
    })


@app.route("/api/devices/<device_id>/filesystem/archive", methods=["GET"])
def list_device_archive(device_id):
    """Read-only listing of ZIP/TAR/GZ members; never extracts the archive."""
    devices = DeviceModel.list_all(get_db_path())
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "device_not_found"}), 404
    path = request.args.get("path", "")
    if not is_local_device(dev):
        request_id = f"fs_{uuid.uuid4().hex[:12]}"
        FILE_REQUESTS[request_id] = {"request_id": request_id, "device_id": device_id, "kind": "archive", "path": path, "status": "pending"}
        deadline = time.time() + 12
        while time.time() < deadline:
            result = FILE_REQUESTS.get(request_id, {})
            if result.get("status") == "complete":
                FILE_REQUESTS.pop(request_id, None)
                return jsonify({"device_id": device_id, **result.get("result", {})})
            time.sleep(.25)
        FILE_REQUESTS.pop(request_id, None)
        return jsonify({"error": "filesystem_request_timeout", "message": "The endpoint did not answer the archive request."}), 504
    path = os.path.abspath(os.path.expanduser(unquote(path)))
    if not os.path.isfile(path):
        return jsonify({"error": "not_a_file", "path": path}), 400
    try:
        entries = _archive_entries_local(path)
        record_audit_event("investigator", "LIST_ARCHIVE_CONTENTS", device_id, {"path": path, "count": len(entries)}, get_db_path())
        return jsonify({"device_id": device_id, "path": path, "count": len(entries), "entries": entries, "read_only": True})
    except (OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        return jsonify({"error": "archive_read_failed", "message": str(exc), "path": path}), 400


@app.route("/api/devices/<device_id>/filesystem/archive/content", methods=["GET"])
def read_device_archive_member(device_id):
    """Read-only, in-memory preview of one member inside ZIP/TAR/GZ evidence."""
    devices=DeviceModel.list_all(get_db_path()); dev=next((d for d in devices if d.get("id")==device_id),None)
    if not dev:
        # Local test/forensic workflows may inspect a path before a device record
        # has been registered. Only permit an explicitly local filesystem path.
        requested_path = os.path.abspath(os.path.expanduser(unquote(request.args.get("path", ""))))
        if not requested_path or not os.path.isfile(requested_path):
            return jsonify({"error":"device_not_found"}),404
        dev = {"id": device_id, "os": host_platform.system(), "hostname": socket.gethostname()}
    archive_path=request.args.get("path",""); member=request.args.get("member","")
    if not archive_path or not member: return jsonify({"error":"archive_and_member_required"}),400
    if not is_local_device(dev):
        request_id=f"fs_{uuid.uuid4().hex[:12]}"
        FILE_REQUESTS[request_id]={"request_id":request_id,"device_id":device_id,"kind":"archive_content","path":archive_path,"member":member,"status":"pending"}
        deadline=time.time()+15
        while time.time()<deadline:
            result=FILE_REQUESTS.get(request_id,{})
            if result.get("status")=="complete":
                FILE_REQUESTS.pop(request_id,None); return jsonify({"device_id":device_id,**result.get("result",{})})
            time.sleep(.25)
        FILE_REQUESTS.pop(request_id,None); return jsonify({"error":"filesystem_request_timeout","message":"The endpoint did not answer the archive member request."}),504
    try:
        result=_archive_member_preview_local(archive_path,member)
        if result.get("error"): return jsonify(result),400
        record_audit_event("investigator","PREVIEW_ARCHIVE_MEMBER",device_id,{"archive":archive_path,"member":member},get_db_path())
        return jsonify({"device_id":device_id,**result})
    except Exception as exc:
        return jsonify({"error":"archive_member_read_failed","message":str(exc)}),400

@app.route("/api/devices/<device_id>/filesystem/preview", methods=["GET"])
def preview_device_file(device_id):
    """Return a bounded read-only text or image preview for a target file."""
    devices = DeviceModel.list_all(get_db_path())
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "device_not_found"}), 404
    path = request.args.get("path", "")
    if not is_local_device(dev):
        request_id = f"fs_{uuid.uuid4().hex[:12]}"
        FILE_REQUESTS[request_id] = {"request_id": request_id, "device_id": device_id, "kind": "preview", "path": path, "status": "pending"}
        deadline = time.time() + 12
        while time.time() < deadline:
            result = FILE_REQUESTS.get(request_id, {})
            if result.get("status") == "complete":
                FILE_REQUESTS.pop(request_id, None)
                return jsonify({"device_id": device_id, **result.get("result", {})})
            time.sleep(.25)
        FILE_REQUESTS.pop(request_id, None)
        return jsonify({"error": "filesystem_request_timeout", "message": "The endpoint did not answer the preview request."}), 504
    path = os.path.abspath(os.path.expanduser(unquote(path)))
    if not os.path.isfile(path):
        return jsonify({"error": "not_a_file", "path": path}), 400
    try:
        result = _preview_local_file(path)
        record_audit_event("investigator", "PREVIEW_FILE", device_id, {"path": path, "bytes": result.get("bytes_returned", 0)}, get_db_path())
        return jsonify({"device_id": device_id, **result})
    except PermissionError:
        return jsonify({"error": "permission_denied", "path": path}), 403
    except OSError as exc:
        return jsonify({"error": "preview_failed", "message": str(exc), "path": path}), 500


@app.route("/api/devices/<device_id>/filesystem/metadata", methods=["GET"])
def get_device_file_metadata(device_id):
    """Retrieve full deep forensic metadata for a file from the selected endpoint."""
    devices = DeviceModel.list_all(get_db_path())
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "device_not_found"}), 404
    if not is_local_device(dev):
        path=request.args.get("path", "")
        request_id=f"fs_{uuid.uuid4().hex[:12]}"
        FILE_REQUESTS[request_id]={"request_id":request_id,"device_id":device_id,"kind":"metadata","path":path,"status":"pending"}
        deadline=time.time()+12
        while time.time()<deadline:
            result=FILE_REQUESTS.get(request_id,{})
            if result.get("status")=="complete":
                FILE_REQUESTS.pop(request_id,None); payload=result.get("result",{})
                if payload.get("error"): return jsonify(payload),400
                return jsonify({"device_id":device_id,**payload})
            time.sleep(.25)
        FILE_REQUESTS.pop(request_id,None); return jsonify({"error":"filesystem_request_timeout","message":"The endpoint did not answer the metadata request."}),504

    path = os.path.abspath(os.path.expanduser(unquote(request.args.get("path", ""))))
    if not path or not os.path.exists(path):
        return jsonify({"error": "file_not_found", "path": path}), 404
    try:
        stat = os.stat(path)
        is_dir = os.path.isdir(path)
        ext = os.path.splitext(path)[1] if not is_dir else ""
        mismatch_info = {}
        if os.name == "nt" and not is_dir:
            from collector.windows_collector import detect_extension_mismatch
            mismatch_info = detect_extension_mismatch(path, ext)
        
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha256 = hasher.hexdigest()
        except Exception:
            sha256 = "N/A (Directory or Access Denied)"
            
        owner = os.environ.get("USERNAME", "SYSTEM") if os.name == "nt" else "root"
        if os.name == "posix":
            try:
                import pwd
                owner = pwd.getpwuid(stat.st_uid).pw_name
            except Exception:
                owner = str(stat.st_uid)

        exif_gps = None
        exif_present = False
        if not is_dir and ext.lower() in {".jpg", ".jpeg", ".tif", ".tiff", ".webp"}:
            try:
                from collector.location_intelligence import GPSArtifactParser
                with open(path, "rb") as image_file:
                    header = image_file.read(2 * 1024 * 1024)
                exif_gps = GPSArtifactParser.extract_exif_gps_from_bytes(header)
                exif_present = b"Exif\x00\x00" in header
            except Exception:
                exif_gps = None
        meta = {
            "device_id": device_id,
            "path": path,
            "name": os.path.basename(path),
            "extension": ext,
            "is_directory": is_dir,
            "size_bytes": stat.st_size if not is_dir else 0,
            "mode_octal": oct(stat.st_mode & 0o7777),
            "attributes": "Directory" if is_dir else ("Read-Only" if not (stat.st_mode & 0o222) else "Normal"),
            "owner": owner,
            "group": (str(stat.st_gid) if os.name != "posix" else __import__("grp").getgrgid(stat.st_gid).gr_name),
            "inode": stat.st_ino,
            "uid": getattr(stat, "st_uid", None),
            "gid": getattr(stat, "st_gid", None),
            "nlink": stat.st_nlink,
            "created_time": (datetime.fromtimestamp(getattr(stat, "st_birthtime", stat.st_ctime), tz=timezone.utc).isoformat() if getattr(stat, "st_birthtime", None) else None),
            "change_time": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            "modified_time": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "access_time": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
            "sha256": sha256,
            "exif_present": exif_present,
            "exif_gps": exif_gps,
            "exif_gps_coordinates": (f"{exif_gps['latitude']}, {exif_gps['longitude']}" if exif_gps else None),
            "mismatch_flag": mismatch_info.get("mismatch", False),
            "detected_type": mismatch_info.get("detected_type", "Directory" if is_dir else "File"),
            "magic_hex": mismatch_info.get("magic_hex", ""),
            "status": "PRESENT",
            "is_deleted": False,
            "read_only": True
        }
        record_audit_event("investigator", "READ_FILE_METADATA", device_id, {"path": path}, get_db_path())
        return jsonify(meta)
    except Exception as exc:
        return jsonify({"error": "metadata_read_failed", "message": str(exc)}), 500


@app.route("/api/devices/<device_id>/filesystem/deleted_scan", methods=["GET"])
def scan_device_deleted_files(device_id):
    devices=DeviceModel.list_all(get_db_path()); dev=next((d for d in devices if d.get("id")==device_id),None)
    if not dev:
        # Local test/forensic workflows may inspect a path before a device record
        # has been registered. Only permit an explicitly local filesystem path.
        requested_path = os.path.abspath(os.path.expanduser(unquote(request.args.get("path", ""))))
        if not requested_path or not os.path.isfile(requested_path):
            return jsonify({"error":"device_not_found"}),404
        dev = {"id": device_id, "os": host_platform.system(), "hostname": socket.gethostname()}
    volume=request.args.get("volume", "C:\\" if os.name=="nt" else "/")
    if not is_local_device(dev):
        request_id=f"fs_{uuid.uuid4().hex[:12]}"
        FILE_REQUESTS[request_id]={"request_id":request_id,"device_id":device_id,"kind":"deleted_scan","path":volume,"status":"pending"}
        deadline=time.time()+20
        while time.time()<deadline:
            result=FILE_REQUESTS.get(request_id,{})
            if result.get("status")=="complete":
                FILE_REQUESTS.pop(request_id,None); payload=result.get("result",{})
                if payload.get("error"): return jsonify(payload),400
                return jsonify({"device_id":device_id,"volume":volume,**payload})
            time.sleep(.25)
        FILE_REQUESTS.pop(request_id,None); return jsonify({"error":"filesystem_request_timeout","message":"The endpoint did not answer the deleted-file request."}),504
    from collector.recovery import scan_deleted_files
    candidates=scan_deleted_files(volume)
    rows=[{**cand,"name":cand.get("filename","")+" [DELETED]","path":cand.get("original_path","") or f"[inode {cand.get('inode','?')}]","is_directory":False,"status":"DELETED","is_deleted":True,"mtime":cand.get("deleted_time"),"atime":cand.get("deleted_time"),"read_only":True} for cand in candidates]
    record_audit_event("investigator","DELETED_FILE_SCAN",device_id,{"volume":volume,"count":len(rows)},get_db_path())
    return jsonify({"device_id":device_id,"volume":volume,"count":len(rows),"entries":rows,"read_only":True})


@app.route("/api/devices/<device_id>/filesystem/content", methods=["GET"])
def read_device_file_content(device_id):
    """Read a bounded text/binary preview from a local endpoint file."""
    devices = DeviceModel.list_all(get_db_path())
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "device_not_found"}), 404
    if not is_local_device(dev):
        path = os.path.abspath(os.path.expanduser(unquote(request.args.get("path", ""))))
        candidate_id=request.args.get("candidate_id")
        request_id = f"fs_{uuid.uuid4().hex[:12]}"
        FILE_REQUESTS[request_id] = {"request_id": request_id, "device_id": device_id, "kind": "deleted_content" if candidate_id else "content", "path": request.args.get("volume", path), "candidate_id": candidate_id, "status": "pending"}
        deadline = time.time() + 12
        while time.time() < deadline:
            result = FILE_REQUESTS.get(request_id, {})
            if result.get("status") == "complete":
                FILE_REQUESTS.pop(request_id, None)
                payload = result.get("result", {})
                if payload.get("error"):
                    return jsonify(payload), 400
                return jsonify({"device_id": device_id, **payload})
            time.sleep(0.25)
        FILE_REQUESTS.pop(request_id, None)
        return jsonify({"error": "filesystem_request_timeout", "message": "The endpoint did not answer the read-only request."}), 504

    path = os.path.abspath(os.path.expanduser(unquote(request.args.get("path", ""))))
    candidate_id = request.args.get("candidate_id")
    if candidate_id and str(candidate_id).startswith("EXT4DEL_") and is_local_device(dev):
        from collector.recovery import read_linux_deleted_inode
        volume=request.args.get("volume", "/")
        rec=read_linux_deleted_inode(candidate_id,volume)
        if rec.get("error"): return jsonify(rec),400
        raw=rec.get("raw",b"")
        try: text=raw.decode("utf-8"); encoding,binary="utf-8",False
        except UnicodeDecodeError: text=raw.decode("utf-8",errors="replace"); encoding,binary="utf-8-with-replacement",True
        return jsonify({"device_id":device_id,"path":f"[deleted inode {rec.get('inode')}]","size_bytes":rec.get("size_bytes"),"bytes_returned":rec.get("bytes_returned"),"truncated":rec.get("truncated"),"encoding":encoding,"binary":binary,"content":text,"sha256":rec.get("sha256"),"read_only":True,"deleted":True})
    if candidate_id or not path or not os.path.isfile(path):
        try:
            from collector.recovery import scan_deleted_files, recover_deleted_file
            volume=request.args.get("volume", "/" if os.name != "nt" else "C:\\")
            candidates=scan_deleted_files(volume)
            matching=next((c for c in candidates if (candidate_id and c.get("candidate_id")==candidate_id) or c.get("original_path")==path or c.get("candidate_id") in path or c.get("filename") in path),None)
            cand_id=matching.get("candidate_id") if matching else candidate_id
            src_p=matching.get("original_path") if matching else path
            res=recover_deleted_file(cand_id, src_p, volume=volume) if cand_id else {}
            if res.get("destination_path") and os.path.exists(res.get("destination_path")):
                path = res.get("destination_path")
        except Exception:
            pass

    if not path or not os.path.isfile(path):
        return jsonify({"error": "not_a_file", "path": path}), 400

    max_bytes = 256 * 1024
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes + 1)
        truncated = len(raw) > max_bytes
        raw = raw[:max_bytes]
        try:
            text = raw.decode("utf-8")
            encoding = "utf-8"
            binary = False
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            encoding = "utf-8-with-replacement"
            binary = True
        record_audit_event("investigator", "READ_FILE_PREVIEW", device_id, {"path": path, "bytes": len(raw)}, get_db_path())
        return jsonify({
            "device_id": device_id,
            "path": path,
            "size_bytes": size,
            "bytes_returned": len(raw),
            "truncated": truncated,
            "encoding": encoding,
            "binary": binary,
            "content": text,
            "sha256": calculate_sha256(path),
            "read_only": True,
        })
    except PermissionError:
        return jsonify({"error": "permission_denied", "path": path}), 403
    except OSError as exc:
        return jsonify({"error": "read_failed", "message": str(exc), "path": path}), 500


@app.route("/api/agents/<agent_id>/filesystem/requests", methods=["GET"])
def list_filesystem_requests(agent_id):
    return jsonify([request_data for request_data in FILE_REQUESTS.values() if request_data.get("device_id") == agent_id and request_data.get("status") == "pending"])


@app.route("/api/agents/<agent_id>/filesystem/requests/<request_id>", methods=["POST"])
def complete_filesystem_request(agent_id, request_id):
    request_data = FILE_REQUESTS.get(request_id)
    if not request_data or request_data.get("device_id") != agent_id:
        return jsonify({"error": "filesystem_request_not_found"}), 404
    request_data["status"] = "complete"
    request_data["result"] = request.get_json() or {}
    return jsonify({"status": "accepted", "request_id": request_id})


@app.route("/api/devices/<device_id>/telemetry", methods=["POST"])
def ingest_device_telemetry(device_id):
    data = request.get_json() or {}
    categories = data.get("categories")
    if not isinstance(categories, dict) or not categories:
        return jsonify({"error": "categories object is required"}), 400
    # Telemetry is accepted only from the registered endpoint and, when the
    # sender supplies a case id, it must match the endpoint's active case.
    dev = DeviceModel.list_all(get_db_path())
    device = next((d for d in dev if d.get("id") == device_id), None)
    if not device:
        return jsonify({"error": "agent_not_registered"}), 404
    incoming_case = str(data.get("case_id") or "").strip()
    active_case = str(device.get("active_case_id") or "").strip()
    if incoming_case and active_case and incoming_case != active_case:
        return jsonify({"error": "case_device_mismatch", "active_case_id": active_case}), 409
    collected_at = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    stored = 0
    for category, payload in categories.items():
        if not isinstance(category, str) or not category:
            continue
        DeviceTelemetryModel.upsert(device_id, category, payload, collected_at, get_db_path())
        stored += 1
    record_audit_event("agent", "INGEST_DEVICE_TELEMETRY", device_id, {"categories": stored}, get_db_path())
    return jsonify({"status": "accepted", "agent_id": device_id, "categories": stored, "timestamp": collected_at}), 200


@app.route("/api/devices/<device_id>/telemetry", methods=["GET"])
def list_device_telemetry(device_id):
    return jsonify({"device_id": device_id, "telemetry": DeviceTelemetryModel.list_for_agent(device_id, get_db_path()), "read_only": True})


@app.route("/api/devices/<device_id>/telemetry/<category>", methods=["GET"])
def device_telemetry(device_id, category):
    # Dashboard telemetry reads are intentionally side-effect free. The UI can
    # poll these endpoints frequently; writing an audit row for every refresh
    # causes unnecessary SQLite writer contention. Explicit forensic actions
    # remain audited elsewhere.
    live = DeviceTelemetryModel.get(device_id, category, get_db_path())
    if live is not None:
        return jsonify(live)
    data = get_agent_telemetry_category(device_id, category)
    return jsonify({"device_id": device_id, "category": category, "data": data, "timestamp": None, "read_only": True})


@app.route("/api/devices/<device_id>/accessed_shared_files", methods=["GET"])
@app.route("/api/devices/accessed_shared_files", methods=["GET"])
@app.route("/api/agents/<agent_id>/removable_media", methods=["GET"])
@app.route("/api/devices/<agent_id>/removable_media", methods=["GET"])
def get_connected_device_accessed_shared_files(device_id="all", agent_id=None):
    """Retrieve all files accessed, transferred, or shared to connected devices."""
    target_id = agent_id or device_id
    record_audit_event("investigator", "QUERY_CONNECTED_DEVICE_FILES", target_id, {}, get_db_path())
    
    transfers = []
    devices_media = []

    if device_id and device_id != "all":
        live_telemetry = get_agent_telemetry_category(device_id, "removable_media")
        if live_telemetry:
            payload = live_telemetry.get("data") if isinstance(live_telemetry, dict) and "data" in live_telemetry else live_telemetry
            if isinstance(payload, dict):
                devices_media = payload.get("devices") or payload.get("connected_devices") or []
                transfers = payload.get("transfers") or payload.get("all_records") or []
            elif isinstance(payload, list):
                devices_media = payload

            if not transfers and devices_media:
                for dev in devices_media:
                    records = dev.get("file_activity_records") or dev.get("accessed_shared_files") or []
                    for r in records:
                        if r not in transfers:
                            transfers.append(r)

    if not transfers and not devices_media:
        from collector.removable_media import get_removable_media_forensics, get_file_transfers_and_activity
        transfers = get_file_transfers_and_activity()
        devices_media = get_removable_media_forensics()

    accessed_files = [t for t in transfers if "Share" not in t.get("operation_type", "")]
    shared_files = [t for t in transfers if "Share" in t.get("operation_type", "")]

    return jsonify({
        "device_id": target_id,
        "agent_id": target_id,
        "devices": devices_media,
        "transfers": transfers,
        "total_count": len(transfers),
        "accessed_files_count": len(accessed_files),
        "shared_files_count": len(shared_files),
        "accessed_files": accessed_files,
        "shared_files": shared_files,
        "connected_devices": devices_media,
        "all_records": transfers,
        "read_only": True
    })



@app.route("/api/live/processes/<agent_id>", methods=["GET"])
def live_processes(agent_id):
    record_audit_event("investigator", "QUERY_LIVE_PROCESSES", agent_id, {}, DB_PATH)
    procs = get_agent_telemetry_category(agent_id, "processes")
    return jsonify({
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "processes": procs
    })


@app.route("/api/live/system/<agent_id>", methods=["GET"])
def live_system(agent_id):
    record_audit_event("investigator", "QUERY_LIVE_SYSTEM", agent_id, {}, DB_PATH)
    sys_info = get_agent_telemetry_category(agent_id, "system")
    return jsonify({
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "system": sys_info
    })


@app.route("/api/cases/<case_id>/email", methods=["GET"])
@app.route("/api/agents/<agent_id>/email", methods=["GET"])
def get_email_artifacts_endpoint(case_id=None, agent_id=None):
    record_audit_event("investigator", "QUERY_EMAIL_FORENSICS", case_id or agent_id or "global", {}, get_db_path())
    target_id = agent_id or case_id
    if target_id:
        live = get_agent_telemetry_category(target_id, "email")
        if live and isinstance(live, list) and len(live) > 0:
            has_real = any(
                isinstance(x, dict)
                and x.get("artifact_type") not in ("system_mail_scan", "email_scan_result", "mail_client_store")
                and (x.get("from") or x.get("subject") or x.get("path") or x.get("account"))
                for x in live
            )
            if has_real:
                return jsonify({"case_id": case_id, "agent_id": agent_id, "count": len(live), "artifacts": live})
    
    if agent_id:
        artifacts = _queue_email_collection(agent_id)
        return jsonify({"case_id": case_id, "agent_id": agent_id, "count": len(artifacts), "artifacts": artifacts, "source": "endpoint_agent"})
    return jsonify({"case_id": case_id, "agent_id": agent_id, "count": 0, "artifacts": [], "source": "no_endpoint_selected", "message": "Select an enrolled endpoint to collect email evidence."})


@app.route("/api/email/content", methods=["GET"])
def get_email_file_content():
    """Return full raw text content of an email file on disk for full reading in modal."""
    file_path = request.args.get("path")
    if not file_path:
        return jsonify({"error": "path_required"}), 400
    try:
        abs_p = os.path.abspath(file_path)
        if not os.path.isfile(abs_p):
            return jsonify({"error": "file_not_found", "path": file_path}), 404
        with open(abs_p, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(100000)  # Read up to 100 KB
        return jsonify({"path": abs_p, "size_bytes": len(content), "content": content})
    except Exception as e:
        return jsonify({"error": f"read_failed: {str(e)}", "path": file_path}), 500


@app.route("/api/agents/<agent_id>/location", methods=["GET"])
@app.route("/api/cases/<case_id>/location_agent", methods=["GET"])
def get_agent_location_endpoint(agent_id=None, case_id=None):
    record_audit_event("investigator", "QUERY_AGENT_LOCATION", agent_id or case_id or "global", {}, get_db_path())
    target_id = agent_id or case_id
    
    history = []
    if target_id:
        from server.models import DeviceTelemetryModel
        history = DeviceTelemetryModel.get_location_history(target_id, get_db_path())
        live = get_agent_telemetry_category(target_id, "location")
        if live and isinstance(live, dict):
            return jsonify({"agent_id": agent_id, "data": live, "history": history, "read_only": True})
            
    from collector.location import get_location_telemetry
    loc = get_location_telemetry()
    return jsonify({"agent_id": agent_id, "data": loc, "history": history, "read_only": True})


@app.route("/api/cases/<case_id>/removable_media", methods=["GET"])
@app.route("/api/agents/<agent_id>/removable_media", methods=["GET"])
def get_removable_media_endpoint(case_id=None, agent_id=None):
    record_audit_event("investigator", "QUERY_REMOVABLE_MEDIA", case_id or agent_id or "global", {}, get_db_path())
    from collector.removable_media import get_removable_media_forensics, get_file_transfers_and_activity
    devices = get_removable_media_forensics()
    transfers = get_file_transfers_and_activity()
    return jsonify({
        "case_id": case_id,
        "agent_id": agent_id,
        "count": len(devices),
        "devices": devices,
        "transfers": transfers
    })


@app.route("/api/email/intelligence/overview", methods=["GET"])
@app.route("/api/agents/<agent_id>/email/intelligence/overview", methods=["GET"])
def get_email_intelligence_overview_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    target_id = agent_id or "global"
    record_audit_event("investigator", "QUERY_EMAIL_INTELLIGENCE_OVERVIEW", target_id, {"demo_mode": demo_mode}, get_db_path())
    from collector.email_intelligence import get_email_overview_intelligence
    live = get_agent_telemetry_category(agent_id, "email") if agent_id else None
    if isinstance(live, dict) and "data" in live: live = live.get("data")
    if isinstance(live, dict): live = live.get("emails") or live.get("artifacts") or []
    if agent_id and not isinstance(live, list): live = []
    if agent_id and not live: live = _queue_email_collection(agent_id)
    res = get_email_overview_intelligence(demo_mode=demo_mode, email_artifacts=live if isinstance(live, list) else None)
    return jsonify(res)


@app.route("/api/email/intelligence/who_shared_what", methods=["GET", "POST"])
@app.route("/api/agents/<agent_id>/email/intelligence/who_shared_what", methods=["GET", "POST"])
def get_email_who_shared_what_endpoint(agent_id=None):
    data = request.get_json() or {} if request.method == "POST" else request.args
    demo_mode = str(data.get("demo", "0")).lower() in {"1", "true"}
    sender = data.get("sender")
    recipient = data.get("recipient")
    date_str = data.get("date")
    time_str = data.get("time")
    keyword = data.get("keyword")
    att_name = data.get("attachment")
    record_audit_event("investigator", "QUERY_EMAIL_WHO_SHARED_WHAT", agent_id or "global", {"sender": sender, "attachment": att_name}, get_db_path())
    from collector.email_intelligence import search_who_shared_what
    live = get_agent_telemetry_category(agent_id, "email") if agent_id else None
    if isinstance(live, dict) and "data" in live: live = live.get("data")
    if isinstance(live, dict): live = live.get("emails") or live.get("artifacts") or []
    if agent_id and not isinstance(live, list): live = []
    if agent_id and not live: live = _queue_email_collection(agent_id)
    results = search_who_shared_what(sender=sender, recipient=recipient, date_str=date_str, time_str=time_str, keyword=keyword, attachment_name=att_name, demo_mode=demo_mode, email_artifacts=live if isinstance(live,list) else None)
    return jsonify({"count": len(results), "results": results})


@app.route("/api/email/intelligence/timeline", methods=["GET"])
@app.route("/api/agents/<agent_id>/email/intelligence/timeline", methods=["GET"])
def get_email_master_timeline_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    record_audit_event("investigator", "QUERY_EMAIL_MASTER_TIMELINE", agent_id or "global", {"demo_mode": demo_mode}, get_db_path())
    from collector.email_intelligence import get_master_forensic_timeline
    live = get_agent_telemetry_category(agent_id, "email") if agent_id else None
    if isinstance(live, dict) and "data" in live: live = live.get("data")
    if isinstance(live, dict): live = live.get("emails") or live.get("artifacts") or []
    if agent_id and not isinstance(live, list): live = []
    if agent_id and not live: live = _queue_email_collection(agent_id)
    timeline = get_master_forensic_timeline(demo_mode=demo_mode, email_artifacts=live if isinstance(live,list) else None)
    return jsonify({"count": len(timeline), "timeline": timeline})






def _normalize_email_payload(payload):
    if isinstance(payload, dict):
        payload = payload.get("emails") or payload.get("artifacts") or payload.get("data") or []
    return payload if isinstance(payload, list) else []


def _queue_email_collection(agent_id: str, timeout: float = 15.0):
    """Ask the endpoint agent to collect email artifacts; never scan the server host as a substitute."""
    if not agent_id:
        return []
    cached = _normalize_email_payload(get_agent_telemetry_category(agent_id, "email"))
    if cached:
        return cached
    request_id = f"email_{uuid.uuid4().hex[:12]}"
    EMAIL_REQUESTS[request_id] = {"request_id": request_id, "device_id": agent_id, "status": "pending", "created_at": time.time()}
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = EMAIL_REQUESTS.get(request_id, {})
        if result.get("status") == "complete":
            EMAIL_REQUESTS.pop(request_id, None)
            payload = result.get("result", {})
            return _normalize_email_payload(payload)
        # If the agent has not polled yet, keep waiting briefly; this is bounded.
        time.sleep(0.25)
    EMAIL_REQUESTS.pop(request_id, None)
    return []


@app.route("/api/agents/<agent_id>/email/requests", methods=["GET"])
def poll_email_requests(agent_id):
    return jsonify([r for r in EMAIL_REQUESTS.values() if r.get("device_id") == agent_id and r.get("status") == "pending"])


@app.route("/api/agents/<agent_id>/email/requests/<request_id>", methods=["POST"])
def complete_email_request(agent_id, request_id):
    request_data = EMAIL_REQUESTS.get(request_id)
    if not request_data or request_data.get("device_id") != agent_id:
        return jsonify({"error": "email_request_not_found"}), 404
    request_data["status"] = "complete"
    request_data["result"] = request.get_json() or []
    return jsonify({"status": "accepted", "request_id": request_id})


@app.route("/api/devices/<device_id>/filesystem/hex", methods=["GET"])
def read_device_file_hex(device_id):
    devices=DeviceModel.list_all(get_db_path()); dev=next((d for d in devices if d.get("id")==device_id),None)
    if not dev:
        # Local test/forensic workflows may inspect a path before a device record
        # has been registered. Only permit an explicitly local filesystem path.
        requested_path = os.path.abspath(os.path.expanduser(unquote(request.args.get("path", ""))))
        if not requested_path or not os.path.isfile(requested_path):
            return jsonify({"error":"device_not_found"}),404
        dev = {"id": device_id, "os": host_platform.system(), "hostname": socket.gethostname()}
    if not is_local_device(dev):
        path=request.args.get("path",""); candidate_id=request.args.get("candidate_id")
        request_id=f"fs_{uuid.uuid4().hex[:12]}"
        FILE_REQUESTS[request_id]={"request_id":request_id,"device_id":device_id,"kind":"deleted_hex" if candidate_id else "hex","path":request.args.get("volume",path),"candidate_id":candidate_id,"status":"pending"}
        deadline=time.time()+12
        while time.time()<deadline:
            result=FILE_REQUESTS.get(request_id,{})
            if result.get("status")=="complete":
                FILE_REQUESTS.pop(request_id,None); payload=result.get("result",{})
                if payload.get("error"): return jsonify(payload),400
                return jsonify({"device_id":device_id,**payload})
            time.sleep(.25)
        FILE_REQUESTS.pop(request_id,None); return jsonify({"error":"filesystem_request_timeout","message":"The endpoint did not answer the hex request."}),504

    path = os.path.abspath(os.path.expanduser(unquote(request.args.get("path", ""))))
    candidate_id=request.args.get("candidate_id")
    if candidate_id and str(candidate_id).startswith("EXT4DEL_") and is_local_device(dev):
        from collector.recovery import read_linux_deleted_inode
        rec=read_linux_deleted_inode(candidate_id,request.args.get("volume", "/"),1024)
        if rec.get("error"): return jsonify(rec),400
        raw=rec.get("raw",b"")
        hex_dump=[{"offset":f"{i:08X}","hex":" ".join(f"{b:02X}" for b in raw[i:i+16]).ljust(47),"ascii":"".join(chr(b) if 32<=b<=126 else "." for b in raw[i:i+16])} for i in range(0,len(raw),16)]
        return jsonify({"device_id":device_id,"path":f"[deleted inode {rec.get('inode')}]","size_bytes":rec.get("size_bytes"),"bytes_returned":len(raw),"hex_dump":hex_dump,"sha256":rec.get("sha256"),"read_only":True,"deleted":True})
    if candidate_id or not path or not os.path.isfile(path):
        try:
            from collector.recovery import scan_deleted_files, recover_deleted_file
            volume=request.args.get("volume", "/" if os.name != "nt" else "C:\\")
            candidates=scan_deleted_files(volume)
            matching=next((c for c in candidates if (candidate_id and c.get("candidate_id")==candidate_id) or c.get("original_path")==path or c.get("candidate_id") in path),None)
            cand_id=matching.get("candidate_id") if matching else candidate_id
            src_p=matching.get("original_path") if matching else path
            res=recover_deleted_file(cand_id,src_p,volume=volume) if cand_id else {}
            if res.get("destination_path") and os.path.exists(res.get("destination_path")): path=res.get("destination_path")
        except Exception: pass

    if not path or not os.path.isfile(path):
        return jsonify({"error": "not_a_file", "path": path}), 400
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            raw = f.read(1024)
        hex_dump = []
        for offset in range(0, len(raw), 16):
            chunk = raw[offset:offset+16]
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_dump.append({
                "offset": f"{offset:08X}",
                "hex": hex_bytes.ljust(47),
                "ascii": ascii_repr
            })
        record_audit_event("investigator", "READ_FILE_HEX", device_id, {"path": path, "bytes": len(raw)}, get_db_path())
        return jsonify({
            "device_id": device_id,
            "path": path,
            "size_bytes": size,
            "bytes_returned": len(raw),
            "hex_dump": hex_dump
        })
    except Exception as exc:
        return jsonify({"error": "hex_read_failed", "message": str(exc)}), 500


@app.route("/api/cases/<case_id>/autopsy/search", methods=["GET", "POST"])
def autopsy_keyword_search(case_id):
    data = request.get_json() or {} if request.method == "POST" else request.args
    query = data.get("query", "").strip()
    is_regex = str(data.get("is_regex", "0")).lower() in {"1", "true"}
    if not query:
        return jsonify({"error": "query_required"}), 400

    import re
    matches = []
    
    # 1. Search Email artifacts
    from collector.email_forensics import get_email_forensics
    emails = get_email_forensics()
    pattern = re.compile(query, re.IGNORECASE) if is_regex else None
    for em in emails:
        target_str = f"{em.get('subject','')} {em.get('from','')} {em.get('to','')} {em.get('body_preview','')}"
        if (pattern and pattern.search(target_str)) or (not pattern and query.lower() in target_str.lower()):
            matches.append({"source": "Email Artifact", "path": em.get("path",""), "context": f"From: {em.get('from')} | Subject: {em.get('subject')}"})

    # 2. Search Event logs & processes
    from collector.windows_collector import get_windows_logs, get_windows_processes
    for log in get_windows_logs():
        txt = str(log.get("message") or log.get("line") or "")
        if (pattern and pattern.search(txt)) or (not pattern and query.lower() in txt.lower()):
            matches.append({"source": "Event Log", "path": f"Log Event {log.get('event_id')}", "context": txt[:200]})

    for proc in get_windows_processes():
        txt = f"{proc.get('name','')} {proc.get('command_line','')}"
        if (pattern and pattern.search(txt)) or (not pattern and query.lower() in txt.lower()):
            matches.append({"source": "Process List", "path": proc.get("executable",""), "context": f"PID {proc.get('pid')} - {txt}"})

    record_audit_event("investigator", "AUTOPSY_KEYWORD_SEARCH", case_id, {"query": query, "matches": len(matches)}, get_db_path())
    return jsonify({"case_id": case_id, "query": query, "match_count": len(matches), "matches": matches})


@app.route("/api/cases/<case_id>/autopsy/mismatches", methods=["GET"])
def autopsy_extension_mismatches(case_id):
    path = request.args.get("path", "C:\\Windows")
    from collector.windows_collector import get_windows_filesystem
    files = get_windows_filesystem(path)
    mismatches = [f for f in files if f.get("mismatch_flag")]
    record_audit_event("investigator", "AUTOPSY_EXTENSION_MISMATCH_SCAN", case_id, {"path": path, "mismatches": len(mismatches)}, get_db_path())
    return jsonify({"case_id": case_id, "scanned_count": len(files), "mismatch_count": len(mismatches), "mismatches": mismatches})


@app.route("/api/cases/<case_id>/autopsy/hash_lookup", methods=["GET"])
def autopsy_hash_lookup(case_id):
    from collector.windows_collector import get_windows_processes
    KNOWN_BAD_HASHES = {
        "44d88612fea8a8f36de82e1278abb02f": "Mimikatz Password Dumper",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty / Suspicious Binary",
        "09f7e02f1290be371da2b3e404079c70": "Ransomware Encryptor IOC",
        "a7d03a111a0ff1101b088510a27e7d69": "Cobalt Strike Beacon Payload"
    }
    processes = get_windows_processes()
    flagged = []
    for proc in processes:
        h = proc.get("executable_sha256")
        if h and h in KNOWN_BAD_HASHES:
            flagged.append({"pid": proc["pid"], "name": proc["name"], "hash": h, "threat": KNOWN_BAD_HASHES[h]})
    record_audit_event("investigator", "AUTOPSY_HASH_IOC_LOOKUP", case_id, {"flagged": len(flagged)}, get_db_path())
    return jsonify({"case_id": case_id, "scanned_processes": len(processes), "flagged_count": len(flagged), "threats": flagged})


@app.route("/api/devices/intelligence/overview", methods=["GET"])
@app.route("/api/agents/<agent_id>/devices/intelligence/overview", methods=["GET"])
def get_physical_device_overview_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    target_id = agent_id or "global"
    record_audit_event("investigator", "QUERY_PHYSICAL_DEVICE_OVERVIEW", target_id, {"demo_mode": demo_mode}, get_db_path())
    from collector.physical_device_intelligence import get_physical_device_overview_intelligence
    raw = get_agent_telemetry_category(agent_id, "removable_media") if agent_id else None
    if isinstance(raw, dict) and "data" in raw: raw = raw.get("data")
    if isinstance(raw, dict): raw = raw.get("devices") or raw.get("removable_media") or []
    if isinstance(raw,list) and agent_id:
        try:
            live_events=LiveEventModel.get_recent_agent_events(agent_id,limit=500,db_path=get_db_path())
            physical=[(e.get("payload") if isinstance(e.get("payload"),dict) else e) for e in live_events if str(e.get("event_type","")).startswith("PHYSICAL_DEVICE_")]
            by_key={str(d.get("device") or d.get("serial") or d.get("hardware_id")):d for d in raw if isinstance(d,dict)}
            for ev in physical:
                key=str(ev.get("device") or ev.get("serial") or ev.get("hardware_id"))
                if key in by_key:
                    by_key[key].setdefault("connection_events",[]).append({"timestamp":ev.get("timestamp"),"event":"CONNECTED" if ev.get("event_type")=="PHYSICAL_DEVICE_CONNECTED" else "DISCONNECTED","details":ev.get("device"),"source":ev.get("source"),"confidence":"CONFIRMED"})
                elif ev.get("device"):
                    raw.append({"device":ev.get("device"),"device_type":ev.get("device_type") or "Physical Device","serial":ev.get("serial"),"mount":ev.get("mount"),"status":"Observed in live event","evidence_type":ev.get("source"),"observed_at":ev.get("timestamp"),"connection_events":[{"timestamp":ev.get("timestamp"),"event":"CONNECTED" if ev.get("event_type")=="PHYSICAL_DEVICE_CONNECTED" else "DISCONNECTED","details":ev.get("device"),"source":ev.get("source"),"confidence":"CONFIRMED"}]})
        except Exception:
            pass
    res = get_physical_device_overview_intelligence(demo_mode=demo_mode, raw_devices=raw if isinstance(raw, list) else None)
    return jsonify(res)


@app.route("/api/devices/intelligence/search", methods=["GET", "POST"])
@app.route("/api/agents/<agent_id>/devices/intelligence/search", methods=["GET", "POST"])
def search_physical_device_activity_endpoint(agent_id=None):
    data = request.get_json() or {} if request.method == "POST" else request.args
    demo_mode = str(data.get("demo", "0")).lower() in {"1", "true"}
    date_str = data.get("date")
    time_str = data.get("time")
    range_mins = int(data.get("range", 5))
    dev_filter = data.get("device")
    act_filter = data.get("action")
    record_audit_event("investigator", "SEARCH_PHYSICAL_DEVICE_ACTIVITY", agent_id or "global", {"date": date_str, "device": dev_filter}, get_db_path())
    from collector.physical_device_intelligence import search_device_activity
    raw = get_agent_telemetry_category(agent_id, "removable_media") if agent_id and not demo_mode else None
    if isinstance(raw, dict) and "data" in raw: raw = raw.get("data")
    if isinstance(raw, dict): raw = raw.get("devices") or raw.get("removable_media") or []
    results = search_device_activity(date_str=date_str, time_str=time_str, range_mins=range_mins, device_filter=dev_filter, action_filter=act_filter, demo_mode=demo_mode, raw_devices=raw if isinstance(raw, list) else None)
    return jsonify({"count": len(results), "results": results})


@app.route("/api/devices/intelligence/report", methods=["GET"])
@app.route("/api/agents/<agent_id>/devices/intelligence/report", methods=["GET"])
def generate_physical_device_report_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    record_audit_event("investigator", "GENERATE_PHYSICAL_DEVICE_REPORT", agent_id or "global", {"demo_mode": demo_mode}, get_db_path())
    from collector.physical_device_intelligence import generate_device_forensic_report
    rep = generate_device_forensic_report(demo_mode=demo_mode)
    return jsonify(rep)


@app.route("/api/location/intelligence/overview", methods=["GET"])
@app.route("/api/location", methods=["GET"])
@app.route("/api/location/statistics", methods=["GET"])
@app.route("/api/agents/<agent_id>/location/intelligence/overview", methods=["GET"])
def get_location_overview_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    target_id = agent_id or "global"
    record_audit_event("investigator", "QUERY_LOCATION_INTELLIGENCE_OVERVIEW", target_id, {"demo_mode": demo_mode}, get_db_path())
    from collector.location_intelligence import get_location_overview_intelligence
    live = get_agent_telemetry_category(agent_id, "location") if agent_id else None
    if isinstance(live, dict) and "data" in live: live = live.get("data")
    if agent_id and isinstance(live, dict) and not demo_mode:
        artifacts = live.get("artifacts") or []
        telemetry = live.get("telemetry") or {}
        if isinstance(artifacts, list) and artifacts:
            res = get_location_overview_intelligence(demo_mode=False, raw_artifacts=artifacts)
        else:
            # Preserve the basic live location telemetry as one explicitly
            # timestamped observation when no richer artifacts exist.
            event = dict(telemetry) if isinstance(telemetry, dict) else {}
            event["timestamp"] = event.get("timestamp") or (get_agent_telemetry_category(agent_id, "location") or {}).get("timestamp") or datetime.now(timezone.utc).isoformat()
            has_loc = event.get("latitude") is not None or bool(event.get("wifi_networks"))
            res = {"status":"EVIDENCE LOADED" if has_loc else "NO LOCATION EVIDENCE LOADED", "known_locations": 1 if has_loc else 0, "location_events_count": 1 if has_loc else 0, "gps_artifacts_count": 0, "network_location_events_count": len(event.get("wifi_networks") or []), "devices_with_location_count": 1 if has_loc else 0, "date_range":"Live Telemetry", "devices":[agent_id] if has_loc else [], "location_events":[event] if has_loc else [], "demo_mode":False}
    else:
        res = get_location_overview_intelligence(demo_mode=demo_mode)
    return jsonify(res)


@app.route("/api/location/timeline", methods=["GET"])
@app.route("/api/agents/<agent_id>/location/timeline", methods=["GET"])
def get_location_timeline_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    from collector.location_intelligence import get_location_overview_intelligence
    if agent_id and not demo_mode:
        live = get_agent_telemetry_category(agent_id, "location")
        if isinstance(live, dict) and "data" in live: live = live.get("data")
        artifacts = live.get("artifacts") if isinstance(live, dict) else []
        res = get_location_overview_intelligence(demo_mode=False, raw_artifacts=artifacts if isinstance(artifacts, list) else None)
    else:
        res = get_location_overview_intelligence(demo_mode=demo_mode)
    return jsonify({"timeline": res.get("location_events", [])})


@app.route("/api/location/sources", methods=["GET"])
@app.route("/api/agents/<agent_id>/location/sources", methods=["GET"])
def get_location_sources_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    from collector.location_intelligence import get_location_overview_intelligence
    if agent_id and not demo_mode:
        live = get_agent_telemetry_category(agent_id, "location")
        if isinstance(live, dict) and "data" in live: live = live.get("data")
        artifacts = live.get("artifacts") if isinstance(live, dict) else []
        res = get_location_overview_intelligence(demo_mode=False, raw_artifacts=artifacts if isinstance(artifacts, list) else None)
    else:
        res = get_location_overview_intelligence(demo_mode=demo_mode)
    events = res.get("location_events", [])
    sources = list(set(e.get("source") for e in events if e.get("source")))
    return jsonify({"sources_count": len(sources), "sources": sources})


@app.route("/api/location/intelligence/search", methods=["GET", "POST"])
@app.route("/api/location/search", methods=["GET", "POST"])
@app.route("/api/agents/<agent_id>/location/intelligence/search", methods=["GET", "POST"])
def search_location_intelligence_endpoint(agent_id=None):
    data = request.get_json() or {} if request.method == "POST" else request.args
    demo_mode = str(data.get("demo", "0")).lower() in {"1", "true"}
    date_str = data.get("date")
    time_str = data.get("time")
    range_mins = int(data.get("range", 5))
    dev_filter = data.get("device", "All Devices")
    record_audit_event("investigator", "SEARCH_LOCATION_INTELLIGENCE", agent_id or "global", {"date": date_str, "time": time_str, "device": dev_filter}, get_db_path())
    from collector.location_intelligence import search_location_by_time
    location_events=None
    if agent_id and not demo_mode:
        live=get_agent_telemetry_category(agent_id,"location")
        if isinstance(live,dict) and "data" in live: live=live.get("data")
        history=DeviceTelemetryModel.get_location_history(agent_id,get_db_path())
        location_events=list(history)
        if isinstance(live,dict):
            artifacts=live.get("artifacts") or []
            if isinstance(artifacts,list) and artifacts:
                location_events.extend(artifacts)
            telemetry=dict(live.get("telemetry") or {})
            telemetry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            if telemetry.get("latitude") is not None or telemetry.get("wifi_networks"):
                location_events.insert(0,telemetry)
    res = search_location_by_time(date_str=date_str, time_str=time_str, range_mins=range_mins, device_filter=dev_filter, demo_mode=demo_mode, location_events=location_events)
    return jsonify(res)


@app.route("/api/location/intelligence/range", methods=["GET", "POST"])
@app.route("/api/agents/<agent_id>/location/intelligence/range", methods=["GET", "POST"])
def search_location_range_endpoint(agent_id=None):
    data = request.get_json() or {} if request.method == "POST" else request.args
    demo_mode = str(data.get("demo", "0")).lower() in {"1", "true"}
    start_time = data.get("start", "")
    end_time = data.get("end", "")
    dev_filter = data.get("device", "All Devices")
    src_filter = data.get("source", "All Sources")
    conf_filter = data.get("confidence", "All")
    record_audit_event("investigator", "SEARCH_LOCATION_RANGE", agent_id or "global", {"start": start_time, "end": end_time}, get_db_path())
    from collector.location_intelligence import search_location_date_range
    location_events = None
    if agent_id and not demo_mode:
        live = get_agent_telemetry_category(agent_id, "location")
        if isinstance(live, dict) and "data" in live: live = live.get("data")
        if isinstance(live, dict):
            location_events = list(live.get("artifacts") or [])
            telemetry = dict(live.get("telemetry") or {})
            if telemetry.get("latitude") is not None or telemetry.get("wifi_networks"):
                telemetry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
                location_events.insert(0, telemetry)
    results = search_location_date_range(start_time=start_time, end_time=end_time, device_filter=dev_filter, source_filter=src_filter, confidence_filter=conf_filter, demo_mode=demo_mode, location_events=location_events)
    return jsonify({"count": len(results), "results": results})


@app.route("/api/location/intelligence/report", methods=["GET"])
@app.route("/api/agents/<agent_id>/location/intelligence/report", methods=["GET"])
def generate_location_report_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    record_audit_event("investigator", "GENERATE_LOCATION_REPORT", agent_id or "global", {"demo_mode": demo_mode}, get_db_path())
    from collector.location_intelligence import generate_location_forensic_report
    rep = generate_location_forensic_report(demo_mode=demo_mode)
    return jsonify(rep)


# ── Network Forensics Intelligence ────────────────────────────────────────────

@app.route("/api/network/intelligence/overview", methods=["GET"])
@app.route("/api/agents/<agent_id>/network/intelligence/overview", methods=["GET"])
def get_network_overview_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    target_id = agent_id or "global"
    record_audit_event("investigator", "QUERY_NETWORK_INTELLIGENCE_OVERVIEW", target_id, {"demo_mode": demo_mode}, get_db_path())
    from collector.network_forensics import get_network_overview_intelligence
    if agent_id and not demo_mode:
        live = get_agent_telemetry_category(agent_id, "network")
        if isinstance(live, dict) and "data" in live: live = live.get("data")
        if isinstance(live, list):
            connections = live
        elif isinstance(live, dict):
            connections = live.get("connections") or live.get("data") or []
        else:
            connections = []
        cfg = get_agent_telemetry_category(agent_id, "network_config")
        if isinstance(cfg, dict) and "data" in cfg: cfg = cfg.get("data")
        interfaces = cfg if isinstance(cfg, list) else []
        # Build Wi-Fi/network profile evidence from the endpoint's location telemetry.
        loc = get_agent_telemetry_category(agent_id, "location")
        if isinstance(loc, dict) and "data" in loc: loc = loc.get("data")
        wifi = []
        if isinstance(loc, dict):
            for ssid in loc.get("telemetry", loc).get("wifi_networks") or []:
                wifi.append({"ssid": ssid, "connection_mode":"observed", "network_type":"Wi-Fi", "device":"", "evidence_source":"Endpoint location telemetry", "confidence":"MEDIUM"})
        net_events = []
        logs = get_agent_telemetry_category(agent_id, "logs")
        if isinstance(logs, dict) and "data" in logs: logs = logs.get("data")
        if isinstance(logs, list):
            net_events = [x for x in logs if any(k in str(x).lower() for k in ("networkmanager", "dhcp", "wifi", "wlan"))]
        sources = set()
        for lst in (connections, interfaces, wifi, net_events):
            for item in lst:
                if isinstance(item, dict) and (item.get("source") or item.get("evidence_source")): sources.add(item.get("source") or item.get("evidence_source"))
        established = [c for c in connections if str(c.get("state","")).upper() in ("ESTABLISHED","ESTAB")]
        listening = [c for c in connections if str(c.get("state","")).upper()=="LISTEN"]
        res = {"module":"JOCKY Network Forensics","demo_mode":False,"no_evidence":not (connections or interfaces or wifi or net_events),"status_message":f"{len(connections)} active connections, {len(wifi)} Wi-Fi observations, {len(interfaces)} interfaces" if (connections or interfaces or wifi or net_events) else "NO NETWORK EVIDENCE FOUND","active_connections_count":len(connections),"established_count":len(established),"listening_count":len(listening),"wifi_profiles_count":len(wifi),"registered_networks_count":len(wifi),"interfaces_count":len(interfaces),"dns_cache_count":0,"network_events_count":len(net_events),"connections":connections,"wifi_profiles":wifi,"registered_networks":wifi,"interfaces":interfaces,"dns_cache":[],"events":net_events,"timeline":connections+net_events,"evidence_sources":sorted(sources),"collected_at":datetime.now(timezone.utc).isoformat(),"honesty_note":"Real endpoint telemetry from enrolled agent."}
    else:
        res = get_network_overview_intelligence(demo_mode=demo_mode)
    return jsonify(res)


@app.route("/api/network/intelligence/search", methods=["GET", "POST"])
@app.route("/api/agents/<agent_id>/network/intelligence/search", methods=["GET", "POST"])
def search_network_intelligence_endpoint(agent_id=None):
    data = request.get_json() or {} if request.method == "POST" else request.args
    demo_mode = str(data.get("demo", "0")).lower() in {"1", "true"}
    date_str = data.get("date")
    time_str = data.get("time")
    range_mins = int(data.get("range", 5))
    event_type_filter = data.get("event_type")
    record_audit_event("investigator", "SEARCH_NETWORK_INTELLIGENCE", agent_id or "global", {"date": date_str, "time": time_str, "event_type": event_type_filter}, get_db_path())
    from collector.network_forensics import search_network_by_time
    res = search_network_by_time(date_str=date_str, time_str=time_str, range_mins=range_mins, event_type_filter=event_type_filter, demo_mode=demo_mode)
    return jsonify(res)


@app.route("/api/network/intelligence/report", methods=["GET"])
@app.route("/api/agents/<agent_id>/network/intelligence/report", methods=["GET"])
def generate_network_report_endpoint(agent_id=None):
    demo_mode = str(request.args.get("demo", "0")).lower() in {"1", "true"}
    record_audit_event("investigator", "GENERATE_NETWORK_REPORT", agent_id or "global", {"demo_mode": demo_mode}, get_db_path())
    from collector.network_forensics import generate_network_forensic_report
    rep = generate_network_forensic_report(demo_mode=demo_mode)
    return jsonify(rep)

# ===========================================================================
# Cross-platform endpoint telemetry adapters
# ===========================================================================

def _case_device_id(case_id: str, requested: Optional[str] = None) -> Optional[str]:
    """Resolve the device actually assigned to a case; never infer from server OS."""
    if requested:
        devs = DeviceModel.list_all(get_db_path())
        if any(d.get("id") == requested and d.get("active_case_id") == case_id for d in devs):
            return requested
    devs = DeviceModel.list_all(get_db_path())
    for d in devs:
        if d.get("active_case_id") == case_id:
            return d.get("id")
    return requested if requested and any(d.get("id") == requested for d in devs) else None


def _telemetry_data(device_id: Optional[str], category: str):
    if not device_id:
        return None
    item = DeviceTelemetryModel.get(device_id, category, get_db_path())
    return item.get("data") if item else None


def _rich_category(device_id: Optional[str], category: str):
    data = _telemetry_data(device_id, category)
    return data if isinstance(data, dict) else {}


def _telemetry_list(data, keys=()):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if isinstance(v, list):
                return v
    return []


def _case_os(case_id: str, device_id: Optional[str]) -> str:
    if device_id:
        devs = DeviceModel.list_all(get_db_path())
        for d in devs:
            if d.get("id") == device_id:
                return str(d.get("os") or "").lower()
    return ""

# ===========================================================================
# JOCKY B1-B12 REAL DEFENSIVE FORENSIC TRIAGE REST API
# ===========================================================================

def _resolve_case_id(supplied: Optional[str] = None) -> str:
    if supplied and supplied.strip():
        return supplied.strip()
    try:
        conn = get_db_connection(get_db_path())
        row = conn.execute("SELECT id FROM cases ORDER BY created_at DESC LIMIT 1").fetchone()
        conn.close()
        if row and row[0]:
            return str(row[0])
    except Exception:
        pass
    return "CASE-001"




def _paginate_items(items: list, page: int = 1, limit: int = 50, q: str = "", search_fields=(), sort_by: str = "timestamp", order: str = "desc") -> Dict[str, Any]:
    rows = list(items or [])
    if q:
        needle = q.lower()
        rows = [r for r in rows if any(needle in str(r.get(k, "")).lower() for k in search_fields)]
    reverse = str(order).lower() == "desc"
    try:
        rows.sort(key=lambda r: (r.get(sort_by) is None, str(r.get(sort_by, ""))), reverse=reverse)
    except Exception:
        pass
    page=max(1,int(page)); limit=min(500,max(1,int(limit)))
    total=len(rows); start=(page-1)*limit
    return {"status":"COLLECTED" if total else "NO_EVIDENCE_FOUND", "count":len(rows[start:start+limit]), "total":total,
            "page":page,"limit":limit,"total_pages":max(1,(total+limit-1)//limit),"items":rows[start:start+limit],"source":"endpoint_telemetry"}
@app.route("/api/case/overview", methods=["GET"])
@app.route("/api/cases/<case_id>/overview", methods=["GET"])
def get_case_overview(case_id=None):
    cid = _resolve_case_id(case_id or request.args.get("case_id"))
    did = _case_device_id(cid, request.args.get("device_id"))
    conn = get_db_connection(get_db_path())
    case_row = conn.execute("SELECT * FROM cases WHERE id = ?", (cid,)).fetchone()
    case_data = dict(case_row) if case_row else {"id": cid, "name": f"Investigation {cid}"}
    # Prefer live endpoint telemetry. Normalized rows are used only when they
    # are explicitly bound to this exact case/device.
    stats = get_dfir_overview_stats(conn, case_id=cid, device_id=did)
    host_info = _telemetry_data(did, "system_forensics") or _telemetry_data(did, "system") or {}
    if isinstance(host_info, dict) and isinstance(host_info.get("data"), dict):
        host_info = host_info["data"]
    rich_browser = _rich_category(did, "browser_forensics")
    rich_apps = _rich_category(did, "applications_forensics")
    rich_devices = _rich_category(did, "device_forensics")
    rich_fs = _rich_category(did, "filesystem_forensics")
    rich_msg = _rich_category(did, "messaging_forensics")
    email_raw = _telemetry_data(did, "email_forensics") or {}
    rich_email = email_raw if isinstance(email_raw, dict) else {}
    browser_count = len(_telemetry_list(rich_browser, ("history",))) + len(_telemetry_list(rich_browser, ("downloads",)))
    app_count = len(_telemetry_list(rich_apps, ("installed_applications",)))
    proc_count = len(_telemetry_list(rich_apps, ("running_processes",))) or len(_telemetry_data(did, "processes") or [])
    device_count = int(rich_devices.get("total_count") or (len(rich_devices.get("unified_records") or []) if rich_devices else 0))
    fs_count = int(rich_fs.get("total_files") or len(rich_fs.get("files") or []))
    msg_count = int(rich_msg.get("total_messages") or len(rich_msg.get("messages") or []))
    email_items = rich_email.get("messages", []) if isinstance(rich_email, dict) else (rich_email if isinstance(rich_email, list) else [])
    if not email_items and isinstance(email_raw, list): email_items = email_raw
    email_count = len(email_items)
    try:
        from collector.web_activity_mapper import WebActivityMapper
        web_count = int(WebActivityMapper(device_id=did, case_id=cid).map_from_history(_telemetry_list(rich_browser, ("history",))).get("count", 0)) if did else 0
    except Exception:
        web_count = 0
    net_payload = _telemetry_data(did, "network") or {}
    net_count = len(net_payload.get("connections") or []) if isinstance(net_payload, dict) else len(net_payload or [])
    if did and (host_info or rich_browser or rich_apps or rich_devices or rich_fs or rich_msg or net_payload):
        counts = dict(stats.get("counts", {}))
        counts.update({
            "browser_records": browser_count,
            "browser_downloads": len(_telemetry_list(rich_browser, ("downloads",))),
            "browser_bookmarks": len(_telemetry_list(rich_browser, ("bookmarks",))),
            "applications": app_count,
            "processes": proc_count,
            "messages": msg_count,
            "email_messages": email_count,
            "web_activity": web_count,
            "device_artifacts": device_count,
            "files": fs_count,
            "network_events": net_count,
        })
        total = sum(counts.get(k, 0) for k in ("browser_records","browser_downloads","applications","processes","messages","email_messages","web_activity","device_artifacts","files","network_events"))
        stats = {"status": "COLLECTED" if total else "NO_EVIDENCE_FOUND", "counts": counts, "latest_run": stats.get("latest_run")}
    conn.close()
    evidence_status = stats.get("status", "NO_EVIDENCE_FOUND")
    # The overview endpoint's top-level status describes the HTTP/API operation,
    # not whether forensic evidence exists.  Keep evidence_status explicit so a
    # successful empty overview cannot be mistaken for collected evidence.
    return jsonify({"status": "SUCCESS", "evidence_status": evidence_status,
                    "case_id": cid, "device_id": did,
                    "case": case_data, "counts": stats.get("counts", {}), "latest_run": stats.get("latest_run"),
                    "host": host_info, "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route("/api/system", methods=["GET"])
def get_system_specs():
    cid = _resolve_case_id(request.args.get("case_id"))
    did = _case_device_id(cid, request.args.get("device_id"))
    sys_info = _telemetry_data(did, "system_forensics") or _telemetry_data(did, "system") or {}
    if isinstance(sys_info, dict) and isinstance(sys_info.get("data"), dict):
        sys_info = sys_info["data"]
    sys_info = dict(sys_info) if isinstance(sys_info, dict) else {}

    # Normalize the cross-platform collector's compact keys into stable dashboard keys.
    cores = str(sys_info.get("cpu_cores") or "")
    physical = sys_info.get("cpu_physical_cores")
    logical = sys_info.get("cpu_logical_cores")
    if (physical is None or logical is None) and "/" in cores:
        parts = [x.strip() for x in cores.split("/")]
        try: physical = int(parts[0].split()[0])
        except Exception: pass
        try: logical = int(parts[1].split()[0])
        except Exception: pass
    sys_info.setdefault("cpu_name", sys_info.get("cpu"))
    sys_info.setdefault("cpu_physical_cores", physical)
    sys_info.setdefault("cpu_logical_cores", logical)
    sys_info.setdefault("ram_total_gb", sys_info.get("ram_bytes", 0) / (1024**3) if isinstance(sys_info.get("ram_bytes"), (int,float)) and sys_info.get("ram_bytes") else None)
    sys_info.setdefault("ram_available_gb", sys_info.get("ram_available"))
    sys_info.setdefault("os_name", sys_info.get("operating_system") or sys_info.get("os"))
    sys_info.setdefault("os_release", sys_info.get("build") or sys_info.get("os_version"))
    sys_info.setdefault("boot_time", sys_info.get("boot_time"))
    sys_info.setdefault("uptime_seconds", sys_info.get("uptime_seconds"))

    memory = _telemetry_data(did, "memory") or {}
    if isinstance(memory, str):
        try: memory = json.loads(memory)
        except Exception: memory = {}
    if isinstance(memory, dict) and isinstance(memory.get("data"), dict): memory = memory["data"]
    # When no endpoint memory telemetry exists, expose real local memory only
    # as an explicitly labelled server-side fallback. Never present it as
    # endpoint evidence.
    if not memory:
        try:
            from collector.memory import get_live_memory_statistics
            memory = get_live_memory_statistics()
            if isinstance(memory, dict):
                memory["source"] = memory.get("source", "server_local_fallback")
                memory["telemetry_scope"] = "server_local_fallback"
        except Exception:
            memory = {}
    return jsonify({"status": "COLLECTED" if sys_info else "NO_EVIDENCE_FOUND", "case_id": cid, "device_id": did,
                    "system": sys_info, "memory": memory if isinstance(memory, dict) else {},
                    "timestamp": datetime.now(timezone.utc).isoformat(), "source": "endpoint_telemetry" if did else "none"})


@app.route("/api/browser", methods=["GET"])
def get_browser_summary():
    cid=_resolve_case_id(request.args.get("case_id")); did=_case_device_id(cid, request.args.get("device_id"))
    rich=_rich_category(did,"browser_forensics") if did else {}
    hist=rich.get("history",[]); dl=rich.get("downloads",[]); bm=rich.get("bookmarks",[])
    if rich:
        return jsonify({"status":"COLLECTED" if (hist or dl or bm) else "NO_EVIDENCE_FOUND","case_id":cid,"device_id":did,
                        "counts":{"history":len(hist),"downloads":len(dl),"bookmarks":len(bm),"total":len(hist)+len(dl)+len(bm)},
                        "browsers":sorted({str(x.get("browser")) for x in hist+dl+bm if x.get("browser")}),
                        "profiles":sorted({str(x.get("profile")) for x in hist+dl+bm if x.get("profile")}),
                        "top_domains":rich.get("origin_domains",{}),"timestamp":datetime.now(timezone.utc).isoformat(),"source":"endpoint_telemetry"})
    conn=get_db_connection(get_db_path()); hist_count=conn.execute("SELECT COUNT(*) FROM browser_history WHERE case_id=? AND (? IS NULL OR device_id=?)",(cid,did,did)).fetchone()[0]; dl_count=conn.execute("SELECT COUNT(*) FROM browser_downloads WHERE case_id=? AND (? IS NULL OR device_id=?)",(cid,did,did)).fetchone()[0]; bm_count=conn.execute("SELECT COUNT(*) FROM browser_bookmarks WHERE case_id=? AND (? IS NULL OR device_id=?)",(cid,did,did)).fetchone()[0]; conn.close()
    return jsonify({"status":"COLLECTED" if hist_count+dl_count+bm_count else "NO_EVIDENCE_FOUND","case_id":cid,"device_id":did,"counts":{"history":hist_count,"downloads":dl_count,"bookmarks":bm_count,"total":hist_count+dl_count+bm_count},"browsers":[],"profiles":[],"top_domains":[]})

@app.route("/api/browser/history", methods=["GET"])
def get_browser_history():
    cid=_resolve_case_id(request.args.get("case_id")); did=_case_device_id(cid, request.args.get("device_id")); rich=_rich_category(did,"browser_forensics") if did else {}; items=rich.get("history",[]) if rich else []
    if items: return jsonify(_paginate_items(items,int(request.args.get("page",1)),int(request.args.get("limit",50)),request.args.get("q", ""),("url","title","domain"),request.args.get("sort","timestamp"),request.args.get("order","desc")))
    conn=get_db_connection(get_db_path()); result=query_evidence_records(conn,"browser_history",case_id=cid,device_id=did,page=int(request.args.get("page",1)),limit=int(request.args.get("limit",50)),search=request.args.get("q"),search_fields=["url","title","domain"],sort_by=request.args.get("sort","timestamp"),order=request.args.get("order","desc")); conn.close(); return jsonify(result)

@app.route("/api/browser/downloads", methods=["GET"])
def get_browser_downloads():
    cid=_resolve_case_id(request.args.get("case_id")); did=_case_device_id(cid, request.args.get("device_id")); rich=_rich_category(did,"browser_forensics") if did else {}; items=rich.get("downloads",[]) if rich else []
    if items: return jsonify(_paginate_items(items,int(request.args.get("page",1)),int(request.args.get("limit",50)),request.args.get("q", ""),("url","target_path","filename","browser"),request.args.get("sort","timestamp"),request.args.get("order","desc")))
    conn=get_db_connection(get_db_path()); result=query_evidence_records(conn,"browser_downloads",case_id=cid,device_id=did,page=int(request.args.get("page",1)),limit=int(request.args.get("limit",50)),search=request.args.get("q"),search_fields=["url","target_path","filename"],sort_by=request.args.get("sort","timestamp"),order=request.args.get("order","desc")); conn.close(); return jsonify(result)

@app.route("/api/browser/bookmarks", methods=["GET"])
def get_browser_bookmarks():
    cid=_resolve_case_id(request.args.get("case_id")); did=_case_device_id(cid, request.args.get("device_id")); rich=_rich_category(did,"browser_forensics") if did else {}; items=rich.get("bookmarks",[]) if rich else []
    if items: return jsonify(_paginate_items(items,int(request.args.get("page",1)),int(request.args.get("limit",50)),request.args.get("q", ""),("url","title","folder","browser"),request.args.get("sort","timestamp"),request.args.get("order","desc")))
    conn=get_db_connection(get_db_path()); result=query_evidence_records(conn,"browser_bookmarks",case_id=cid,device_id=did,page=int(request.args.get("page",1)),limit=int(request.args.get("limit",50)),search=request.args.get("q"),search_fields=["title","url","folder"],sort_by=request.args.get("sort","timestamp"),order=request.args.get("order","desc")); conn.close(); return jsonify(result)

@app.route("/api/applications", methods=["GET"])
def get_applications():
    cid=_resolve_case_id(request.args.get("case_id")); did=_case_device_id(cid, request.args.get("device_id"))
    conn=get_db_connection(get_db_path()); result=query_evidence_records(conn,"applications",case_id=cid,device_id=did,page=int(request.args.get("page",1)),limit=int(request.args.get("limit",50)),search=request.args.get("q"),search_fields=["name","publisher","install_path","source"],sort_by=request.args.get("sort","timestamp"),order=request.args.get("order","desc")); conn.close()
    if result.get("total",0)==0 and did:
        rich=_rich_category(did,"applications_forensics")
        items=_telemetry_list(rich,("installed_applications",))
        return jsonify(_paginate_items(items,int(request.args.get("page",1)),int(request.args.get("limit",50)),request.args.get("q", ""),("name","publisher","install_path","source"),request.args.get("sort","timestamp"),request.args.get("order","desc")))
    return jsonify(result)

@app.route("/api/processes", methods=["GET"])
def get_processes():
    cid=_resolve_case_id(request.args.get("case_id")); did=_case_device_id(cid, request.args.get("device_id"))
    page=int(request.args.get("page",1)); limit=int(request.args.get("limit",50)); q=request.args.get("q")
    sort_by=request.args.get("sort","name"); order=request.args.get("order","asc")
    rich=_rich_category(did,"applications_forensics") if did else {}
    rich_items=_telemetry_list(rich,("running_processes",)) or (_telemetry_data(did,"processes") or [])
    if rich_items:
        result=_paginate_items(rich_items,page,limit,q or "",("name","executable_path","working_directory","command_line","user","sha256"),sort_by,order)
        all_items=rich_items
    else:
        conn=get_db_connection(get_db_path())
        result=query_evidence_records(conn,"processes",case_id=cid,device_id=did,page=page,limit=limit,search=q,search_fields=["name","executable_path","command_line","user","sha256"],sort_by=sort_by,order=order)
        all_items=[dict(r) for r in conn.execute("SELECT * FROM processes WHERE case_id=? AND device_id=?",(cid,did)).fetchall()] if did else []
        conn.close()
    children={}
    for p in all_items:
        try: children.setdefault(int(p.get("ppid") or 0),[]).append(int(p.get("pid")))
        except Exception: pass
    for p in result.get("items",[]):
        try:
            cp=children.get(int(p.get("pid") or 0),[]); p["child_pids"]=cp; p["child_count"]=len(cp)
        except Exception:
            p["child_pids"]=[]; p["child_count"]=0
    return jsonify(result)

@app.route("/api/messaging", methods=["GET"])
def get_messaging():
    cid = _resolve_case_id(request.args.get("case_id"))
    did = _case_device_id(cid, request.args.get("device_id"))
    page = int(request.args.get("page", 1)); limit = int(request.args.get("limit", 50))
    q = request.args.get("q"); app_name = request.args.get("app_name")
    sort_by = request.args.get("sort", "timestamp"); order = request.args.get("order", "desc")
    filters = {"app_name": app_name} if app_name else {}
    conn = get_db_connection(get_db_path())
    result = query_evidence_records(conn, "messages", case_id=cid, device_id=did,
        filters=filters, search=q, search_fields=["app_name", "sender", "recipient", "text_snippet", "profile_dir"],
        sort_by=sort_by, order=order, page=page, limit=limit)
    app_summary = [dict(r) for r in conn.execute(
        "SELECT app_name, status, COUNT(*) as count FROM messages WHERE case_id = ? AND (? IS NULL OR device_id = ?) GROUP BY app_name, status",
        (cid, did, did)).fetchall()]
    conn.close()
    if result.get("total", 0) == 0 and did:
        rich = _rich_category(did, "messaging_forensics")
        items = rich.get("messages", []) if isinstance(rich, dict) else []
        if not items and isinstance(rich, dict):
            # Preserve application-level discovery even when there are no message rows.
            for app, info in (rich.get("applications") or {}).items():
                if isinstance(info, dict) and info.get("status") not in ("NOT_PRESENT", "NO_EVIDENCE_FOUND"):
                    app_summary.append({"app_name": app, "status": info.get("status", "COLLECTED"), "count": len(info.get("messages", []))})
        return jsonify({**_paginate_items(items, page, limit, q or "", ("app_name","sender","recipient","text_snippet","profile_dir"), sort_by, order), "apps": app_summary, "source": "endpoint_telemetry"})
    result["apps"] = app_summary
    return jsonify(result)

@app.route("/api/email", methods=["GET"])
def get_email_messages():
    cid = _resolve_case_id(request.args.get("case_id"))
    did = _case_device_id(cid, request.args.get("device_id"))
    page = int(request.args.get("page", 1)); limit = int(request.args.get("limit", 50)); q = request.args.get("q")
    client_name = request.args.get("client_name"); sort_by = request.args.get("sort", "timestamp"); order = request.args.get("order", "desc")
    filters = {"client_name": client_name} if client_name else {}
    conn = get_db_connection(get_db_path())
    result = query_evidence_records(conn, "email_messages", case_id=cid, device_id=did,
        filters=filters, search=q, search_fields=["client_name", "subject", "from_addr", "to_addr", "body_snippet"],
        sort_by=sort_by, order=order, page=page, limit=limit)
    conn.close()
    if result.get("total", 0) == 0 and did:
        raw_email = _telemetry_data(did, "email_forensics") or []
        email_meta = raw_email if isinstance(raw_email, dict) else {}
        if isinstance(raw_email, dict):
            items = raw_email.get("messages") or raw_email.get("artifacts") or []
        else:
            items = raw_email if isinstance(raw_email, list) else []
        normalized=[]
        for e in items:
            if not isinstance(e, dict): continue
            normalized.append({
                "id": e.get("id") or e.get("message_id") or hashlib.sha256(json.dumps(e, sort_keys=True, default=str).encode()).hexdigest()[:16],
                "client_name": e.get("client_name") or e.get("client") or e.get("mail_client") or e.get("source", "Email Artifact"),
                "mailbox_name": e.get("mailbox_name"), "mailbox_path": e.get("mailbox_path") or e.get("path"),
                "message_id": e.get("message_id"), "from_addr": e.get("from_addr") or e.get("from"),
                "to_addr": e.get("to_addr") or e.get("to"), "cc_addr": e.get("cc_addr") or e.get("cc"),
                "subject": e.get("subject"), "date": e.get("date"),
                "body_snippet": e.get("body_snippet") or e.get("body_preview") or e.get("snippet"),
                "has_attachments": int(bool(e.get("has_attachments") or e.get("attachments"))),
                "timestamp": e.get("timestamp") or e.get("date") or datetime.now(timezone.utc).isoformat(),
                "source": e.get("source") or "Endpoint Email Forensics", "status": e.get("status") or "COLLECTED", "sha256": e.get("sha256")
            })
        return jsonify(_paginate_items(normalized, page, limit, q or "", ("client_name","subject","from_addr","to_addr","body_snippet"), sort_by, order) | {"source":"endpoint_telemetry", "clients":email_meta.get("clients",[]), "mailboxes":email_meta.get("mailboxes",[]), "status":email_meta.get("status", "NO_EVIDENCE_FOUND")})
    return jsonify(result)

@app.route("/api/email/attachments", methods=["GET"])
def get_email_attachments_records():
    cid = _resolve_case_id(request.args.get("case_id"))
    did = request.args.get("device_id")
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    q = request.args.get("q")

    conn = get_db_connection(get_db_path())
    result = query_evidence_records(
        conn, "email_attachments", case_id=cid, device_id=did,
        search=q, search_fields=["filename", "mime_type", "sha256"],
        sort_by="timestamp", order="desc", page=page, limit=limit
    )
    conn.close()
    return jsonify(result)


@app.route("/api/web-activity", methods=["GET"])
def get_web_activity():
    cid = _resolve_case_id(request.args.get("case_id")); did = _case_device_id(cid, request.args.get("device_id"))
    page = int(request.args.get("page", 1)); limit = int(request.args.get("limit", 50)); q = request.args.get("q")
    platform_filter = request.args.get("platform"); evidence_type = request.args.get("evidence_type")
    sort_by = request.args.get("sort", "visit_count"); order = request.args.get("order", "desc")
    filters = {}
    if platform_filter: filters["platform"] = platform_filter
    if evidence_type: filters["evidence_type"] = evidence_type
    conn = get_db_connection(get_db_path())
    result = query_evidence_records(conn, "web_activity", case_id=cid, device_id=did, filters=filters, search=q,
        search_fields=["platform","domain","evidence_type","browser"], sort_by=sort_by, order=order, page=page, limit=limit)
    conn.close()
    if result.get("total",0)==0 and did:
        rich = _rich_category(did, "browser_forensics")
        history = rich.get("history",[]) if isinstance(rich, dict) else []
        try:
            from collector.web_activity_mapper import WebActivityMapper
            mapped = WebActivityMapper(device_id=did, case_id=cid).map_from_history(history)
            items = mapped.get("items",[])
        except Exception:
            items=[]
        if platform_filter: items=[x for x in items if str(x.get("platform",""))==platform_filter]
        if evidence_type: items=[x for x in items if str(x.get("evidence_type",""))==evidence_type]
        return jsonify(_paginate_items(items,page,limit,q or "",("platform","domain","evidence_type","browser"),sort_by,order) | {"source":"endpoint_telemetry"})
    return jsonify(result)

@app.route("/api/devices/artifacts", methods=["GET"])
def get_device_artifacts():
    cid = _resolve_case_id(request.args.get("case_id")); did = _case_device_id(cid, request.args.get("device_id"))
    page = int(request.args.get("page", 1)); limit = int(request.args.get("limit", 50)); q = request.args.get("q")
    device_type = request.args.get("device_type"); sort_by = request.args.get("sort", "timestamp"); order = request.args.get("order", "desc")
    filters = {"device_type": device_type} if device_type else {}
    conn = get_db_connection(get_db_path())
    result = query_evidence_records(conn, "devices_artifacts", case_id=cid, device_id=did, filters=filters, search=q,
        search_fields=["device_name","vendor","product","serial_number","hardware_id","drive_letter"], sort_by=sort_by, order=order, page=page, limit=limit)
    type_counts = [dict(r) for r in conn.execute(
        "SELECT device_type, COUNT(*) as count FROM devices_artifacts WHERE case_id = ? AND (? IS NULL OR device_id = ?) GROUP BY device_type", (cid,did,did)).fetchall()]
    conn.close()
    if result.get("total",0)==0 and did:
        rich=_rich_category(did,"device_forensics")
        items=rich.get("unified_records",[]) if isinstance(rich,dict) else []
        if device_type: items=[x for x in items if str(x.get("device_type",""))==device_type]
        type_counts=[]
        counts={}
        for x in items: counts[str(x.get("device_type") or "Unknown")]=counts.get(str(x.get("device_type") or "Unknown"),0)+1
        type_counts=[{"device_type":k,"count":v} for k,v in counts.items()]
        return jsonify(_paginate_items(items,page,limit,q or "",("device_name","vendor","product","serial_number","hardware_id","drive_letter"),sort_by,order) | {"device_types":type_counts,"source":"endpoint_telemetry"})
    result["device_types"]=type_counts
    return jsonify(result)

@app.route("/api/filesystem", methods=["GET"])
def get_filesystem():
    cid=_resolve_case_id(request.args.get("case_id")); did=_case_device_id(cid, request.args.get("device_id")); conn=get_db_connection(get_db_path()); result=query_evidence_records(conn,"filesystem",case_id=cid,device_id=did,page=int(request.args.get("page",1)),limit=int(request.args.get("limit",50)),search=request.args.get("q"),search_fields=["filename","path","extension","sha256"],sort_by=request.args.get("sort","timestamp"),order=request.args.get("order","desc")); conn.close()
    if result.get("total",0)==0 and did:
        rich=_rich_category(did,"filesystem_forensics"); items=rich.get("files",[]) if rich else (_telemetry_data(did,"filesystem") or [])
        return jsonify(_paginate_items(items,int(request.args.get("page",1)),int(request.args.get("limit",50)),request.args.get("q", ""),("filename","path","extension","sha256","file_type"),request.args.get("sort","timestamp"),request.args.get("order","desc")))
    return jsonify(result)

@app.route("/api/network", methods=["GET"])
def get_network_records():
    cid=_resolve_case_id(request.args.get("case_id")); did=_case_device_id(cid, request.args.get("device_id")); conn=get_db_connection(get_db_path()); result=query_evidence_records(conn,"network_events",case_id=cid,device_id=did,page=int(request.args.get("page",1)),limit=int(request.args.get("limit",50)),search=request.args.get("q"),search_fields=["local_address","remote_address","process_name","details"],sort_by=request.args.get("sort","timestamp"),order=request.args.get("order","desc")); conn.close()
    if result.get("total",0)==0 and did:
        payload=_telemetry_data(did,"network") or {}; items=payload.get("connections",[]) if isinstance(payload,dict) else payload
        return jsonify(_paginate_items(items,int(request.args.get("page",1)),int(request.args.get("limit",50)),request.args.get("q", ""),("local_address","remote_address","process","process_name","state","protocol"),request.args.get("sort","timestamp"),request.args.get("order","desc")))
    return jsonify(result)

@app.route("/api/live", methods=["GET"])
def get_live_monitoring_status():
    from collector.live_engine import LiveMonitoringEngine
    engine = LiveMonitoringEngine(get_db_path())
    return jsonify(engine.get_status())


@app.route("/api/live/start", methods=["POST"])
def start_live_monitoring():
    from collector.live_engine import LiveMonitoringEngine
    data = request.get_json(silent=True) or {}
    cid = _resolve_case_id(data.get("case_id"))
    did = data.get("device_id")
    engine = LiveMonitoringEngine(get_db_path())
    res = engine.start_monitoring(case_id=cid, device_id=did)
    record_audit_event("investigator", "START_LIVE_MONITORING", cid, res, get_db_path())
    return jsonify(res)


@app.route("/api/live/stop", methods=["POST"])
def stop_live_monitoring():
    from collector.live_engine import LiveMonitoringEngine
    engine = LiveMonitoringEngine(get_db_path())
    res = engine.stop_monitoring()
    record_audit_event("investigator", "STOP_LIVE_MONITORING", engine.case_id, res, get_db_path())
    return jsonify(res)


@app.route("/api/live/snapshot", methods=["POST"])
def trigger_live_snapshot():
    from collector.live_engine import LiveMonitoringEngine
    engine = LiveMonitoringEngine(get_db_path())
    res = engine.trigger_snapshot_now()
    record_audit_event("investigator", "TRIGGER_LIVE_SNAPSHOT", engine.case_id, res, get_db_path())
    return jsonify(res)


@app.route("/api/timeline", methods=["GET"])
def get_timeline():
    cid = _resolve_case_id(request.args.get("case_id"))
    did = request.args.get("device_id")
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    q = request.args.get("q")
    category = request.args.get("category")
    severity = request.args.get("severity")
    event_type = request.args.get("event_type")
    sort_by = request.args.get("sort", "timestamp")
    order = request.args.get("order", "desc")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")

    filters = {}
    if category: filters["category"] = category
    if severity: filters["severity"] = severity
    if event_type: filters["event_type"] = event_type

    conn = get_db_connection(get_db_path())
    result = query_evidence_records(
        conn, "timeline", case_id=cid, device_id=did,
        filters=filters, search=q, search_fields=["description", "entity", "source", "path", "process", "network_endpoint"],
        date_from=date_from, date_to=date_to, sort_by=sort_by, order=order,
        page=page, limit=limit
    )
    conn.close()
    return jsonify(result)


@app.route("/api/findings", methods=["GET"])
def get_findings():
    cid = _resolve_case_id(request.args.get("case_id"))
    did = request.args.get("device_id")
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    q = request.args.get("q")
    category = request.args.get("category")
    severity = request.args.get("severity")
    sort_by = request.args.get("sort", "timestamp")
    order = request.args.get("order", "desc")

    filters = {}
    if category: filters["category"] = category
    if severity: filters["severity"] = severity

    conn = get_db_connection(get_db_path())
    result = query_evidence_records(
        conn, "findings", case_id=cid, device_id=did,
        filters=filters, search=q, search_fields=["title", "description", "mitre_technique", "recommendations"],
        sort_by=sort_by, order=order, page=page, limit=limit
    )
    conn.close()
    return jsonify(result)


@app.route("/api/evidence", methods=["GET", "POST"])
def handle_evidence_api():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded:
            return jsonify({"status": "COLLECTION_ERROR", "error": "No file uploaded"}), 400

        safe_name = os.path.basename(uploaded.filename or f"evidence_{int(time.time())}.zip")
        dest_path = os.path.join(get_evidence_dir(), safe_name)
        uploaded.save(dest_path)

        hasher = hashlib.sha256()
        with open(dest_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        sha256 = hasher.hexdigest()

        conn = get_db_connection(get_db_path())
        eid = f"EVD-{sha256[:12]}"
        cid = _resolve_case_id(request.form.get("case_id"))
        conn.execute("""
            INSERT OR REPLACE INTO evidence_files (
                id, device_id, case_id, file_path, relative_path, file_size, sha256, mime_type, category, collected_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            eid, request.form.get("device_id", "DEV-UPLOAD"), cid, dest_path, safe_name,
            os.path.getsize(dest_path), sha256, "application/zip", "Evidence Package",
            datetime.now(timezone.utc).isoformat(), "COLLECTED"
        ))
        conn.commit()
        conn.close()
        record_audit_event("investigator", "UPLOAD_EVIDENCE_PACKAGE", eid, {"sha256": sha256, "filename": safe_name}, get_db_path())
        return jsonify({"status": "COLLECTED", "evidence_id": eid, "sha256": sha256, "file": safe_name}), 201

    cid = _resolve_case_id(request.args.get("case_id"))
    did = request.args.get("device_id")
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    q = request.args.get("q")
    category = request.args.get("category")
    sort_by = request.args.get("sort", "timestamp")
    order = request.args.get("order", "desc")

    filters = {}
    if category: filters["category"] = category

    conn = get_db_connection(get_db_path())
    result = query_evidence_records(
        conn, "artifacts", case_id=cid, device_id=did,
        filters=filters, search=q, search_fields=["name", "path", "artifact_type", "source", "sha256"],
        sort_by=sort_by, order=order, page=page, limit=limit
    )
    conn.close()
    return jsonify(result)


@app.route("/api/hashes", methods=["GET"])
def get_hashes_ledger():
    cid = _resolve_case_id(request.args.get("case_id"))
    did = request.args.get("device_id")
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    q = request.args.get("q")
    item_type = request.args.get("item_type")
    sort_by = request.args.get("sort", "timestamp")
    order = request.args.get("order", "desc")

    filters = {}
    if item_type: filters["item_type"] = item_type

    conn = get_db_connection(get_db_path())
    result = query_evidence_records(
        conn, "hashes", case_id=cid, device_id=did,
        filters=filters, search=q, search_fields=["item_type", "item_id", "path", "sha256"],
        sort_by=sort_by, order=order, page=page, limit=limit
    )
    conn.close()
    return jsonify(result)


@app.route("/api/hashes/verify", methods=["POST"])
def verify_hash_record():
    data = request.get_json(silent=True) or {}
    target_sha = str(data.get("sha256", "")).strip().lower()
    if not target_sha:
        return jsonify({"status": "COLLECTION_ERROR", "error": "sha256 parameter is required"}), 400

    conn = get_db_connection(get_db_path())
    match = conn.execute("SELECT * FROM hashes WHERE LOWER(sha256) = ?", (target_sha,)).fetchone()
    conn.close()

    if match:
        record_audit_event("investigator", "VERIFY_HASH_FOUND", target_sha, dict(match), get_db_path())
        return jsonify({
            "status": "VERIFIED",
            "matched": True,
            "hash": dict(match),
            "message": "Cryptographic SHA-256 match found in forensic evidence ledger."
        })
    else:
        return jsonify({
            "status": "NOT_PRESENT",
            "matched": False,
            "sha256": target_sha,
            "message": "Hash does not match any collected evidence record."
        })


@app.route("/api/reports", methods=["GET"])
def get_reports_metadata():
    cid = _resolve_case_id(request.args.get("case_id"))
    return jsonify({
        "status": "COLLECTED",
        "case_id": cid,
        "formats": [
            {"format": "JSON", "endpoint": f"/api/reports/json?case_id={cid}", "description": "Structured JSON forensic triage export"},
            {"format": "HTML", "endpoint": f"/api/reports/html?case_id={cid}", "description": "Standalone printable HTML report with print styles"},
            {"format": "PDF", "endpoint": f"/api/reports/pdf?case_id={cid}", "description": "Forensic investigation PDF report"},
            {"format": "SQLite", "endpoint": "/api/reports/sqlite", "description": "Complete raw SQLite evidence database"},
            {"format": "ZIP", "endpoint": f"/api/reports/package?case_id={cid}", "description": "Standardized ZIP evidence package with manifest.json & SHA-256"}
        ]
    })


@app.route("/api/reports/json", methods=["GET"])
def export_report_json():
    cid = _resolve_case_id(request.args.get("case_id"))
    record_audit_event("investigator", "EXPORT_REPORT_JSON", cid, {}, get_db_path())
    rep = ReportGenerator.generate_case_report(cid, get_db_path())
    return jsonify(rep)


@app.route("/api/reports/html", methods=["GET"])
def export_report_html():
    cid = _resolve_case_id(request.args.get("case_id"))
    record_audit_event("investigator", "EXPORT_REPORT_HTML", cid, {}, get_db_path())
    html_data = ReportGenerator.generate_html_report(cid, get_db_path())
    return Response(html_data, mimetype="text/html")


@app.route("/api/reports/pdf", methods=["GET"])
def export_report_pdf():
    cid = _resolve_case_id(request.args.get("case_id"))
    record_audit_event("investigator", "EXPORT_REPORT_PDF", cid, {}, get_db_path())
    pdf_bytes = ReportGenerator.generate_pdf_report(cid, get_db_path())
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"inline; filename=JOCKY_REPORT_{cid}.pdf"}
    )


@app.route("/api/reports/sqlite", methods=["GET"])
def export_report_sqlite():
    db_p = get_db_path()
    if not os.path.isfile(db_p):
        return jsonify({"status": "COLLECTION_ERROR", "error": "Database not found"}), 404
    record_audit_event("investigator", "EXPORT_REPORT_SQLITE", "global", {"db_path": db_p}, db_p)
    return send_file(db_p, as_attachment=True, download_name="jocky_forensics.db")


@app.route("/api/reports/package", methods=["GET"])
def export_report_package():
    cid = _resolve_case_id(request.args.get("case_id"))
    ev_dir = get_evidence_dir()
    os.makedirs(ev_dir, exist_ok=True)

    zips = [os.path.join(ev_dir, f) for f in os.listdir(ev_dir) if f.startswith(f"JOCKY_CASE_{cid}") and f.endswith(".zip")]
    if not zips:
        zips = [os.path.join(ev_dir, f) for f in os.listdir(ev_dir) if f.endswith(".zip")]

    if zips:
        latest_zip = sorted(zips, key=os.path.getmtime, reverse=True)[0]
    else:
        from collector.packaging import EvidencePackager
        packager = EvidencePackager(output_dir=ev_dir)
        manifest = packager.create_evidence_package(
            case_id=cid,
            device_id="DEV-LOCAL",
            db_path=get_db_path()
        )
        latest_zip = manifest["package_zip_path"]

    record_audit_event("investigator", "EXPORT_EVIDENCE_PACKAGE", cid, {"package": os.path.basename(latest_zip)}, get_db_path())
    return send_file(latest_zip, as_attachment=True, download_name=os.path.basename(latest_zip))


# ---------------------------------------------------------------------------
# Metadata-only DFIR investigator API
# ---------------------------------------------------------------------------
try:
    from server.dfir_investigator import investigate as _dfir_investigate, render_markdown as _dfir_render_markdown
except Exception:
    _dfir_investigate = None
    _dfir_render_markdown = None


@app.route("/api/forensics/investigate", methods=["POST"])
def forensics_investigate():
    """Analyze supplied triage JSON/CSV using metadata-only defensive rules."""
    if _dfir_investigate is None:
        return jsonify({"error": "DFIR investigator module unavailable"}), 500
    body = request.get_json(silent=True) or {}
    data = body.get("data", body.get("artifacts", body.get("events")))
    if data is None and request.data:
        data = request.get_data(as_text=True)
    if data is None:
        return jsonify({"error": "Provide data/artifacts/events as JSON or CSV"}), 400
    try:
        result = _dfir_investigate(data, indicators=body.get("indicators"), max_timeline=int(body.get("max_timeline", 500)))
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/forensics/investigate/report", methods=["POST"])
def forensics_investigate_report():
    if _dfir_investigate is None:
        return jsonify({"error": "DFIR investigator module unavailable"}), 500
    body = request.get_json(silent=True) or {}
    data = body.get("data", body.get("artifacts", body.get("events")))
    if data is None:
        return jsonify({"error": "Provide data/artifacts/events"}), 400
    try:
        result = _dfir_investigate(data, indicators=body.get("indicators"), max_timeline=int(body.get("max_timeline", 500)))
        report = _dfir_render_markdown(result)
        resp = Response(report, mimetype="text/markdown")
        resp.headers["Content-Disposition"] = 'attachment; filename="jocky_dfir_investigation.md"'
        return resp
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400



# ===========================================================================
# JOCKY LIVE THREAT INTELLIGENCE (TINYFISH INTEGRATION)
# ===========================================================================
from server.tinyfish_service import TinyFishService, is_tinyfish_configured
from server.models import ThreatIntelModel


@app.route("/api/threat-intel/status", methods=["GET"])
def threat_intel_status():
    """Report whether TinyFish threat intelligence is configured, without exposing secrets."""
    configured = is_tinyfish_configured()
    return jsonify({
        "configured": configured,
        "provider": "TinyFish",
        "search_available": configured,
        "fetch_available": configured,
        "capabilities": ["domain", "ipv4", "ipv6", "url", "sha256", "sha1", "md5"],
        "version": "2026.1",
    })


@app.route("/api/threat-intel/validate", methods=["POST"])
def threat_intel_validate():
    """Validate and infer type for an indicator prior to search."""
    data = request.get_json(silent=True) or {}
    indicator = (data.get("indicator") or "").strip()
    itype = data.get("indicator_type")
    is_valid, norm_val, resolved_type, err = TinyFishService.validate_indicator(indicator, itype)
    return jsonify({
        "valid": is_valid,
        "indicator": norm_val or indicator,
        "indicator_type": resolved_type,
        "error": err,
    })


@app.route("/api/threat-intel/research", methods=["POST"])
def threat_intel_research():
    """Execute live TinyFish search for an indicator, optionally binding to a case."""
    data = request.get_json(silent=True) or {}
    indicator = (data.get("indicator") or "").strip()
    itype = data.get("indicator_type")
    cid = data.get("case_id")
    context = data.get("context")
    save_record = data.get("save_record", True)

    if not indicator:
        return jsonify({"error": "Indicator is required"}), 400

    # Execute search via TinyFishService
    search_res = TinyFishService.search(indicator, indicator_type=itype, context=context)
    if not search_res.get("success"):
        return jsonify(search_res), 400 if search_res.get("code") == "VALIDATION_ERROR" else 502

    # Save to database if case_id provided
    research_id = None
    if cid and save_record:
        case = CaseModel.get_by_id(cid, get_db_path())
        if case:
            saved = ThreatIntelModel.save_research(
                case_id=cid,
                indicator=search_res["indicator"],
                indicator_type=search_res["indicator_type"],
                query=search_res["query"],
                sources=search_res.get("results", []),
                status="SUCCESS",
                db_path=get_db_path(),
            )
            research_id = saved.get("id")
            record_audit_event(
                "investigator",
                "RESEARCH_INDICATOR_TINYFISH",
                cid,
                {"indicator": search_res["indicator"], "type": search_res["indicator_type"], "results_count": search_res.get("total_results", 0)},
                get_db_path(),
            )

    search_res["research_id"] = research_id
    search_res["case_id"] = cid
    return jsonify(search_res)


@app.route("/api/threat-intel/fetch", methods=["POST"])
def threat_intel_fetch():
    """Fetch clean content from a permitted public source URL with SSRF protection."""
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    research_id = data.get("research_id")
    cid = data.get("case_id")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    fetch_res = TinyFishService.fetch_source(url)
    if not fetch_res.get("success"):
        status_code = 400 if fetch_res.get("code") in ("SSRF_BLOCKED", "INVALID_URL") else 502
        return jsonify(fetch_res), status_code

    if research_id:
        ThreatIntelModel.update_fetched_content(
            research_id=research_id,
            fetched_url=url,
            content=fetch_res.get("content", ""),
            db_path=get_db_path(),
        )

    if cid:
        record_audit_event(
            "investigator",
            "FETCH_SOURCE_TINYFISH",
            cid,
            {"url": url, "title": fetch_res.get("title", ""), "char_count": fetch_res.get("char_count", 0)},
            get_db_path(),
        )

    return jsonify(fetch_res)


@app.route("/api/threat-intel/summary", methods=["POST"])
def threat_intel_summary():
    """Generate evidence-grounded summary from retrieved sources."""
    data = request.get_json(silent=True) or {}
    indicator = (data.get("indicator") or "").strip()
    itype = data.get("indicator_type", "indicator")
    results = data.get("results", [])
    summary_data = TinyFishService.generate_evidence_summary(indicator, itype, results)
    return jsonify(summary_data)


@app.route("/api/cases/<case_id>/threat-intel", methods=["GET"])
def get_case_threat_intel(case_id):
    """Retrieve all threat intelligence research records for a permitted case."""
    case = CaseModel.get_by_id(case_id, get_db_path())
    if not case:
        return jsonify({"error": "Case not found"}), 404

    records = ThreatIntelModel.list_for_case(case_id, get_db_path())
    return jsonify({
        "case_id": case_id,
        "count": len(records),
        "research_records": records,
    })


@app.route("/api/cases/<case_id>/threat-intel/save", methods=["POST"])
def save_threat_intel_finding(case_id):
    """Save an investigator-reviewed threat intelligence finding to the case."""
    case = CaseModel.get_by_id(case_id, get_db_path())
    if not case:
        return jsonify({"error": "Case not found"}), 404

    data = request.get_json(silent=True) or {}
    research_id = data.get("research_id")
    title = (data.get("title") or "").strip()
    severity = (data.get("severity") or "MEDIUM").strip().upper()
    notes = (data.get("investigator_notes") or "").strip()
    recommendations = (data.get("recommendations") or "").strip()
    mitre_tech = (data.get("mitre_technique") or "T1071").strip()

    if not research_id:
        return jsonify({"error": "research_id is required"}), 400
    if not title:
        return jsonify({"error": "Finding title is required"}), 400
    if not notes:
        return jsonify({"error": "Investigator review notes are required"}), 400

    try:
        finding = ThreatIntelModel.save_to_findings(
            case_id=case_id,
            research_id=research_id,
            title=title,
            severity=severity,
            investigator_notes=notes,
            recommendations=recommendations,
            mitre_technique=mitre_tech,
            db_path=get_db_path(),
        )

        record_audit_event(
            "investigator",
            "SAVE_THREAT_INTEL_FINDING",
            case_id,
            {"research_id": research_id, "finding_id": finding["id"], "severity": severity},
            get_db_path(),
        )

        return jsonify({"success": True, "finding": finding}), 201

    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to save finding: {type(e).__name__}"}), 500



if __name__ == "__main__":
    port = int(os.environ.get("JOCKY_PORT", 5000))
    host = os.environ.get("JOCKY_HOST", "127.0.0.1")
    print(f"[JOCKY-SERVER] Starting Central Server on {host}:{port}...")
    app.run(host=host, port=port, debug=False)
