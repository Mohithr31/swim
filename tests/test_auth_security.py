"""
TINY MONITOR — Authentication Hardening & Security Regression Suite
===================================================================
Tests:
  1. Missing API key configuration in normal runtime (fails closed).
  2. Missing and invalid request API keys rejected with HTTP 401.
  3. Valid API key access succeeds.
  4. Dashboard login rejects incorrect username, password, or OTP with HTTP 401.
  5. Dashboard login succeeds with valid credentials (HTTP 302 -> /) and establishes session.
  6. Unauthenticated dashboard access redirects to /login when API key is configured.
  7. Authenticated dashboard access succeeds with HTTP 200.
  8. Authentication-status accuracy (/api/auth/status reflects session/key state, no secret leaks).
  9. Protected agent-download routes (/downloads/*) cannot bypass authentication.
 10. Preservation of ordinary test-mode authentication bypass behavior.
 11. Public status endpoints (/api/health, /api/auth/status) remain public and disclose no secrets.
"""

import os
import json
import pytest
from server.server import app, init_db
import server.server as srv


@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    """Provide isolated test client with dedicated test database and clean env."""
    test_db = str(tmp_path / "auth_test.db")
    test_evd = str(tmp_path / "evidence")
    os.makedirs(test_evd, exist_ok=True)
    init_db(test_db)

    old_srv_db = srv.DB_PATH
    old_srv_evd = srv.EVIDENCE_DIR

    monkeypatch.setenv("JOCKY_DB", test_db)
    monkeypatch.setenv("JOCKY_EVIDENCE_DIR", test_evd)
    monkeypatch.setenv("JOCKY_ENFORCE_AUTH_TEST", "1")

    srv.DB_PATH = test_db
    srv.EVIDENCE_DIR = test_evd
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client

    srv.DB_PATH = old_srv_db
    srv.EVIDENCE_DIR = old_srv_evd


# -----------------------------------------------------------------------------
# 1. API Key Authentication Matrix
# -----------------------------------------------------------------------------

def test_missing_api_key_fails_closed_in_runtime(auth_client, monkeypatch):
    """When JOCKY_API_KEY is unset or empty, protected API routes fail closed (401)."""
    monkeypatch.setenv("JOCKY_API_KEY", "")
    res = auth_client.get("/api/cases")
    assert res.status_code == 401
    data = res.get_json()
    assert data["error"] == "Unauthorized"


def test_placeholder_api_key_fails_closed(auth_client, monkeypatch):
    """Placeholder credentials in environment must fail closed rather than grant open access."""
    placeholders = [
        "REPLACE_WITH_GENERATED_AGENT_API_KEY",
        "your_api_key_here",
        "change_me",
        "default",
        "<api-key>",
        "change-this-to-a-secure-random-key-in-production",
    ]
    for ph in placeholders:
        monkeypatch.setenv("JOCKY_API_KEY", ph)
        res = auth_client.get("/api/cases")
        assert res.status_code == 401, f"Placeholder '{ph}' did not fail closed!"


def test_missing_request_api_key_rejected(auth_client, monkeypatch):
    """Protected API routes reject requests missing the X-API-Key header."""
    monkeypatch.setenv("JOCKY_API_KEY", "test-hardened-api-key-2026")
    res = auth_client.get("/api/cases")
    assert res.status_code == 401
    assert res.get_json()["error"] == "Unauthorized"


def test_invalid_request_api_key_rejected(auth_client, monkeypatch):
    """Protected API routes reject requests with incorrect X-API-Key header."""
    monkeypatch.setenv("JOCKY_API_KEY", "test-hardened-api-key-2026")
    headers = {"X-API-Key": "completely-wrong-key"}
    res = auth_client.get("/api/cases", headers=headers)
    assert res.status_code == 401
    assert res.get_json()["error"] == "Unauthorized"


def test_valid_request_api_key_accepted(auth_client, monkeypatch):
    """Protected API routes allow access when a valid X-API-Key header is supplied."""
    valid_key = "test-hardened-api-key-2026"
    monkeypatch.setenv("JOCKY_API_KEY", valid_key)
    headers = {"X-API-Key": valid_key}
    res = auth_client.get("/api/cases", headers=headers)
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


# -----------------------------------------------------------------------------
# 2. Dashboard Login Authentication
# -----------------------------------------------------------------------------

def test_dashboard_login_rejects_invalid_username(auth_client, monkeypatch):
    """Dashboard login rejects an invalid badge ID / username."""
    monkeypatch.setenv("JOCKY_API_KEY", "test-key-123")
    monkeypatch.setenv("JOCKY_DASHBOARD_USERNAME", "AUTHORIZED_INVESTIGATOR")
    monkeypatch.setenv("JOCKY_DASHBOARD_PASSWORD", "SuperSecurePass123!")
    monkeypatch.setenv("JOCKY_DASHBOARD_OTP", "123456")

    res = auth_client.post("/login", data={
        "username": "WRONG_USER",
        "password": "SuperSecurePass123!",
        "otp": "123456",
    })
    assert res.status_code == 401
    assert "Invalid investigator credentials or MFA token" in res.get_data(as_text=True)


def test_dashboard_login_rejects_invalid_password(auth_client, monkeypatch):
    """Dashboard login rejects an invalid password."""
    monkeypatch.setenv("JOCKY_API_KEY", "test-key-123")
    monkeypatch.setenv("JOCKY_DASHBOARD_USERNAME", "AUTHORIZED_INVESTIGATOR")
    monkeypatch.setenv("JOCKY_DASHBOARD_PASSWORD", "SuperSecurePass123!")
    monkeypatch.setenv("JOCKY_DASHBOARD_OTP", "123456")

    res = auth_client.post("/login", data={
        "username": "AUTHORIZED_INVESTIGATOR",
        "password": "IncorrectPassword!",
        "otp": "123456",
    })
    assert res.status_code == 401
    assert "Invalid investigator credentials or MFA token" in res.get_data(as_text=True)


def test_dashboard_login_rejects_invalid_otp(auth_client, monkeypatch):
    """Dashboard login rejects an invalid 6-digit OTP token."""
    monkeypatch.setenv("JOCKY_API_KEY", "test-key-123")
    monkeypatch.setenv("JOCKY_DASHBOARD_USERNAME", "AUTHORIZED_INVESTIGATOR")
    monkeypatch.setenv("JOCKY_DASHBOARD_PASSWORD", "SuperSecurePass123!")
    monkeypatch.setenv("JOCKY_DASHBOARD_OTP", "123456")

    res = auth_client.post("/login", data={
        "username": "AUTHORIZED_INVESTIGATOR",
        "password": "SuperSecurePass123!",
        "otp": "999999",
    })
    assert res.status_code == 401
    assert "Invalid investigator credentials or MFA token" in res.get_data(as_text=True)


def test_dashboard_login_success_sets_session(auth_client, monkeypatch):
    """Dashboard login with correct credentials redirects to / and establishes session."""
    monkeypatch.setenv("JOCKY_API_KEY", "test-key-123")
    monkeypatch.setenv("JOCKY_DASHBOARD_USERNAME", "AUTHORIZED_INVESTIGATOR")
    monkeypatch.setenv("JOCKY_DASHBOARD_PASSWORD", "SuperSecurePass123!")
    monkeypatch.setenv("JOCKY_DASHBOARD_OTP", "123456")

    res = auth_client.post("/login", data={
        "username": "AUTHORIZED_INVESTIGATOR",
        "password": "SuperSecurePass123!",
        "otp": "123456",
    })
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/")

    # Following the session to / succeeds with 200
    res_dash = auth_client.get("/")
    assert res_dash.status_code == 200
    assert "Tiny Monitor" in res_dash.get_data(as_text=True)


# -----------------------------------------------------------------------------
# 3. Unauthenticated vs Authenticated Dashboard Access
# -----------------------------------------------------------------------------

def test_unauthenticated_dashboard_redirects_to_login(auth_client, monkeypatch):
    """When API key is configured, unauthenticated GET / redirects to /login."""
    monkeypatch.setenv("JOCKY_API_KEY", "configured-api-key")
    res = auth_client.get("/")
    assert res.status_code == 302
    assert "login" in res.headers["Location"]


def test_authenticated_dashboard_session_serves_ui(auth_client, monkeypatch):
    """When session is authenticated, GET / serves the dashboard with HTTP 200."""
    monkeypatch.setenv("JOCKY_API_KEY", "configured-api-key")
    with auth_client.session_transaction() as sess:
        sess["dashboard_authenticated"] = True
    res = auth_client.get("/")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Tiny Monitor" in html
    assert "Presidency University" in html


# -----------------------------------------------------------------------------
# 4. Authentication Status Accuracy & Public Endpoints
# -----------------------------------------------------------------------------

def test_auth_status_accurately_reflects_unauthenticated_state(auth_client, monkeypatch):
    """Unauthenticated request to /api/auth/status reports authenticated: False."""
    monkeypatch.setenv("JOCKY_API_KEY", "configured-api-key")
    res = auth_client.get("/api/auth/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["authenticated"] is False


def test_auth_status_accurately_reflects_api_key_auth(auth_client, monkeypatch):
    """Request with valid X-API-Key reports authenticated: True."""
    valid_key = "configured-api-key"
    monkeypatch.setenv("JOCKY_API_KEY", valid_key)
    res = auth_client.get("/api/auth/status", headers={"X-API-Key": valid_key})
    assert res.status_code == 200
    data = res.get_json()
    assert data["authenticated"] is True


def test_auth_status_accurately_reflects_session_auth(auth_client, monkeypatch):
    """Request with active session reports authenticated: True."""
    monkeypatch.setenv("JOCKY_API_KEY", "configured-api-key")
    with auth_client.session_transaction() as sess:
        sess["dashboard_authenticated"] = True
    res = auth_client.get("/api/auth/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["authenticated"] is True


def test_auth_status_unconfigured_server_does_not_treat_all_as_authenticated(auth_client, monkeypatch):
    """When no API key is configured, /api/auth/status does NOT treat callers as authenticated."""
    monkeypatch.setenv("JOCKY_API_KEY", "")
    res = auth_client.get("/api/auth/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["authenticated"] is False


def test_public_endpoints_disclose_no_secrets(auth_client, monkeypatch):
    """Public endpoints /api/health and /api/auth/status never disclose secrets."""
    secret_key = "super-secret-production-token-999"
    monkeypatch.setenv("JOCKY_API_KEY", secret_key)
    monkeypatch.setenv("JOCKY_SECRET_KEY", "super-session-secret-key")

    for endpoint in ("/api/health", "/api/auth/status"):
        res = auth_client.get(endpoint)
        assert res.status_code == 200
        text = res.get_data(as_text=True)
        assert secret_key not in text
        assert "super-session" not in text


# -----------------------------------------------------------------------------
# 5. Protected Agent Download Routes
# -----------------------------------------------------------------------------

def test_agent_downloads_require_authentication(auth_client, monkeypatch):
    """Agent download routes under /downloads/ reject unauthenticated callers."""
    monkeypatch.setenv("JOCKY_API_KEY", "configured-api-key")

    for platform in ("windows", "linux"):
        res = auth_client.get(f"/downloads/agent/{platform}")
        assert res.status_code == 401
        assert res.get_json()["error"] == "Unauthorized"


def test_agent_downloads_allowed_with_valid_api_key(auth_client, monkeypatch):
    """Agent download routes accept valid API key (does not return 401)."""
    valid_key = "configured-api-key"
    monkeypatch.setenv("JOCKY_API_KEY", valid_key)

    res = auth_client.get("/downloads/agent/windows", headers={"X-API-Key": valid_key})
    # Since artifact might not be pre-built on disk in test env, it should return 200 or 404 (not 401 Unauthorized)
    assert res.status_code in (200, 404)
    if res.status_code == 404:
        assert res.get_json()["error"] == "agent_artifact_not_built"


def test_agent_downloads_allowed_with_dashboard_session(auth_client, monkeypatch):
    """Agent download routes accept authenticated dashboard session (does not return 401)."""
    monkeypatch.setenv("JOCKY_API_KEY", "configured-api-key")
    with auth_client.session_transaction() as sess:
        sess["dashboard_authenticated"] = True

    res = auth_client.get("/downloads/agent/linux")
    assert res.status_code in (200, 404)
    if res.status_code == 404:
        assert res.get_json()["error"] == "agent_artifact_not_built"


# -----------------------------------------------------------------------------
# 6. Test-Only Authentication Bypass Behavior
# -----------------------------------------------------------------------------

def test_ordinary_tests_bypass_auth_when_enforce_var_unset(tmp_path, monkeypatch):
    """When JOCKY_ENFORCE_AUTH_TEST is unset, ordinary test client can access API routes without headers."""
    monkeypatch.delenv("JOCKY_ENFORCE_AUTH_TEST", raising=False)
    monkeypatch.setenv("JOCKY_API_KEY", "enforced-key")

    test_db = str(tmp_path / "ordinary_test.db")
    init_db(test_db)
    srv.DB_PATH = test_db
    app.config["TESTING"] = True

    with app.test_client() as normal_client:
        res = normal_client.get("/api/cases")
        # In ordinary test mode without enforcement flag, request bypasses auth check
        assert res.status_code == 200
