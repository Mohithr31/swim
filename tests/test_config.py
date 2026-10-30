"""
TINY MONITOR — Configuration & Security Unit Tests
Tests secret redaction, directory provisioning, and compromised key blocking.
"""

from app.config import Config


def test_redacted_api_key_when_empty(monkeypatch):
    monkeypatch.setattr(Config, "TINYFISH_API_KEY", "")
    assert Config.get_redacted_api_key() == "NOT_CONFIGURED"
    assert Config.is_tinyfish_configured() is False


def test_redacted_api_key_when_placeholder(monkeypatch):
    monkeypatch.setattr(Config, "TINYFISH_API_KEY", "your_tinyfish_api_key_here")
    assert Config.get_redacted_api_key() == "NOT_CONFIGURED"
    assert Config.is_tinyfish_configured() is False


def test_compromised_key_is_blocked(monkeypatch):
    # Blocked key containing signature uURSS7P48Q
    monkeypatch.setattr(Config, "TINYFISH_API_KEY", "sk-dummy-revoked-key-uURSS7P48Q")
    assert "COMPROMISED_KEY_DETECTED" in Config.get_redacted_api_key()
    assert Config.is_tinyfish_configured() is False


def test_valid_rotated_key_is_redacted_safely(monkeypatch):
    monkeypatch.setattr(Config, "TINYFISH_API_KEY", "sk-tinyfish-NEWROTATEDVALIDKEY123456789")
    assert Config.is_tinyfish_configured() is True
    redacted = Config.get_redacted_api_key()
    assert redacted.startswith("sk-t...")
    assert redacted.endswith("6789")
    # Must not contain the full middle secret
    assert "NEWROTATEDVALIDKEY" not in redacted
