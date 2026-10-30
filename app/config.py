"""
TINY MONITOR — Configuration Module
Handles environment variables safely, ensures directories exist, and protects secrets.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment from .env file if present
load_dotenv(BASE_DIR / ".env")


class Config:
    """Application configuration with safe defaults and secret redaction."""
    
    # Environment
    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-key-change-in-production")
    
    # Server Binding
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))
    
    # Database
    DB_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "tiny_monitor.db")))
    if not DB_PATH.is_absolute():
        DB_PATH = BASE_DIR / DB_PATH
        
    # Forensics Storage
    EVIDENCE_DIR = Path(os.getenv("EVIDENCE_STORAGE_PATH", str(BASE_DIR / "data" / "evidence")))
    if not EVIDENCE_DIR.is_absolute():
        EVIDENCE_DIR = BASE_DIR / EVIDENCE_DIR
        
    REPORTS_DIR = Path(os.getenv("REPORTS_STORAGE_PATH", str(BASE_DIR / "reports" / "generated")))
    if not REPORTS_DIR.is_absolute():
        REPORTS_DIR = BASE_DIR / REPORTS_DIR
        
    MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50")) * 1024 * 1024
    
    # TinyFish Search API Configuration
    TINYFISH_API_KEY = os.getenv("TINYFISH_API_KEY", "").strip()
    TINYFISH_SEARCH_ENDPOINT = os.getenv("TINYFISH_SEARCH_ENDPOINT", "https://api.search.tinyfish.ai").rstrip("/")
    TINYFISH_TIMEOUT = float(os.getenv("TINYFISH_TIMEOUT_SECONDS", "15"))

    @classmethod
    def ensure_directories(cls):
        """Ensure all required runtime data and evidence directories exist."""
        cls.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        cls.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    REVOKED_KEYS = {
        "sk-dummy-revoked-key-uURSS7P48Q",
        "sk-tinyfish-old-uURSS7P48Q",
        "sk-tinyfish-compromised-key-sample",
    }

    @classmethod
    def get_redacted_api_key(cls) -> str:
        """Return safe redacted representation of the TinyFish API key without exposing it."""
        key = cls.TINYFISH_API_KEY
        if not key or key == "your_tinyfish_api_key_here":
            return "NOT_CONFIGURED"
        if key in cls.REVOKED_KEYS or "revoked-key" in key.lower() or "compromised" in key.lower():
            return "COMPROMISED_KEY_DETECTED (MUST ROTATE)"
        if len(key) <= 8:
            return "CONFIGURED (hidden)"
        return f"{key[:4]}...{key[-4:]}"

    @classmethod
    def is_tinyfish_configured(cls) -> bool:
        """Check if a genuine non-placeholder, non-compromised TinyFish API key is present."""
        key = cls.TINYFISH_API_KEY
        if not key or key == "your_tinyfish_api_key_here" or len(key) <= 5:
            return False
        if key in cls.REVOKED_KEYS or "revoked-key" in key.lower() or "compromised" in key.lower():
            return False
        return True
