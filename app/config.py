"""Configuration values for the SQL Injection Detection and Prevention System."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Default configuration.

    Docker Compose injects a MySQL URL. If the application is run directly on a
    laptop without Docker, it falls back to SQLite so students can still test the
    frontend and detection engine.
    """

    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-for-production")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'local_sqli_lab.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}

    ML_MODEL_PATH = os.getenv(
        "ML_MODEL_PATH", str(BASE_DIR / "app" / "models" / "sql_injection_rf.joblib")
    )
    ML_THRESHOLD = float(os.getenv("ML_THRESHOLD", "0.62"))
    RISK_BLOCK_THRESHOLD = int(os.getenv("RISK_BLOCK_THRESHOLD", "70"))
    GLOBAL_WAF_BLOCKING = os.getenv("GLOBAL_WAF_BLOCKING", "false").lower() == "true"

    # Demo options. Keeping the vulnerable path available is necessary for the
    # before/after university demonstration. Never expose this app publicly.
    ENABLE_VULNERABLE_DEMO = os.getenv("ENABLE_VULNERABLE_DEMO", "false").lower() == "true"

    # Optional alert integrations. The app always stores alerts in the database;
    # external channels are enabled only when credentials are provided.
    ALERT_EMAIL_ENABLED = os.getenv("ALERT_EMAIL_ENABLED", "false").lower() == "true"
    ALERT_SLACK_WEBHOOK = os.getenv("ALERT_SLACK_WEBHOOK", "")
    ALERT_TELEGRAM_BOT_TOKEN = os.getenv("ALERT_TELEGRAM_BOT_TOKEN", "")
    ALERT_TELEGRAM_CHAT_ID = os.getenv("ALERT_TELEGRAM_CHAT_ID", "")

    # Flask/Gunicorn settings.
    APP_NAME = "SQL Injection Detection and Prevention System"
