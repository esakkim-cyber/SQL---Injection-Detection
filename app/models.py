"""SQLAlchemy models used by the project."""

from __future__ import annotations

from datetime import datetime, timezone

from .database import db


def utc_now() -> datetime:
    """Timezone-aware UTC timestamp helper."""
    return datetime.now(timezone.utc)


class User(db.Model):
    """Demo user table.

    ``password_plain`` exists only to demonstrate insecure legacy code in the
    vulnerable login page. The secure login route uses ``password_hash``.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="student")
    password_plain = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now)


class SecurityEvent(db.Model):
    """A security event shown on the dashboard."""

    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=utc_now, index=True)
    ip_address = db.Column(db.String(64), nullable=False)
    endpoint = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=True)
    payload = db.Column(db.Text, nullable=True)
    detection_methods = db.Column(db.String(255), nullable=True)
    regex_detected = db.Column(db.Boolean, default=False)
    ml_detected = db.Column(db.Boolean, default=False)
    anomaly_detected = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Integer, default=0)
    severity = db.Column(db.String(20), default="LOW")
    action_taken = db.Column(db.String(80), default="LOGGED")
    mode = db.Column(db.String(40), default="monitor")
    blocked = db.Column(db.Boolean, default=False)
    query_preview = db.Column(db.Text, nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)


class Alert(db.Model):
    """Alert generated when a high-risk event is detected."""

    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=utc_now, index=True)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(160), nullable=False)
    message = db.Column(db.Text, nullable=False)
    channel = db.Column(db.String(50), default="dashboard")
    delivered = db.Column(db.Boolean, default=True)
