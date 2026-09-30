"""Alert creation and optional notification integrations."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Any

from flask import Flask

from ..database import db
from ..models import Alert, SecurityEvent

logger = logging.getLogger(__name__)


class AlertService:
    """Store alerts and optionally forward them to external channels.

    The dashboard alert table always works. Slack/Telegram/email are optional so
    the project runs without secrets in the classroom.
    """

    def __init__(self, app: Flask):
        self.app = app

    def create_for_event(self, event: SecurityEvent) -> Alert | None:
        if event.severity not in {"HIGH", "CRITICAL"}:
            return None
        title = f"{event.severity} SQL injection attempt detected"
        message = (
            f"Endpoint: {event.endpoint}\n"
            f"IP: {event.ip_address}\n"
            f"Risk score: {event.risk_score}\n"
            f"Methods: {event.detection_methods}\n"
            f"Action: {event.action_taken}\n"
            f"Payload: {event.payload}"
        )
        return self.create_alert(event.severity, title, message)

    def create_alert(self, severity: str, title: str, message: str) -> Alert:
        alert = Alert(severity=severity, title=title, message=message, channel="dashboard")
        db.session.add(alert)
        db.session.commit()
        logger.warning("ALERT: %s | %s", title, message.replace("\n", " | "))

        # Optional channels are best-effort. Failures are logged but do not break
        # the security workflow.
        self._send_optional_channels(title, message)
        return alert

    def _send_optional_channels(self, title: str, message: str) -> None:
        if self.app.config.get("ALERT_EMAIL_ENABLED"):
            self._send_email(title, message)
        if self.app.config.get("ALERT_SLACK_WEBHOOK"):
            logger.info("Slack webhook configured. Add requests.post in production deployment.")
        if self.app.config.get("ALERT_TELEGRAM_BOT_TOKEN"):
            logger.info("Telegram token configured. Add requests.post in production deployment.")

    def _send_email(self, title: str, message: str) -> None:
        smtp_host = self.app.config.get("SMTP_HOST", "localhost")
        smtp_port = int(self.app.config.get("SMTP_PORT", 25))
        sender = self.app.config.get("SMTP_SENDER", "sqli-lab@example.local")
        recipient = self.app.config.get("SMTP_RECIPIENT", "admin@example.local")
        email = EmailMessage()
        email["Subject"] = title
        email["From"] = sender
        email["To"] = recipient
        email.set_content(message)
        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as server:
                server.send_message(email)
        except Exception as exc:  # pragma: no cover - depends on external SMTP
            logger.error("Email alert failed: %s", exc)
