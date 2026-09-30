"""Behavioral/anomaly detection for repeated suspicious actions."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class AnomalyResult:
    detected: bool
    reason: str
    score: int


class AnomalyDetector:
    """Simple in-memory anomaly detector.

    It watches request frequency and failed login counts per IP address. This is
    intentionally lightweight so it runs easily in Docker for a class project.
    """

    def __init__(self, window_seconds: int = 120):
        self.window = timedelta(seconds=window_seconds)
        self.request_times: dict[str, deque[datetime]] = defaultdict(deque)
        self.failed_logins: dict[str, deque[datetime]] = defaultdict(deque)

    def _trim(self, q: deque[datetime], now: datetime) -> None:
        while q and now - q[0] > self.window:
            q.popleft()

    def observe_request(self, ip_address: str) -> AnomalyResult:
        now = datetime.now(timezone.utc)
        q = self.request_times[ip_address]
        q.append(now)
        self._trim(q, now)
        if len(q) >= 20:
            return AnomalyResult(True, "High request burst from same IP", 25)
        if len(q) >= 10:
            return AnomalyResult(True, "Moderate request burst from same IP", 12)
        return AnomalyResult(False, "Normal request rate", 0)

    def observe_login_result(self, ip_address: str, success: bool) -> AnomalyResult:
        now = datetime.now(timezone.utc)
        q = self.failed_logins[ip_address]
        if not success:
            q.append(now)
        self._trim(q, now)
        if len(q) >= 5:
            return AnomalyResult(True, "Five or more failed logins in two minutes", 30)
        if len(q) >= 3:
            return AnomalyResult(True, "Three or more failed logins in two minutes", 15)
        return AnomalyResult(False, "No failed-login anomaly", 0)
