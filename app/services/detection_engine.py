"""Hybrid SQL injection detection engine.

The engine combines three detection layers:
1. Regex signatures for known attack patterns.
2. Machine-learning classification using handcrafted features.
3. Behavioral anomaly detection for repeated failures or bursts.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

from flask import current_app

from .anomaly_detector import AnomalyDetector
from .ml_detector import MLDetector


@dataclass
class RegexMatch:
    pattern_name: str
    description: str
    weight: int
    matched_text: str


@dataclass
class DetectionResult:
    payload: str
    regex_detected: bool
    ml_detected: bool
    anomaly_detected: bool
    risk_score: int
    severity: str
    methods: list[str]
    regex_matches: list[dict]
    ml_probability: float
    features: dict[str, float]
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


class DetectionEngine:
    """Analyze payloads using regex, ML, and behavior."""

    # Each regex has a name, expression, explanation, and risk weight. The list
    # intentionally covers classic tautology, UNION, stacked queries, comments,
    # metadata extraction, time-based attacks, and dangerous stored procedures.
    REGEX_RULES = [
        ("Quote or SQL comment", r"(%27)|(')|(--)|(%23)|(#)", "Quote/comment token often used to alter SQL syntax", 15),
        ("UNION SELECT", r"(?i)\bunion\b\s+(?:all\s+)?\bselect\b", "UNION-based extraction attempt", 35),
        ("DROP/DELETE statement", r"(?i)\b(drop|delete|truncate|alter)\b\s+\b(table|database|users)?\b", "Destructive SQL keyword", 35),
        ("Boolean tautology", r"(?i)\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", "Boolean condition that may bypass login", 30),
        ("Stacked query", r";\s*(select|insert|update|delete|drop|alter)\b", "Semicolon followed by another SQL statement", 30),
        ("SQL metadata", r"(?i)\binformation_schema\b|\bsysobjects\b|\bsyscolumns\b", "Database metadata enumeration", 25),
        ("Time-based payload", r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\b", "Time-delay SQL injection payload", 30),
        ("xp_cmdshell", r"(?i)\bxp_cmdshell\b", "SQL Server command execution procedure", 45),
        ("Encoded injection", r"(?i)(%27|%22|%2d%2d|0x[0-9a-f]+|char\s*\()", "URL/hex/char encoded suspicious input", 20),
        ("Inline SQL comment", r"/\*.*?\*/", "Inline comment obfuscation", 15),
    ]

    def __init__(self, model_path: str | Path):
        self.model_path = Path(model_path)
        self.ml_detector = MLDetector(model_path=self.model_path)
        self.anomaly_detector = AnomalyDetector()

    def regex_scan(self, payload: str) -> list[RegexMatch]:
        matches: list[RegexMatch] = []
        for name, pattern, description, weight in self.REGEX_RULES:
            found = re.search(pattern, payload or "")
            if found:
                matches.append(
                    RegexMatch(
                        pattern_name=name,
                        description=description,
                        weight=weight,
                        matched_text=found.group(0)[:60],
                    )
                )
        return matches

    def analyze(self, payload: str, ip_address: str = "unknown", endpoint: str = "manual") -> DetectionResult:
        regex_matches = self.regex_scan(payload)
        ml_result = self.ml_detector.predict(payload)
        anomaly_result = self.anomaly_detector.observe_request(ip_address)

        risk = sum(match.weight for match in regex_matches)
        if ml_result.detected:
            risk += int(ml_result.probability * 35)
        if anomaly_result.detected:
            risk += anomaly_result.score
        risk = max(0, min(100, risk))

        methods: list[str] = []
        if regex_matches:
            methods.append("Regex signatures")
        if ml_result.detected:
            methods.append("Machine learning")
        if anomaly_result.detected:
            methods.append("Behavioral anomaly")

        severity = self._severity(risk)
        recommendation = self._recommendation(risk, methods)

        return DetectionResult(
            payload=payload,
            regex_detected=bool(regex_matches),
            ml_detected=ml_result.detected,
            anomaly_detected=anomaly_result.detected,
            risk_score=risk,
            severity=severity,
            methods=methods or ["No malicious pattern found"],
            regex_matches=[asdict(match) for match in regex_matches],
            ml_probability=ml_result.probability,
            features=ml_result.feature_values,
            recommendation=recommendation,
        )

    def record_login_behavior(self, ip_address: str, success: bool) -> None:
        self.anomaly_detector.observe_login_result(ip_address, success)

    @staticmethod
    def _severity(risk: int) -> str:
        if risk >= 85:
            return "CRITICAL"
        if risk >= 70:
            return "HIGH"
        if risk >= 40:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _recommendation(risk: int, methods: list[str]) -> str:
        if risk >= 70:
            return "Block request, create alert, keep using parameterized queries, and review logs."
        if risk >= 40:
            return "Challenge or monitor request; validate input and keep prepared statements enabled."
        if methods:
            return "Log for visibility and continue normal secure query execution."
        return "No action required beyond normal secure coding practices."


def current_detection_engine() -> DetectionEngine:
    """Convenience accessor used by routes."""
    return current_app.detection_engine
