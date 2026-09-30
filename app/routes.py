"""Web routes and API endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, current_app, g, jsonify, render_template, request
from sqlalchemy import desc, func
from sqlalchemy.exc import SQLAlchemyError

from .database import db
from .models import Alert, SecurityEvent, User
from .services.auth_service import AuthService
from .services.detection_engine import DetectionResult

main_bp = Blueprint("main", __name__)

DEMO_PAYLOADS = [
    {"name": "Classic login bypass", "payload": "' OR '1'='1' -- ", "password": "wrong"},
    {"name": "Comment out password check", "payload": "admin' -- ", "password": "anything"},
    {"name": "UNION extraction attempt", "payload": "' UNION SELECT 1, username, password_plain, role FROM users -- ", "password": "x"},
    {"name": "Stacked destructive statement", "payload": "'; DROP TABLE users; --", "password": "x"},
    {"name": "Encoded quote + tautology", "payload": "%27 OR 1=1--", "password": "x"},
    {"name": "Time-based blind payload", "payload": "' OR sleep(5) -- ", "password": "x"},
    {"name": "Benign failed login", "payload": "alice", "password": "wrong"},
    {"name": "Benign successful login", "payload": "alice", "password": "alice123"},
]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _detection_for(payload: str) -> DetectionResult:
    return current_app.detection_engine.analyze(
        payload=payload,
        ip_address=_client_ip(),
        endpoint=request.path,
    )


def _log_event(
    detection: DetectionResult,
    *,
    username: str | None,
    mode: str,
    action_taken: str,
    blocked: bool,
    query_preview: str | None = None,
) -> SecurityEvent:
    event = SecurityEvent(
        ip_address=_client_ip(),
        endpoint=request.path,
        username=username,
        payload=detection.payload,
        detection_methods=", ".join(detection.methods),
        regex_detected=detection.regex_detected,
        ml_detected=detection.ml_detected,
        anomaly_detected=detection.anomaly_detected,
        risk_score=detection.risk_score,
        severity=detection.severity,
        action_taken=action_taken,
        mode=mode,
        blocked=blocked,
        query_preview=query_preview,
        user_agent=(request.user_agent.string or "")[:250],
    )
    db.session.add(event)
    db.session.commit()
    current_app.alert_service.create_for_event(event)
    return event


def _event_to_dict(event: SecurityEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "ip_address": event.ip_address,
        "endpoint": event.endpoint,
        "username": event.username,
        "payload": event.payload,
        "methods": event.detection_methods,
        "risk_score": event.risk_score,
        "severity": event.severity,
        "action_taken": event.action_taken,
        "mode": event.mode,
        "blocked": event.blocked,
    }


@main_bp.route("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@main_bp.route("/")
def index():
    users = User.query.count()
    events = SecurityEvent.query.count()
    alerts = Alert.query.count()
    return render_template("index.html", users=users, events=events, alerts=alerts)


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    result = None
    detection = None
    mode = request.form.get("mode", "secure")
    username = ""
    password = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        payload_to_analyze = f"{username} {password}".strip()
        detection = g.waf_result or _detection_for(payload_to_analyze)

        try:
            if mode == "vulnerable":
                if not current_app.config["ENABLE_VULNERABLE_DEMO"]:
                    result = {"success": False, "message": "Vulnerable demo is disabled by configuration.", "blocked": True}
                    action = "CONFIG_BLOCKED"
                    blocked = True
                    query_preview = None
                else:
                    auth_result = AuthService.vulnerable_login(username, password)
                    result = auth_result.__dict__
                    action = "MONITOR_ONLY_ALLOWED" if detection.risk_score >= 40 else "VULNERABLE_QUERY_EXECUTED"
                    blocked = False
                    query_preview = auth_result.query_preview
            elif mode == "parameterized_only":
                auth_result = AuthService.parameterized_only_demo(username, password)
                result = auth_result.__dict__
                action = "PARAMETERIZED_QUERY_EXECUTED"
                blocked = False
                query_preview = auth_result.query_preview
            else:
                if detection.risk_score >= current_app.config["RISK_BLOCK_THRESHOLD"]:
                    result = {
                        "success": False,
                        "message": "Blocked by Mini-WAF before database execution.",
                        "user": None,
                        "query_preview": "No query executed because WAF risk threshold was exceeded.",
                        "blocked": True,
                    }
                    action = "WAF_BLOCKED"
                    blocked = True
                    query_preview = result["query_preview"]
                else:
                    auth_result = AuthService.secure_login(username, password)
                    result = auth_result.__dict__
                    action = "SECURE_QUERY_EXECUTED" if not auth_result.blocked else "VALIDATION_BLOCKED"
                    blocked = auth_result.blocked
                    query_preview = auth_result.query_preview

            # Feed failed login behavior into the anomaly layer.
            success = bool(result and result.get("success"))
            current_app.detection_engine.record_login_behavior(_client_ip(), success)
            _log_event(
                detection,
                username=username,
                mode=mode,
                action_taken=action,
                blocked=blocked,
                query_preview=query_preview,
            )
        except SQLAlchemyError as exc:
            db.session.rollback()
            result = {
                "success": False,
                "message": f"Database rejected the vulnerable query: {exc.__class__.__name__}. This is logged as a failed attack demo.",
                "user": None,
                "query_preview": "Error occurred while executing query.",
                "blocked": False,
            }
            _log_event(
                detection,
                username=username,
                mode=mode,
                action_taken="DATABASE_ERROR_LOGGED",
                blocked=False,
                query_preview=str(exc)[:500],
            )

    return render_template(
        "login.html",
        result=result,
        detection=detection.to_dict() if detection else None,
        mode=mode,
        username=username,
        password=password,
    )


@main_bp.route("/playground")
def playground():
    return render_template("playground.html")


@main_bp.route("/attack-lab")
def attack_lab():
    return render_template("attack_lab.html", payloads=DEMO_PAYLOADS)


@main_bp.route("/dashboard")
def dashboard():
    stats = _stats()
    latest_events = SecurityEvent.query.order_by(desc(SecurityEvent.timestamp)).limit(25).all()
    return render_template("dashboard.html", stats=stats, latest_events=latest_events)


@main_bp.route("/alerts")
def alerts():
    latest_alerts = Alert.query.order_by(desc(Alert.timestamp)).limit(50).all()
    return render_template("alerts.html", alerts=latest_alerts)


@main_bp.route("/documentation")
def documentation():
    return render_template("documentation.html")


@main_bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    if request.is_json:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be a JSON object."}), 400
    else:
        data = request.form
    payload = str(data.get("payload", ""))
    detection = _detection_for(payload)
    return jsonify(detection.to_dict())


@main_bp.route("/api/stats")
def api_stats():
    return jsonify(_stats())


@main_bp.route("/api/events")
def api_events():
    events = SecurityEvent.query.order_by(desc(SecurityEvent.timestamp)).limit(100).all()
    return jsonify([_event_to_dict(event) for event in events])


@main_bp.route("/api/attack-simulation", methods=["POST"])
def api_attack_simulation():
    """Run the classroom before/after demonstration payloads."""
    results = []
    for case in DEMO_PAYLOADS:
        username = case["payload"]
        password = case["password"]
        detection = _detection_for(f"{username} {password}")

        vulnerable_result: dict[str, Any]
        if not current_app.config.get("ENABLE_VULNERABLE_DEMO", False):
            vulnerable_result = {
                "success": False,
                "message": "Vulnerable demo is disabled by configuration.",
                "user": None,
                "query_preview": "No vulnerable query executed.",
                "blocked": True,
            }
        else:
            try:
                vulnerable_auth = AuthService.vulnerable_login(username, password)
                vulnerable_result = vulnerable_auth.__dict__
            except SQLAlchemyError as exc:
                db.session.rollback()
                vulnerable_result = {
                    "success": False,
                    "message": f"Database error in vulnerable mode: {exc.__class__.__name__}",
                    "user": None,
                    "query_preview": str(exc)[:400],
                    "blocked": False,
                }

        if detection.risk_score >= current_app.config["RISK_BLOCK_THRESHOLD"]:
            secure_result = {
                "success": False,
                "message": "Blocked by Mini-WAF before DB query.",
                "user": None,
                "query_preview": "No query executed.",
                "blocked": True,
            }
            secure_action = "WAF_BLOCKED"
        else:
            secure_auth = AuthService.secure_login(username, password)
            secure_result = secure_auth.__dict__
            secure_action = "SECURE_QUERY_EXECUTED" if not secure_auth.blocked else "VALIDATION_BLOCKED"

        parameterized_auth = AuthService.parameterized_only_demo(username, password)
        parameterized_result = parameterized_auth.__dict__

        _log_event(
            detection,
            username=username,
            mode="attack_lab",
            action_taken=secure_action,
            blocked=bool(secure_result.get("blocked")),
            query_preview=secure_result.get("query_preview"),
        )

        results.append(
            {
                "name": case["name"],
                "payload": username,
                "detection": detection.to_dict(),
                "vulnerable": vulnerable_result,
                "secure": secure_result,
                "parameterized_only": parameterized_result,
            }
        )
    return jsonify(results)


@main_bp.route("/api/seed-demo-events", methods=["POST"])
def api_seed_demo_events():
    """Create demo security data for dashboard screenshots."""
    for case in DEMO_PAYLOADS:
        detection = _detection_for(f"{case['payload']} {case['password']}")
        _log_event(
            detection,
            username=case["payload"],
            mode="seed_demo",
            action_taken="DEMO_EVENT_CREATED",
            blocked=detection.risk_score >= current_app.config["RISK_BLOCK_THRESHOLD"],
            query_preview="Generated by /api/seed-demo-events",
        )
    return jsonify({"created": len(DEMO_PAYLOADS)})


def _stats() -> dict[str, Any]:
    total_events = SecurityEvent.query.count()
    blocked_events = SecurityEvent.query.filter_by(blocked=True).count()
    high_events = SecurityEvent.query.filter(SecurityEvent.severity.in_(["HIGH", "CRITICAL"])).count()
    alerts = Alert.query.count()

    severity_rows = (
        db.session.query(SecurityEvent.severity, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.severity)
        .all()
    )
    mode_rows = db.session.query(SecurityEvent.mode, func.count(SecurityEvent.id)).group_by(SecurityEvent.mode).all()

    method_counts = {"Regex": 0, "ML": 0, "Anomaly": 0}
    method_counts["Regex"] = SecurityEvent.query.filter_by(regex_detected=True).count()
    method_counts["ML"] = SecurityEvent.query.filter_by(ml_detected=True).count()
    method_counts["Anomaly"] = SecurityEvent.query.filter_by(anomaly_detected=True).count()

    avg_risk = db.session.query(func.avg(SecurityEvent.risk_score)).scalar() or 0
    return {
        "total_events": total_events,
        "blocked_events": blocked_events,
        "high_events": high_events,
        "alerts": alerts,
        "avg_risk": round(float(avg_risk), 2),
        "severity_counts": {severity or "UNKNOWN": count for severity, count in severity_rows},
        "mode_counts": {mode or "unknown": count for mode, count in mode_rows},
        "method_counts": method_counts,
    }
