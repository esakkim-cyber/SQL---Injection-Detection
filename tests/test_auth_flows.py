from pathlib import Path

from app import create_app
from app.database import db
from app.services.auth_service import AuthService


class TestConfig:
    SECRET_KEY = "test"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ML_MODEL_PATH = str(Path("app/models/sql_injection_rf.joblib"))
    ML_THRESHOLD = 0.62
    RISK_BLOCK_THRESHOLD = 70
    GLOBAL_WAF_BLOCKING = False
    ENABLE_VULNERABLE_DEMO = True
    ALERT_EMAIL_ENABLED = False
    ALERT_SLACK_WEBHOOK = ""
    ALERT_TELEGRAM_BOT_TOKEN = ""
    ALERT_TELEGRAM_CHAT_ID = ""
    APP_NAME = "test"


def test_vulnerable_login_can_be_bypassed_but_parameterized_cannot():
    app = create_app(TestConfig)
    with app.app_context():
        vulnerable = AuthService.vulnerable_login("' OR '1'='1' -- ", "wrong")
        safe = AuthService.parameterized_only_demo("' OR '1'='1' -- ", "wrong")
        assert vulnerable.success is True
        assert safe.success is False


def test_secure_login_accepts_real_user():
    app = create_app(TestConfig)
    with app.app_context():
        result = AuthService.secure_login("alice", "alice123")
        assert result.success is True
        assert result.user["username"] == "alice"


def test_api_analyze_rejects_non_object_json():
    app = create_app(TestConfig)

    response = app.test_client().post("/api/analyze", json=["payload"])

    assert response.status_code == 400
    assert response.json == {"error": "Request body must be a JSON object."}


def test_api_analyze_counts_request_once():
    app = create_app(TestConfig)

    response = app.test_client().post("/api/analyze", json={"payload": "alice"})

    assert response.status_code == 200
    assert len(app.detection_engine.anomaly_detector.request_times["127.0.0.1"]) == 1


def test_attack_simulation_does_not_run_vulnerable_query_when_disabled():
    class DisabledDemoConfig(TestConfig):
        ENABLE_VULNERABLE_DEMO = False

    app = create_app(DisabledDemoConfig)

    response = app.test_client().post("/api/attack-simulation", json={})

    assert response.status_code == 200
    assert response.json
    assert all(item["vulnerable"]["blocked"] for item in response.json)
    assert all(
        item["vulnerable"]["message"] == "Vulnerable demo is disabled by configuration."
        for item in response.json
    )
