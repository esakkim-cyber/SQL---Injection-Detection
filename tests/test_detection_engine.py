from app.services.detection_engine import DetectionEngine


def test_regex_detects_classic_tautology():
    engine = DetectionEngine(model_path="app/models/sql_injection_rf.joblib")
    result = engine.analyze("' OR '1'='1' -- ", ip_address="127.0.0.1", endpoint="/test")
    assert result.regex_detected is True
    assert result.risk_score >= 70
    assert result.severity in {"HIGH", "CRITICAL"}


def test_normal_username_is_low_risk():
    engine = DetectionEngine(model_path="app/models/sql_injection_rf.joblib")
    result = engine.analyze("alice", ip_address="127.0.0.1", endpoint="/test")
    assert result.risk_score < 40
    assert result.severity == "LOW"
