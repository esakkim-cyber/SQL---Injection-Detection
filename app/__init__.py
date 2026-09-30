"""Flask application factory for the SQL Injection Detection and Prevention System.

The app is intentionally built as a controlled university lab. It contains one
vulnerable demonstration route and several secured routes so students can show
before/after behavior without attacking any real system.
"""

from __future__ import annotations

import logging
from pathlib import Path

from flask import Flask, g, request

from .config import Config
from .database import db, init_database
from .services.detection_engine import DetectionEngine
from .services.alert_service import AlertService


BASE_DIR = Path(__file__).resolve().parent.parent


def create_app(config_object: type[Config] = Config) -> Flask:
    """Create and configure the Flask app.

    The factory pattern keeps the project testable and Docker-friendly. The
    database URL, WAF behavior, and alert options are read from environment
    variables in :mod:`app.config`.
    """
    app = Flask(__name__)
    app.config.from_object(config_object)

    # Logging is intentionally verbose for demonstration and screenshots.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    db.init_app(app)

    # Detection and alert services are attached to the application object so
    # routes can reuse them without global mutable state.
    app.detection_engine = DetectionEngine(model_path=app.config["ML_MODEL_PATH"])
    app.alert_service = AlertService(app)

    @app.before_request
    def mini_waf_monitor() -> None:
        """Inspect incoming input before route execution.

        The middleware stores the result in ``g.waf_result``. By default it runs
        in monitor mode so the vulnerable demo remains demonstrable. Secure
        routes can enforce blocking by consulting this result.
        """
        if request.endpoint in {"static", "main.api_analyze"}:
            return None

        payload_parts: list[str] = []
        if request.method in {"POST", "PUT", "PATCH"}:
            payload_parts.extend(str(v) for v in request.form.values())
            if request.is_json:
                json_data = request.get_json(silent=True) or {}
                if isinstance(json_data, dict):
                    payload_parts.extend(str(v) for v in json_data.values())
        else:
            payload_parts.extend(str(v) for v in request.args.values())

        joined_payload = " ".join(payload_parts).strip()
        if joined_payload:
            g.waf_result = app.detection_engine.analyze(
                payload=joined_payload,
                ip_address=request.remote_addr or "unknown",
                endpoint=request.path,
            )
        else:
            g.waf_result = None

    with app.app_context():
        init_database(app)

    from .routes import main_bp

    app.register_blueprint(main_bp)
    return app
