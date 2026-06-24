"""Flask application factory for the SentinelSSH backend."""
from __future__ import annotations

import logging

from flask import Flask, request
from flask_cors import CORS
from flask_login import current_user

from app.api import register_blueprints
from app.api.errors import register_error_handlers
from app.auth.security import load_user
from app.config import BaseConfig, get_config
from app.extensions import login_manager, socketio
from app.realtime.events import register_socketio_handlers
from app.utils.responses import error

logger = logging.getLogger("sentinelssh.app")

# /api paths that never require an authenticated session.
_AUTH_EXEMPT_PREFIXES = ("/api/auth", "/api/internal")


def create_app(config: type[BaseConfig] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config or get_config())

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    CORS(
        app,
        resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}},
        supports_credentials=True,
    )

    # Real-time channel (optionally fanned out via a Redis message queue).
    socketio.init_app(
        app,
        cors_allowed_origins=app.config["CORS_ORIGINS"],
        async_mode="threading",
        message_queue=app.config.get("SOCKETIO_MESSAGE_QUEUE"),
    )
    register_socketio_handlers(socketio)

    # Authentication.
    login_manager.init_app(app)
    login_manager.user_loader(load_user)

    register_error_handlers(app)
    register_blueprints(app, prefix=app.config["API_PREFIX"])

    # Serve the static dashboard (same-origin) for dev/demo.
    from app.frontend import bp as frontend_bp

    app.register_blueprint(frontend_bp)

    _register_auth_guard(app)
    _maybe_seed_demo(app)

    return app


def _register_auth_guard(app: Flask) -> None:
    @app.before_request
    def _require_auth():
        if not app.config.get("AUTH_REQUIRED", True):
            return None
        path = request.path
        if not path.startswith("/api/"):
            return None  # page/asset routes handle their own protection
        if any(path.startswith(p) for p in _AUTH_EXEMPT_PREFIXES):
            return None
        if not current_user.is_authenticated:
            return error("authentication required", status=401, code="unauthorized")
        return None


def _maybe_seed_demo(app: Flask) -> None:
    if not app.config.get("DEMO_MODE", False):
        return
    try:
        from app.demo_data import seed_if_empty

        created = seed_if_empty()
        if created:
            logger.info("demo mode: seeded %d sample attacks", created)
    except Exception:  # noqa: BLE001 - demo seeding must never block startup
        logger.exception("demo seeding failed")
