"""API blueprint registration."""
from __future__ import annotations

from flask import Blueprint

from app.api import attacks, incidents, realtime, reports, search, stats, system
from app.auth import routes as auth_routes


def register_blueprints(app, prefix: str = "/api") -> None:
    for module in (stats, attacks, incidents, search, realtime, system, reports, auth_routes):
        app.register_blueprint(module.bp, url_prefix=prefix)

    # Health check (no prefix) for load balancers / Docker.
    health = Blueprint("health", __name__)

    @health.get("/health")
    def _health():
        return {"success": True, "data": {"status": "ok"}}

    app.register_blueprint(health)
