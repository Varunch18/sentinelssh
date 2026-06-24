"""System health + high-risk alerts endpoints."""
from __future__ import annotations

from flask import request

from flask import Blueprint

from app.services.system_service import SystemService
from app.utils.responses import success

bp = Blueprint("system", __name__)
_service = SystemService()


@bp.get("/system-health")
def system_health():
    return success(_service.health())


@bp.get("/alerts")
def alerts():
    limit = min(max(int(request.args.get("limit", 10)), 1), 100)
    min_score = min(max(int(request.args.get("min_score", 71)), 0), 100)
    return success(_service.alerts(limit=limit, min_score=min_score))
