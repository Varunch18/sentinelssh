"""Stats / aggregation endpoints."""
from __future__ import annotations

from flask import Blueprint, request

from app.schemas.common import TopParams
from app.services.stats_service import StatsService
from app.utils.responses import success
from app.utils.validation import parse_args

bp = Blueprint("stats", __name__)
_service = StatsService()


@bp.get("/stats")
def stats():
    return success(_service.overview())


@bp.get("/risk-distribution")
def risk_distribution():
    return success(_service.risk_distribution())


@bp.get("/attacks-per-hour")
def attacks_per_hour():
    hours = min(max(int(request.args.get("hours", 24)), 1), 168)
    return success(_service.attacks_per_hour(hours=hours))


@bp.get("/mitre")
def mitre():
    p = parse_args(TopParams)
    return success(_service.top_mitre(p.limit, p.hours))


@bp.get("/behaviors")
def behaviors():
    p = parse_args(TopParams)
    return success(_service.top_behaviors(p.limit, p.hours))
