"""Attack-related endpoints."""
from __future__ import annotations

from flask import Blueprint, request

from app.schemas.attack import AttackQuery
from app.schemas.common import TopParams
from app.services.attack_service import AttackService
from app.utils.responses import paginated, success
from app.utils.validation import parse_args

bp = Blueprint("attacks", __name__)
_service = AttackService()


@bp.get("/attacks")
def list_attacks():
    q = parse_args(AttackQuery)
    items, total = _service.list(q)
    return paginated(items, page=q.page, per_page=q.per_page, total=total)


@bp.get("/attacks/<int:attack_id>")
def get_attack(attack_id: int):
    return success(_service.get(attack_id))


@bp.get("/recent")
def recent():
    limit = min(max(int(request.args.get("limit", 10)), 1), 100)
    return success(_service.recent(limit))


@bp.get("/high-risk")
def high_risk():
    min_score = min(max(int(request.args.get("min_score", 71)), 0), 100)
    limit = min(max(int(request.args.get("limit", 25)), 1), 100)
    return success(_service.high_risk(min_score, limit))


@bp.get("/top-usernames")
def top_usernames():
    p = parse_args(TopParams)
    return success(_service.top_usernames(p.limit, p.hours))


@bp.get("/top-passwords")
def top_passwords():
    p = parse_args(TopParams)
    return success(_service.top_passwords(p.limit, p.hours))


@bp.get("/top-countries")
def top_countries():
    p = parse_args(TopParams)
    return success(_service.top_countries(p.limit, p.hours))


@bp.get("/commands")
def recent_commands():
    limit = min(max(int(request.args.get("limit", 20)), 1), 200)
    return success(_service.recent_commands(limit))
